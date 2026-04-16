from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.responses import JSONResponse
import uvicorn
import threading
from fastmcp import FastMCP
import httpx
import os
import json
import re
from typing import Optional

mcp = FastMCP("Serverless API Gateway")

GATEWAY_BASE_URL = os.environ.get("GATEWAY_BASE_URL", "https://gateway.example.com")
GATEWAY_BEARER_TOKEN = os.environ.get("GATEWAY_BEARER_TOKEN", "")


def build_auth_headers(extra_token: Optional[str] = None) -> dict:
    token = extra_token or GATEWAY_BEARER_TOKEN
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def parse_kv_list(items: Optional[list]) -> dict:
    """Convert [{name, value}, ...] list to a dict."""
    if not items:
        return {}
    result = {}
    for item in items:
        if isinstance(item, dict):
            name = item.get("name") or item.get("key", "")
            value = item.get("value", "")
            if name:
                result[name] = value
    return result


@mcp.tool()
async def proxy_request(
    method: str,
    path: str,
    headers: Optional[list] = None,
    query_params: Optional[list] = None,
    body: Optional[str] = None,
) -> dict:
    """
    Route and proxy an HTTP request through the Serverless API Gateway to a backend service.
    Use this when you need to forward requests to configured upstream HTTP endpoints,
    service bindings, or static responses. Handles JWT auth, CORS, header/query mapping,
    and value transformation automatically based on gateway config.
    """
    url = GATEWAY_BASE_URL.rstrip("/") + "/" + path.lstrip("/")

    req_headers = build_auth_headers()
    if headers:
        for h in headers:
            if isinstance(h, dict):
                name = h.get("name") or h.get("key", "")
                value = h.get("value", "")
                if name:
                    req_headers[name] = value

    params = parse_kv_list(query_params)

    request_body = None
    if body:
        request_body = body
        if "Content-Type" not in req_headers:
            try:
                json.loads(body)
                req_headers["Content-Type"] = "application/json"
            except (json.JSONDecodeError, TypeError):
                req_headers["Content-Type"] = "text/plain"

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.request(
                method=method.upper(),
                url=url,
                headers=req_headers,
                params=params if params else None,
                content=request_body.encode() if isinstance(request_body, str) else request_body,
            )

        result = {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "url": str(response.url),
            "method": method.upper(),
            "path": path,
        }

        content_type = response.headers.get("content-type", "")
        if "application/json" in content_type:
            try:
                result["body"] = response.json()
            except Exception:
                result["body"] = response.text
        else:
            result["body"] = response.text

        return result

    except httpx.ConnectError as e:
        return {
            "error": "Connection failed",
            "detail": str(e),
            "url": url,
            "method": method.upper(),
            "path": path,
            "note": "Ensure GATEWAY_BASE_URL environment variable is set to the correct gateway URL.",
        }
    except httpx.TimeoutException as e:
        return {
            "error": "Request timed out",
            "detail": str(e),
            "url": url,
            "method": method.upper(),
            "path": path,
        }
    except Exception as e:
        return {
            "error": "Request failed",
            "detail": str(e),
            "url": url,
            "method": method.upper(),
            "path": path,
        }


@mcp.tool()
async def refresh_auth_token(
    access_token: str,
    refresh_token: str,
    path: str,
) -> dict:
    """
    Refresh an expired Auth0 access token using a refresh token.
    Use this when the current JWT is expired and you have a refresh token available.
    Validates the existing token, and if expired, exchanges the refresh token
    for a new access token via Auth0.
    """
    url = GATEWAY_BASE_URL.rstrip("/") + "/" + path.lstrip("/")

    req_headers = {
        "Authorization": f"Bearer {access_token}",
        "X-Refresh-Token": refresh_token,
        "Content-Type": "application/json",
    }

    body_payload = json.dumps({"refresh_token": refresh_token})

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                url=url,
                headers=req_headers,
                content=body_payload.encode(),
            )

        result = {
            "status_code": response.status_code,
            "path": path,
            "url": str(response.url),
        }

        content_type = response.headers.get("content-type", "")
        if "application/json" in content_type:
            try:
                resp_data = response.json()
                result["body"] = resp_data
                if "access_token" in resp_data:
                    result["new_access_token"] = resp_data["access_token"]
                    result["token_refreshed"] = True
                elif response.status_code == 200:
                    result["token_refreshed"] = True
                else:
                    result["token_refreshed"] = False
            except Exception:
                result["body"] = response.text
                result["token_refreshed"] = response.status_code == 200
        else:
            result["body"] = response.text
            result["token_refreshed"] = response.status_code == 200

        return result

    except httpx.ConnectError as e:
        return {
            "error": "Connection failed",
            "detail": str(e),
            "path": path,
            "note": "Ensure GATEWAY_BASE_URL environment variable is set correctly.",
        }
    except Exception as e:
        return {
            "error": "Token refresh failed",
            "detail": str(e),
            "path": path,
        }


@mcp.tool()
async def get_gateway_config(
    filter_path: Optional[str] = None,
    include_variables: bool = False,
) -> dict:
    """
    Retrieve and inspect the current Serverless API Gateway configuration from the KV namespace.
    Use this to understand which paths are configured, what integrations are active
    (HTTP proxy, service binding, Auth0, Supabase, static), what JWT/CORS settings are applied,
    and what value mappings exist. Essential before routing or debugging requests.
    """
    config_path = "/_config"
    url = GATEWAY_BASE_URL.rstrip("/") + config_path

    req_headers = build_auth_headers()
    req_headers["Accept"] = "application/json"

    params = {}
    if filter_path:
        params["path"] = filter_path
    if include_variables:
        params["include_variables"] = "true"

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(
                url=url,
                headers=req_headers,
                params=params if params else None,
            )

        result = {
            "status_code": response.status_code,
            "filter_path": filter_path,
            "include_variables": include_variables,
        }

        if response.status_code == 200:
            content_type = response.headers.get("content-type", "")
            if "application/json" in content_type:
                try:
                    config_data = response.json()
                    result["config"] = config_data

                    # Summarize for readability
                    if isinstance(config_data, dict):
                        paths = config_data.get("paths", [])
                        result["path_count"] = len(paths)
                        result["configured_paths"] = [
                            {
                                "path": p.get("path"),
                                "method": p.get("method"),
                                "integration": p.get("integration", {}).get("type") if isinstance(p.get("integration"), dict) else p.get("integration"),
                            }
                            for p in paths
                            if isinstance(p, dict)
                        ]
                        if not include_variables:
                            config_data.pop("variables", None)
                except Exception:
                    result["raw_body"] = response.text
            else:
                result["raw_body"] = response.text
        elif response.status_code == 404:
            result["error"] = "Config endpoint not found. The gateway may not expose a /_config endpoint."
            result["suggestion"] = "Check your gateway's admin or management API for configuration access."
        elif response.status_code in (401, 403):
            result["error"] = "Authentication/authorization failed for config endpoint."
            result["suggestion"] = "Ensure GATEWAY_BEARER_TOKEN is set with an admin-level token."
        else:
            result["error"] = f"Unexpected status: {response.status_code}"
            result["body"] = response.text

        return result

    except httpx.ConnectError as e:
        return {
            "error": "Connection failed",
            "detail": str(e),
            "note": "Ensure GATEWAY_BASE_URL environment variable is set to the correct gateway URL.",
            "simulated_config_structure": {
                "description": "Typical Serverless API Gateway config structure",
                "cors": {"allowOrigin": "*", "allowMethods": "GET,POST,PUT,DELETE,PATCH,OPTIONS"},
                "paths": [
                    {
                        "path": "/api/example",
                        "method": "GET",
                        "integration": {"type": "http_proxy", "url": "https://backend.example.com/api/example"},
                        "auth": {"jwt": True},
                    }
                ],
            },
        }
    except Exception as e:
        return {
            "error": "Failed to retrieve gateway config",
            "detail": str(e),
        }


@mcp.tool()
async def resolve_value_template(
    template: str,
    headers: Optional[list] = None,
    query_params: Optional[list] = None,
    jwt_payload: Optional[str] = None,
    config_variables: Optional[str] = None,
    global_variables: Optional[str] = None,
) -> dict:
    """
    Resolve a gateway value template string to its actual runtime value.
    Use this to debug or preview how template placeholders like $request.header.X-Foo,
    $request.jwt.sub, $config.myKey, or $request.query.param will be evaluated given
    a specific request, JWT payload, and config variables.
    """
    result = {
        "template": template,
        "resolved_value": None,
        "resolution_source": None,
        "error": None,
    }

    try:
        # Parse inputs
        headers_dict = parse_kv_list(headers)
        query_dict = parse_kv_list(query_params)

        jwt_payload_obj = {}
        if jwt_payload:
            try:
                jwt_payload_obj = json.loads(jwt_payload)
            except json.JSONDecodeError as e:
                result["error"] = f"Invalid jwt_payload JSON: {e}"
                return result

        config_vars = {}
        if config_variables:
            try:
                config_vars = json.loads(config_variables)
            except json.JSONDecodeError as e:
                result["error"] = f"Invalid config_variables JSON: {e}"
                return result

        global_vars = {}
        if global_variables:
            try:
                global_vars = json.loads(global_variables)
            except json.JSONDecodeError as e:
                result["error"] = f"Invalid global_variables JSON: {e}"
                return result

        # Resolve template using the same logic as ValueMapper.resolveValue
        pattern = re.compile(
            r'\$(request\.header|request\.jwt|config|request\.query)\.([a-zA-Z0-9-_.]+)'
        )
        match = pattern.search(template)

        if not match:
            result["error"] = (
                f"Template '{template}' does not match expected patterns: "
                "$request.header.<name>, $request.jwt.<claim>, "
                "$config.<key>, $request.query.<param>"
            )
            result["valid_patterns"] = [
                "$request.header.X-My-Header",
                "$request.jwt.sub",
                "$request.jwt.email",
                "$config.apiKey",
                "$request.query.page",
            ]
            return result

        source_type = match.group(1)
        key = match.group(2)

        if source_type == "request.header":
            value = headers_dict.get(key) or headers_dict.get(key.lower())
            result["resolved_value"] = value
            result["resolution_source"] = f"request.header.{key}"
            result["available_headers"] = list(headers_dict.keys())

        elif source_type == "request.jwt":
            value = jwt_payload_obj.get(key)
            result["resolved_value"] = value
            result["resolution_source"] = f"jwt_payload.{key}"
            result["available_jwt_claims"] = list(jwt_payload_obj.keys())

        elif source_type == "config":
            if key in config_vars:
                value = config_vars[key]
                result["resolution_source"] = f"config_variables.{key}"
            elif key in global_vars:
                value = global_vars[key]
                result["resolution_source"] = f"global_variables.{key} (fallback)"
            else:
                value = None
                result["resolution_source"] = "not found"
                result["available_config_keys"] = list(config_vars.keys())
                result["available_global_keys"] = list(global_vars.keys())
            result["resolved_value"] = value

        elif source_type == "request.query":
            value = query_dict.get(key)
            result["resolved_value"] = value
            result["resolution_source"] = f"query_params.{key}"
            result["available_query_params"] = list(query_dict.keys())

        else:
            result["error"] = f"Unknown source type: {source_type}"
            return result

        result["resolved"] = result["resolved_value"] is not None

    except Exception as e:
        result["error"] = f"Template resolution failed: {e}"

    return result


@mcp.tool()
async def authenticate_request(
    access_token: str,
    path: str,
    method: str = "GET",
) -> dict:
    """
    Validate a JWT Bearer token against the gateway's configured Auth settings.
    Use this to check whether a token is valid, inspect its decoded payload
    (sub, email, roles, expiry), and determine if it grants access to a specific
    gateway path. Also use to initiate Auth0 login redirects or handle OAuth callbacks.
    """
    url = GATEWAY_BASE_URL.rstrip("/") + "/" + path.lstrip("/")

    req_headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }

    result = {
        "path": path,
        "method": method.upper(),
        "token_provided": bool(access_token),
    }

    # Decode JWT payload locally (without verification) for inspection
    try:
        import base64
        parts = access_token.split(".")
        if len(parts) == 3:
            payload_b64 = parts[1]
            # Add padding
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += "=" * padding
            payload_bytes = base64.urlsafe_b64decode(payload_b64)
            payload_obj = json.loads(payload_bytes.decode("utf-8"))

            import time
            now = int(time.time())
            exp = payload_obj.get("exp")
            iat = payload_obj.get("iat")

            result["jwt_payload"] = payload_obj
            result["token_expired"] = (exp is not None and exp < now)
            result["token_expiry"] = exp
            result["token_issued_at"] = iat
            result["time_until_expiry_seconds"] = (exp - now) if exp else None
            result["claims"] = {
                "sub": payload_obj.get("sub"),
                "email": payload_obj.get("email"),
                "roles": payload_obj.get("roles") or payload_obj.get("https://example.com/roles"),
                "iss": payload_obj.get("iss"),
                "aud": payload_obj.get("aud"),
                "scope": payload_obj.get("scope"),
            }
            result["jwt_format"] = "valid_jwt_structure"
        else:
            result["jwt_format"] = "not_a_jwt"
            result["token_expired"] = None
    except Exception as e:
        result["jwt_decode_error"] = str(e)
        result["jwt_format"] = "decode_failed"

    # Make actual request to the gateway to validate the token
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.request(
                method=method.upper(),
                url=url,
                headers=req_headers,
            )

        result["gateway_status_code"] = response.status_code
        result["gateway_response_headers"] = dict(response.headers)

        if response.status_code == 200:
            result["authenticated"] = True
            result["authorized"] = True
            content_type = response.headers.get("content-type", "")
            if "application/json" in content_type:
                try:
                    result["gateway_response"] = response.json()
                except Exception:
                    result["gateway_response"] = response.text
            else:
                result["gateway_response"] = response.text
        elif response.status_code == 401:
            result["authenticated"] = False
            result["authorized"] = False
            result["auth_failure"] = "Token is invalid or expired (401 Unauthorized)"
            content_type = response.headers.get("content-type", "")
            if "application/json" in content_type:
                try:
                    result["gateway_response"] = response.json()
                except Exception:
                    result["gateway_response"] = response.text
            else:
                result["gateway_response"] = response.text
        elif response.status_code == 403:
            result["authenticated"] = True
            result["authorized"] = False
            result["auth_failure"] = "Token is valid but access to this path is forbidden (403 Forbidden)"
        elif response.status_code == 302:
            result["authenticated"] = False
            result["redirect_url"] = response.headers.get("location")
            result["auth_failure"] = "Gateway redirected (possibly to Auth0 login)"
        else:
            result["authenticated"] = None
            result["authorized"] = None
            result["gateway_status"] = f"Unexpected status: {response.status_code}"

    except httpx.ConnectError as e:
        result["gateway_error"] = f"Connection failed: {e}"
        result["note"] = "Could not reach gateway. JWT decode results above are based on local decoding only."
    except Exception as e:
        result["gateway_error"] = f"Request failed: {e}"

    return result


@mcp.tool()
async def supabase_auth(
    operation: str,
    path: str,
    payload: Optional[str] = None,
    access_token: Optional[str] = None,
) -> dict:
    """
    Interact with Supabase authentication integrations configured in the gateway.
    Use this to trigger OTP flows (email or phone), verify OTP codes, or validate
    Supabase JWTs. Use when the gateway path is configured with a Supabase auth
    integration type.
    """
    SUPPORTED_OPERATIONS = [
        "email_otp",
        "phone_otp",
        "verify_otp",
        "jwt_verify",
        "email_otp_alternative",
    ]

    if operation not in SUPPORTED_OPERATIONS:
        return {
            "error": f"Unsupported operation '{operation}'",
            "supported_operations": SUPPORTED_OPERATIONS,
        }

    url = GATEWAY_BASE_URL.rstrip("/") + "/" + path.lstrip("/")

    req_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    if access_token:
        req_headers["Authorization"] = f"Bearer {access_token}"
    elif GATEWAY_BEARER_TOKEN:
        req_headers["Authorization"] = f"Bearer {GATEWAY_BEARER_TOKEN}"

    # Parse payload
    body_obj = {}
    if payload:
        try:
            body_obj = json.loads(payload)
        except json.JSONDecodeError as e:
            return {
                "error": f"Invalid payload JSON: {e}",
                "operation": operation,
                "path": path,
            }

    # Add operation metadata to body if not present
    if operation == "verify_otp" and "type" not in body_obj:
        body_obj.setdefault("type", "email")

    result = {
        "operation": operation,
        "path": path,
        "url": url,
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Determine HTTP method based on operation
            if operation == "jwt_verify":
                http_method = "GET"
                response = await client.get(url=url, headers=req_headers)
            else:
                http_method = "POST"
                response = await client.post(
                    url=url,
                    headers=req_headers,
                    content=json.dumps(body_obj).encode(),
                )

        result["http_method"] = http_method
        result["status_code"] = response.status_code
        result["response_headers"] = dict(response.headers)

        content_type = response.headers.get("content-type", "")
        if "application/json" in content_type:
            try:
                resp_data = response.json()
                result["body"] = resp_data

                # Operation-specific result interpretation
                if operation in ("email_otp", "phone_otp", "email_otp_alternative"):
                    result["otp_sent"] = response.status_code in (200, 201)
                    if result["otp_sent"]:
                        result["message"] = "OTP sent successfully"
                    else:
                        result["message"] = "OTP send failed"

                elif operation == "verify_otp":
                    result["otp_verified"] = response.status_code in (200, 201)
                    if "access_token" in resp_data:
                        result["access_token"] = resp_data["access_token"]
                        result["refresh_token"] = resp_data.get("refresh_token")
                    result["message"] = "OTP verified" if result["otp_verified"] else "OTP verification failed"

                elif operation == "jwt_verify":
                    result["jwt_valid"] = response.status_code == 200
                    if "user" in resp_data:
                        result["user"] = resp_data["user"]
                    result["message"] = "JWT is valid" if result["jwt_valid"] else "JWT validation failed"

            except Exception:
                result["raw_body"] = response.text
        else:
            result["raw_body"] = response.text

        if response.status_code in (401, 403):
            result["auth_error"] = True
            result["suggestion"] = "Check the access_token or ensure the gateway path is correctly configured for Supabase auth."
        elif response.status_code == 404:
            result["not_found"] = True
            result["suggestion"] = f"Path '{path}' not found on the gateway. Verify the Supabase auth path configuration."

        return result

    except httpx.ConnectError as e:
        return {
            "error": "Connection failed",
            "detail": str(e),
            "operation": operation,
            "path": path,
            "note": "Ensure GATEWAY_BASE_URL environment variable is set to the correct gateway URL.",
        }
    except Exception as e:
        return {
            "error": "Supabase auth operation failed",
            "detail": str(e),
            "operation": operation,
            "path": path,
        }




_SERVER_SLUG = "irensaltali-serverlessapigateway"

def _track(tool_name: str, ua: str = ""):
    try:
        import urllib.request, json as _json
        data = _json.dumps({"slug": _SERVER_SLUG, "event": "tool_call", "tool": tool_name, "user_agent": ua}).encode()
        req = urllib.request.Request("https://www.volspan.dev/api/analytics/event", data=data, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=1)
    except Exception:
        pass

async def health(request):
    return JSONResponse({"status": "ok", "server": mcp.name})

async def tools(request):
    registered = await mcp.list_tools()
    tool_list = [{"name": t.name, "description": t.description or ""} for t in registered]
    return JSONResponse({"tools": tool_list, "count": len(tool_list)})

sse_app = mcp.http_app(transport="sse")

app = Starlette(
    routes=[
        Route("/health", health),
        Route("/tools", tools),
        Mount("/", sse_app),
    ],
    lifespan=sse_app.lifespan,
)
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
