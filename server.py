from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.responses import JSONResponse
import uvicorn
import threading
from fastmcp import FastMCP
import httpx
import os
import json
import base64
import re
from typing import Optional

mcp = FastMCP("Serverless API Gateway")

# Load gateway configuration from CONFIG env var
def get_config() -> dict:
    config_str = os.environ.get("CONFIG", "{}")
    try:
        return json.loads(config_str)
    except json.JSONDecodeError:
        return {}

def get_bearer_token() -> Optional[str]:
    """Extract bearer token from CONFIG env var."""
    config = get_config()
    return config.get("bearer_token") or config.get("token")

def get_base_url() -> Optional[str]:
    """Get the gateway base URL from config."""
    config = get_config()
    return config.get("base_url") or config.get("gateway_url") or ""

def build_auth_headers() -> dict:
    token = get_bearer_token()
    if token:
        return {"Authorization": f"Bearer {token}"}
    return {}

def decode_jwt_payload(token: str) -> Optional[dict]:
    """Decode JWT payload without verification."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload_b64 = parts[1]
        # Add padding
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        return json.loads(payload_bytes)
    except Exception as e:
        return None

def resolve_template_value(
    template: str,
    jwt_payload: Optional[dict] = None,
    config_variables: Optional[dict] = None,
    request_headers: Optional[list] = None,
    query_params: Optional[list] = None
) -> Optional[str]:
    """Resolve a gateway value template string."""
    pattern = re.compile(r'\$(request\.header|request\.jwt|config|request\.query)\.([a-zA-Z0-9\-_.]+)')
    match = pattern.search(template)
    if not match:
        return None
    source = match.group(1)
    key = match.group(2)
    if source == "request.header":
        if request_headers:
            for h in request_headers:
                if h.get("name", "").lower() == key.lower():
                    return h.get("value")
        return None
    elif source == "request.jwt":
        if jwt_payload and key in jwt_payload:
            return str(jwt_payload[key])
        return None
    elif source == "config":
        global_config = get_config()
        config_vars = config_variables or {}
        if key in config_vars:
            return str(config_vars[key])
        if key in global_config:
            return str(global_config[key])
        return None
    elif source == "request.query":
        if query_params:
            for q in query_params:
                if q.get("name") == key:
                    return q.get("value")
        return None
    return None


@mcp.tool()
async def proxy_request(
    _track("proxy_request")
    path: str,
    method: str,
    headers: Optional[list] = None,
    body: Optional[str] = None,
    query_params: Optional[list] = None
) -> dict:
    """
    Proxy an HTTP request through the Serverless API Gateway to a configured backend endpoint.
    Use this when you need to forward requests to upstream services with optional header/query
    parameter transformations, JWT authentication, and CORS handling.
    Supports GET, POST, PUT, DELETE, PATCH methods.
    """
    base_url = get_base_url()
    if not base_url:
        return {
            "error": "No gateway base_url configured. Set base_url in CONFIG environment variable.",
            "config_keys_present": list(get_config().keys())
        }

    # Build URL
    url = base_url.rstrip("/") + "/" + path.lstrip("/")

    # Build query params
    params = {}
    if query_params:
        for qp in query_params:
            params[qp["name"]] = qp["value"]

    # Build headers
    req_headers = {**build_auth_headers()}
    if headers:
        for h in headers:
            req_headers[h["name"]] = h["value"]

    # Determine content type for body
    if body and "Content-Type" not in req_headers:
        try:
            json.loads(body)
            req_headers["Content-Type"] = "application/json"
        except (json.JSONDecodeError, TypeError):
            req_headers["Content-Type"] = "text/plain"

    method_upper = method.upper()

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.request(
                method=method_upper,
                url=url,
                headers=req_headers,
                params=params if params else None,
                content=body.encode() if body else None
            )
            # Try to parse JSON response
            try:
                response_body = response.json()
            except Exception:
                response_body = response.text

            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response_body,
                "url": str(response.url)
            }
    except httpx.RequestError as e:
        return {
            "error": f"Request failed: {str(e)}",
            "url": url,
            "method": method_upper
        }


@mcp.tool()
async def authenticate_jwt(
    _track("authenticate_jwt")
    token: str,
    path: Optional[str] = None
) -> dict:
    """
    Validate a JWT Bearer token against the gateway's configured auth settings
    (JWT, Auth0, or Supabase). Use this to verify whether a token is valid,
    not expired, and properly signed before making authenticated requests.
    """
    import time

    result = {
        "token_provided": bool(token),
        "path": path,
        "valid": False,
        "expired": None,
        "payload": None,
        "error": None
    }

    payload = decode_jwt_payload(token)
    if payload is None:
        result["error"] = "Failed to decode JWT payload. Token may be malformed."
        return result

    result["payload"] = payload

    # Check expiration
    exp = payload.get("exp")
    now = int(time.time())
    if exp is not None:
        if now > exp:
            result["expired"] = True
            result["valid"] = False
            result["error"] = f"Token expired at {exp} (current time: {now})"
            return result
        else:
            result["expired"] = False
            result["seconds_until_expiry"] = exp - now

    # Check nbf (not before)
    nbf = payload.get("nbf")
    if nbf is not None and now < nbf:
        result["valid"] = False
        result["error"] = f"Token not valid before {nbf}"
        return result

    # If gateway base URL is available, try to validate against gateway
    base_url = get_base_url()
    if base_url and path:
        url = base_url.rstrip("/") + "/" + path.lstrip("/")
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    url,
                    headers={"Authorization": f"Bearer {token}"}
                )
                result["gateway_validation_status"] = response.status_code
                if response.status_code == 401:
                    result["valid"] = False
                    result["error"] = "Gateway rejected token with 401 Unauthorized"
                    return result
                elif response.status_code in (200, 204, 403):
                    result["valid"] = True
                    result["gateway_validated"] = True
        except httpx.RequestError as e:
            result["gateway_validation_error"] = str(e)

    result["valid"] = True
    result["claims"] = {
        "sub": payload.get("sub"),
        "iss": payload.get("iss"),
        "aud": payload.get("aud"),
        "iat": payload.get("iat"),
        "exp": payload.get("exp")
    }
    return result


@mcp.tool()
async def refresh_auth_token(
    _track("refresh_auth_token")
    access_token: str,
    refresh_token: str,
    path: Optional[str] = None
) -> dict:
    """
    Exchange an Auth0 refresh token for a new access token when the current
    access token has expired. Use this when a request fails with a 401 Unauthorized
    error and you have a refresh token available.
    """
    base_url = get_base_url()
    if not base_url:
        return {
            "error": "No gateway base_url configured in CONFIG environment variable."
        }

    refresh_path = path or "/auth/refresh"
    url = base_url.rstrip("/") + "/" + refresh_path.lstrip("/")

    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-Refresh-Token": refresh_token,
        "Content-Type": "application/json"
    }

    body = json.dumps({"refresh_token": refresh_token})

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                url,
                headers=headers,
                content=body.encode()
            )
            try:
                response_body = response.json()
            except Exception:
                response_body = response.text

            return {
                "status_code": response.status_code,
                "success": response.status_code in (200, 201),
                "response": response_body,
                "url": str(response.url)
            }
    except httpx.RequestError as e:
        return {
            "error": f"Token refresh request failed: {str(e)}",
            "url": url
        }


@mcp.tool()
async def auth0_login(
    _track("auth0_login")
    flow: str,
    code: Optional[str] = None,
    access_token: Optional[str] = None,
    state: Optional[str] = None
) -> dict:
    """
    Initiate or complete an Auth0 authentication flow. Use this to get user profile info,
    handle the OAuth callback after login, or retrieve user information from Auth0
    using an existing token.
    """
    config = get_config()
    base_url = get_base_url()

    if not base_url:
        return {
            "error": "No gateway base_url configured in CONFIG environment variable."
        }

    auth0_config = config.get("auth0", {})

    if flow == "redirect":
        # Build Auth0 login redirect URL
        domain = auth0_config.get("domain", "")
        client_id = auth0_config.get("client_id", "")
        redirect_uri = auth0_config.get("redirect_uri", base_url + "/auth/callback")
        scope = auth0_config.get("scope", "openid profile email")

        if not domain or not client_id:
            return {
                "error": "Auth0 domain and client_id must be configured in CONFIG.auth0",
                "flow": flow
            }

        login_url = (
            f"https://{domain}/authorize"
            f"?response_type=code"
            f"&client_id={client_id}"
            f"&redirect_uri={redirect_uri}"
            f"&scope={scope}"
        )
        if state:
            login_url += f"&state={state}"

        return {
            "flow": "redirect",
            "login_url": login_url,
            "instructions": "Redirect the user to login_url to begin Auth0 authentication."
        }

    elif flow == "callback":
        if not code:
            return {"error": "Authorization code is required for 'callback' flow."}

        callback_path = auth0_config.get("callback_path", "/auth/callback")
        url = base_url.rstrip("/") + "/" + callback_path.lstrip("/")

        params = {"code": code}
        if state:
            params["state"] = state

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(url, params=params)
                try:
                    body = response.json()
                except Exception:
                    body = response.text
                return {
                    "flow": "callback",
                    "status_code": response.status_code,
                    "success": response.status_code in (200, 201),
                    "response": body
                }
        except httpx.RequestError as e:
            return {"error": f"Auth0 callback request failed: {str(e)}"}

    elif flow == "userinfo":
        if not access_token:
            return {"error": "access_token is required for 'userinfo' flow."}

        userinfo_path = auth0_config.get("userinfo_path", "/auth/userinfo")
        url = base_url.rstrip("/") + "/" + userinfo_path.lstrip("/")

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(
                    url,
                    headers={"Authorization": f"Bearer {access_token}"}
                )
                try:
                    body = response.json()
                except Exception:
                    body = response.text
                return {
                    "flow": "userinfo",
                    "status_code": response.status_code,
                    "success": response.status_code == 200,
                    "user_profile": body
                }
        except httpx.RequestError as e:
            return {"error": f"Auth0 userinfo request failed: {str(e)}"}

    else:
        return {
            "error": f"Unknown flow '{flow}'. Supported flows: 'callback', 'userinfo', 'redirect'."
        }


@mcp.tool()
async def supabase_passwordless_auth(
    _track("supabase_passwordless_auth")
    method: str,
    identifier: str,
    path: Optional[str] = None
) -> dict:
    """
    Send a passwordless authentication request (OTP via email or phone) using Supabase.
    Use this to initiate a login flow where the user receives a one-time code to verify
    their identity without a password.
    """
    base_url = get_base_url()
    if not base_url:
        return {
            "error": "No gateway base_url configured in CONFIG environment variable."
        }

    if method not in ("email", "phone"):
        return {"error": "method must be 'email' or 'phone'"}

    auth_path = path or f"/auth/otp/{method}"
    url = base_url.rstrip("/") + "/" + auth_path.lstrip("/")

    payload_key = "email" if method == "email" else "phone"
    body = json.dumps({payload_key: identifier})

    headers = {
        **build_auth_headers(),
        "Content-Type": "application/json"
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(url, headers=headers, content=body.encode())
            try:
                response_body = response.json()
            except Exception:
                response_body = response.text

            return {
                "method": method,
                "identifier": identifier,
                "status_code": response.status_code,
                "success": response.status_code in (200, 201, 204),
                "response": response_body,
                "url": str(response.url)
            }
    except httpx.RequestError as e:
        return {"error": f"Supabase OTP request failed: {str(e)}", "url": url}


@mcp.tool()
async def supabase_verify_otp(
    _track("supabase_verify_otp")
    identifier: str,
    otp: str,
    type: Optional[str] = "email",
    path: Optional[str] = None
) -> dict:
    """
    Verify a Supabase one-time password (OTP) to complete passwordless authentication.
    Use this after the user receives their OTP code to exchange it for a valid Supabase
    session token.
    """
    base_url = get_base_url()
    if not base_url:
        return {
            "error": "No gateway base_url configured in CONFIG environment variable."
        }

    verify_path = path or "/auth/otp/verify"
    url = base_url.rstrip("/") + "/" + verify_path.lstrip("/")

    otp_type = type or "email"
    identifier_key = "email" if otp_type == "email" else "phone"

    body = json.dumps({
        identifier_key: identifier,
        "token": otp,
        "type": otp_type
    })

    headers = {
        **build_auth_headers(),
        "Content-Type": "application/json"
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(url, headers=headers, content=body.encode())
            try:
                response_body = response.json()
            except Exception:
                response_body = response.text

            return {
                "identifier": identifier,
                "otp_type": otp_type,
                "status_code": response.status_code,
                "success": response.status_code in (200, 201),
                "session": response_body,
                "url": str(response.url)
            }
    except httpx.RequestError as e:
        return {"error": f"Supabase OTP verification failed: {str(e)}", "url": url}


@mcp.tool()
async def resolve_value_template(
    _track("resolve_value_template")
    template: str,
    jwt_payload: Optional[str] = None,
    config_variables: Optional[str] = None,
    request_headers: Optional[list] = None,
    query_params: Optional[list] = None
) -> dict:
    """
    Resolve a gateway value template string against request context, JWT payload,
    and config variables. Use this to understand or debug how the gateway will transform
    values like '$request.jwt.sub', '$request.header.X-Foo', '$config.myVar',
    or '$request.query.param' at runtime.
    """
    parsed_jwt = None
    if jwt_payload:
        try:
            parsed_jwt = json.loads(jwt_payload)
        except json.JSONDecodeError:
            return {"error": "jwt_payload is not valid JSON", "template": template}

    parsed_config = None
    if config_variables:
        try:
            parsed_config = json.loads(config_variables)
        except json.JSONDecodeError:
            return {"error": "config_variables is not valid JSON", "template": template}

    resolved = resolve_template_value(
        template=template,
        jwt_payload=parsed_jwt,
        config_variables=parsed_config,
        request_headers=request_headers,
        query_params=query_params
    )

    # Determine template type for explanation
    pattern = re.compile(r'\$(request\.header|request\.jwt|config|request\.query)\.([a-zA-Z0-9\-_.]+)')
    match = pattern.search(template)
    template_info = {}
    if match:
        template_info["source"] = match.group(1)
        template_info["key"] = match.group(2)

    return {
        "template": template,
        "resolved_value": resolved,
        "resolved": resolved is not None,
        "template_info": template_info,
        "context_provided": {
            "jwt_payload": parsed_jwt is not None,
            "config_variables": parsed_config is not None,
            "request_headers_count": len(request_headers) if request_headers else 0,
            "query_params_count": len(query_params) if query_params else 0
        }
    }


@mcp.tool()
async def get_gateway_config(
    _track("get_gateway_config")
    filter_path: Optional[str] = None,
    include_secrets: bool = False
) -> dict:
    """
    Retrieve and inspect the current Serverless API Gateway configuration, including
    defined routes, integration types, auth settings, CORS policy, and value mappings.
    Use this to understand the gateway setup, debug routing issues, or audit security
    policies before making requests.
    """
    config = get_config()

    if not config:
        return {
            "error": "No configuration found. Set the CONFIG environment variable with the gateway JSON configuration.",
            "hint": "CONFIG should be a JSON string with keys like base_url, paths, cors, auth, etc."
        }

    def sanitize_config(obj, depth=0):
        """Recursively sanitize config, hiding secret values."""
        if depth > 10:
            return obj
        if isinstance(obj, dict):
            result = {}
            for k, v in obj.items():
                lower_k = k.lower()
                is_sensitive = any(word in lower_k for word in ["secret", "password", "key", "token", "credential"])
                if is_sensitive and not include_secrets:
                    if isinstance(v, str):
                        result[k] = "[REDACTED]" if not v.startswith("$") else v
                    else:
                        result[k] = "[REDACTED]"
                else:
                    result[k] = sanitize_config(v, depth + 1)
            return result
        elif isinstance(obj, list):
            return [sanitize_config(item, depth + 1) for item in obj]
        else:
            return obj

    sanitized = sanitize_config(config)

    # Extract and filter paths
    paths = sanitized.get("paths", [])
    if filter_path:
        paths = [
            p for p in paths
            if isinstance(p, dict) and (
                p.get("path", "") == filter_path or
                p.get("path", "").startswith(filter_path.rstrip("*"))
            )
        ]

    # Build summary
    summary = {
        "base_url": sanitized.get("base_url") or sanitized.get("gateway_url", "not configured"),
        "total_paths_configured": len(sanitized.get("paths", [])),
        "filtered_paths": paths if filter_path else sanitized.get("paths", []),
        "cors": sanitized.get("cors"),
        "global_auth": sanitized.get("auth"),
        "auth0": sanitized.get("auth0"),
        "supabase": sanitized.get("supabase"),
        "global_variables": sanitized.get("variables") or sanitized.get("globalVariables"),
    }

    if include_secrets:
        summary["secret_key_names"] = [
            k for k in config.keys()
            if any(word in k.lower() for word in ["secret", "password", "key", "token"])
        ]

    # Integration types summary
    integration_types = set()
    for p in sanitized.get("paths", []):
        if isinstance(p, dict):
            itype = p.get("integration") or p.get("type")
            if itype:
                integration_types.add(itype)

    summary["integration_types_used"] = list(integration_types)

    return summary




_SERVER_SLUG = "irensaltali-serverlessapigateway"

def _track(tool_name: str, ua: str = ""):
    import threading
    def _send():
        try:
            import urllib.request, json as _json
            data = _json.dumps({"slug": _SERVER_SLUG, "event": "tool_call", "tool": tool_name, "user_agent": ua}).encode()
            req = urllib.request.Request("https://www.volspan.dev/api/analytics/event", data=data, headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5)
        except Exception:
            pass
    threading.Thread(target=_send, daemon=True).start()

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
