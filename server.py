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
from typing import Optional, List, Dict, Any

mcp = FastMCP("Serverless API Gateway")

GATEWAY_BASE_URL = os.environ.get("GATEWAY_BASE_URL", "")
GATEWAY_BEARER_TOKEN = os.environ.get("GATEWAY_BEARER_TOKEN", "")


def get_auth_headers() -> dict:
    headers = {}
    if GATEWAY_BEARER_TOKEN:
        headers["Authorization"] = f"Bearer {GATEWAY_BEARER_TOKEN}"
    return headers


@mcp.tool()
async def route_request(
    method: str,
    path: str,
    headers: Optional[List[Dict[str, str]]] = None,
    body: Optional[str] = None,
    query_params: Optional[List[Dict[str, str]]] = None,
) -> dict:
    """
    Send an HTTP request through the Serverless API Gateway.
    Use this to proxy requests to configured integrations (HTTP backends, service bindings,
    Auth0, Supabase, static responses). This is the primary tool for interacting with any
    API endpoint managed by the gateway.
    """
    if not GATEWAY_BASE_URL:
        return {
            "error": "GATEWAY_BASE_URL environment variable is not set.",
            "hint": "Set GATEWAY_BASE_URL to the base URL of your Cloudflare Workers gateway."
        }

    url = GATEWAY_BASE_URL.rstrip("/") + "/" + path.lstrip("/")

    # Merge default auth headers with provided headers
    merged_headers = get_auth_headers()
    if headers:
        for header_obj in headers:
            for k, v in header_obj.items():
                merged_headers[k] = v

    # Merge query params
    params = {}
    if query_params:
        for param_obj in query_params:
            for k, v in param_obj.items():
                params[k] = v

    http_method = method.upper()

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.request(
                method=http_method,
                url=url,
                headers=merged_headers,
                params=params if params else None,
                content=body.encode("utf-8") if body else None,
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
            "url": str(response.url),
        }
    except httpx.RequestError as e:
        return {
            "error": f"Request failed: {str(e)}",
            "url": url,
            "method": http_method,
        }


@mcp.tool()
async def refresh_auth_token(
    refresh_token: Optional[str] = None,
    existing_token: Optional[str] = None,
) -> dict:
    """
    Refresh an Auth0 access token using a refresh token or validate an existing token.
    Use this when the current access token has expired or when you need to obtain a new
    token pair without requiring the user to re-authenticate.
    """
    if not refresh_token and not existing_token:
        return {
            "error": "Either refresh_token or existing_token must be provided."
        }

    if existing_token:
        # Validate existing token by decoding its payload (without verification for inspection)
        try:
            parts = existing_token.split(".")
            if len(parts) != 3:
                return {"valid": False, "error": "Invalid JWT format (must have 3 parts)."}

            import base64
            # Decode payload (add padding if needed)
            payload_b64 = parts[1]
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += "=" * padding
            payload_bytes = base64.urlsafe_b64decode(payload_b64)
            payload = json.loads(payload_bytes.decode("utf-8"))

            import time
            exp = payload.get("exp")
            now = int(time.time())
            is_expired = exp is not None and exp < now

            return {
                "valid": not is_expired,
                "expired": is_expired,
                "token": existing_token if not is_expired else None,
                "payload": payload,
                "expires_at": exp,
                "expires_in_seconds": (exp - now) if exp else None,
                "message": "Token is valid and not expired." if not is_expired else "Token has expired. Please use a refresh_token to obtain a new one.",
            }
        except Exception as e:
            return {"valid": False, "error": f"Failed to decode token: {str(e)}"}

    # Exchange refresh token
    if refresh_token:
        # Try gateway refresh endpoint first
        if GATEWAY_BASE_URL:
            refresh_url = GATEWAY_BASE_URL.rstrip("/") + "/auth/refresh"
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await client.post(
                        refresh_url,
                        headers={"Content-Type": "application/json", **get_auth_headers()},
                        content=json.dumps({"refresh_token": refresh_token}).encode("utf-8"),
                    )
                try:
                    resp_body = response.json()
                except Exception:
                    resp_body = response.text

                return {
                    "status_code": response.status_code,
                    "response": resp_body,
                    "message": "Token refresh request sent to gateway.",
                }
            except httpx.RequestError as e:
                return {
                    "error": f"Request to gateway refresh endpoint failed: {str(e)}",
                    "hint": "Ensure GATEWAY_BASE_URL is set and your gateway has a /auth/refresh route configured.",
                }
        else:
            return {
                "error": "GATEWAY_BASE_URL is not set.",
                "hint": "Set GATEWAY_BASE_URL to your gateway base URL so the refresh token exchange can be forwarded.",
                "refresh_token_received": True,
            }


@mcp.tool()
async def resolve_value_template(
    template: str,
    jwt_payload: Optional[str] = None,
    config_variables: Optional[str] = None,
    global_variables: Optional[str] = None,
    request_headers: Optional[str] = None,
    request_query: Optional[str] = None,
) -> dict:
    """
    Resolve a gateway template string to its actual runtime value.
    Use this to understand or debug what a template expression like $request.header.X-Foo,
    $request.jwt.sub, $config.key, or $request.query.param will evaluate to given specific inputs.
    """
    result = {
        "template": template,
        "resolved_value": None,
        "resolution_source": None,
        "error": None,
    }

    try:
        jwt = json.loads(jwt_payload) if jwt_payload else {}
        config_vars = json.loads(config_variables) if config_variables else {}
        global_vars = json.loads(global_variables) if global_variables else {}
        req_headers = json.loads(request_headers) if request_headers else {}
        req_query = json.loads(request_query) if request_query else {}
    except json.JSONDecodeError as e:
        result["error"] = f"Invalid JSON input: {str(e)}"
        return result

    pattern = re.compile(r'\$(request\.header|request\.jwt|config|request\.query)\.([a-zA-Z0-9\-_.]+)')
    match = pattern.search(template)

    if not match:
        result["error"] = f"Template '{template}' does not match any known pattern. Expected patterns: $request.header.*, $request.jwt.*, $config.*, $request.query.*"
        result["supported_patterns"] = [
            "$request.header.<header-name> - resolves from request headers",
            "$request.jwt.<claim> - resolves from decoded JWT payload",
            "$config.<key> - resolves from path-level config variables, falls back to global",
            "$request.query.<param> - resolves from request query parameters",
        ]
        return result

    source_type = match.group(1)
    key = match.group(2)

    if source_type == "request.header":
        # Case-insensitive header lookup
        value = None
        for h_key, h_val in req_headers.items():
            if h_key.lower() == key.lower():
                value = h_val
                break
        result["resolved_value"] = value
        result["resolution_source"] = "request.headers"
        result["looked_up_key"] = key
        if value is None:
            result["warning"] = f"Header '{key}' not found in provided request_headers."

    elif source_type == "request.jwt":
        value = jwt.get(key)
        result["resolved_value"] = value
        result["resolution_source"] = "jwt_payload"
        result["looked_up_key"] = key
        if value is None:
            result["warning"] = f"JWT claim '{key}' not found in provided jwt_payload."
            result["available_claims"] = list(jwt.keys())

    elif source_type == "config":
        if key in config_vars:
            result["resolved_value"] = config_vars[key]
            result["resolution_source"] = "config_variables (path-level)"
        elif key in global_vars:
            result["resolved_value"] = global_vars[key]
            result["resolution_source"] = "global_variables (fallback)"
        else:
            result["resolved_value"] = None
            result["resolution_source"] = None
            result["warning"] = f"Key '{key}' not found in config_variables or global_variables."
            result["available_config_keys"] = list(config_vars.keys())
            result["available_global_keys"] = list(global_vars.keys())
        result["looked_up_key"] = key

    elif source_type == "request.query":
        value = req_query.get(key)
        result["resolved_value"] = value
        result["resolution_source"] = "request.query"
        result["looked_up_key"] = key
        if value is None:
            result["warning"] = f"Query parameter '{key}' not found in provided request_query."
            result["available_query_params"] = list(req_query.keys())

    return result


@mcp.tool()
async def apply_value_mapping(
    mapping_config: str,
    original_headers: Optional[str] = None,
    jwt_payload: Optional[str] = None,
    config_variables: Optional[str] = None,
    global_variables: Optional[str] = None,
) -> dict:
    """
    Apply a mapping configuration to transform request headers and query parameters
    using template resolution. Use this to preview or debug how a mapping config will
    modify an outgoing request before it reaches a backend integration.
    """
    try:
        mapping = json.loads(mapping_config)
    except json.JSONDecodeError as e:
        return {"error": f"Invalid mapping_config JSON: {str(e)}"}

    try:
        orig_headers = json.loads(original_headers) if original_headers else {}
        jwt = json.loads(jwt_payload) if jwt_payload else {}
        config_vars = json.loads(config_variables) if config_variables else {}
        global_vars = json.loads(global_variables) if global_variables else {}
    except json.JSONDecodeError as e:
        return {"error": f"Invalid JSON input: {str(e)}"}

    def resolve_template(template: str) -> Optional[str]:
        pattern = re.compile(r'\$(request\.header|request\.jwt|config|request\.query)\.([a-zA-Z0-9\-_.]+)')
        match = pattern.search(str(template))
        if not match:
            return template  # Return literal value if no template pattern
        source_type = match.group(1)
        key = match.group(2)
        if source_type == "request.header":
            for h_key, h_val in orig_headers.items():
                if h_key.lower() == key.lower():
                    return h_val
            return None
        elif source_type == "request.jwt":
            return jwt.get(key)
        elif source_type == "config":
            if key in config_vars:
                return config_vars[key]
            return global_vars.get(key)
        elif source_type == "request.query":
            return None  # No query context here
        return None

    result = {
        "original_headers": orig_headers,
        "modified_headers": dict(orig_headers),
        "added_query_params": {},
        "resolution_details": [],
        "warnings": [],
    }

    # Apply header mappings
    if "headers" in mapping:
        for header_key, template_value in mapping["headers"].items():
            resolved = resolve_template(str(template_value))
            detail = {
                "type": "header",
                "key": header_key,
                "template": template_value,
                "resolved_value": resolved,
            }
            if resolved is not None:
                result["modified_headers"][header_key] = resolved
                detail["status"] = "applied"
            else:
                detail["status"] = "skipped (resolved to null)"
                result["warnings"].append(f"Header '{header_key}' template '{template_value}' resolved to null and was not applied.")
            result["resolution_details"].append(detail)

    # Apply query param mappings
    if "query" in mapping:
        for param_key, template_value in mapping["query"].items():
            resolved = resolve_template(str(template_value))
            detail = {
                "type": "query",
                "key": param_key,
                "template": template_value,
                "resolved_value": resolved,
            }
            if resolved is not None:
                result["added_query_params"][param_key] = resolved
                detail["status"] = "applied"
            else:
                detail["status"] = "skipped (resolved to null)"
                result["warnings"].append(f"Query param '{param_key}' template '{template_value}' resolved to null and was not applied.")
            result["resolution_details"].append(detail)

    return result


@mcp.tool()
async def validate_gateway_config(
    config_json: str,
    check_path: Optional[str] = None,
    check_method: Optional[str] = None,
) -> dict:
    """
    Validate and inspect the current API gateway configuration, including route definitions,
    integration types, CORS settings, JWT auth rules, and value mappings. Use this to check
    configuration correctness, diagnose routing issues, or understand how a path is configured.
    """
    try:
        config = json.loads(config_json)
    except json.JSONDecodeError as e:
        return {"valid": False, "error": f"Invalid JSON: {str(e)}"}

    issues = []
    warnings = []
    info = {}

    # Top-level field checks
    required_top_level = ["paths"]
    for field in required_top_level:
        if field not in config:
            issues.append(f"Missing required top-level field: '{field}'")

    if "paths" in config:
        if not isinstance(config["paths"], list):
            issues.append("'paths' must be an array.")
        else:
            info["total_routes"] = len(config["paths"])
            route_summary = []
            for i, path_cfg in enumerate(config["paths"]):
                route_info = {}
                if "path" not in path_cfg:
                    issues.append(f"Route at index {i} is missing 'path' field.")
                if "method" not in path_cfg:
                    issues.append(f"Route at index {i} is missing 'method' field.")
                if "integration" not in path_cfg:
                    warnings.append(f"Route at index {i} (path='{path_cfg.get('path', 'unknown')}') has no 'integration' defined.")
                else:
                    integration = path_cfg["integration"]
                    known_types = ["http", "service", "auth0", "supabase", "static", "mock"]
                    int_type = integration.get("type", "")
                    if int_type not in known_types:
                        warnings.append(f"Route '{path_cfg.get('path')}' has unknown integration type '{int_type}'. Known types: {known_types}")
                    route_info["integration_type"] = int_type

                route_info["path"] = path_cfg.get("path")
                route_info["method"] = path_cfg.get("method")
                route_info["has_auth"] = "auth" in path_cfg
                route_info["has_mapping"] = "mapping" in path_cfg
                route_info["has_cors"] = "cors" in path_cfg
                route_summary.append(route_info)

            info["routes"] = route_summary

    # CORS check
    if "cors" in config:
        cors = config["cors"]
        info["cors"] = cors
        if "allowedOrigins" not in cors and "allowed_origins" not in cors:
            warnings.append("CORS config found but no 'allowedOrigins' specified. This may block all cross-origin requests.")

    # JWT auth check
    if "auth" in config:
        auth = config["auth"]
        info["auth"] = auth
        if auth.get("type") == "jwt":
            if not auth.get("jwksUri") and not auth.get("secret"):
                issues.append("JWT auth configured but neither 'jwksUri' nor 'secret' is provided.")

    # Targeted path check
    targeted_route = None
    if check_path and "paths" in config and isinstance(config["paths"], list):
        method_filter = check_method.upper() if check_method else None
        for path_cfg in config["paths"]:
            cfg_path = path_cfg.get("path", "")
            cfg_method = path_cfg.get("method", "").upper()
            # Simple exact and prefix match
            path_matches = cfg_path == check_path or check_path.startswith(cfg_path.rstrip("*"))
            method_matches = method_filter is None or cfg_method == method_filter or cfg_method == "*"
            if path_matches and method_matches:
                targeted_route = path_cfg
                break

        if targeted_route:
            info["targeted_route"] = targeted_route
        else:
            warnings.append(f"No route found matching path='{check_path}' method='{check_method or 'ANY'}'.")
            info["targeted_route"] = None

    return {
        "valid": len(issues) == 0,
        "issues": issues,
        "warnings": warnings,
        "info": info,
        "summary": f"{len(issues)} issue(s), {len(warnings)} warning(s) found.",
    }


@mcp.tool()
async def substitute_env_secrets(
    config_json: str,
    env_vars: str,
    redact_secrets: bool = True,
) -> dict:
    """
    Preview how environment variable and secret placeholders ($env.VAR_NAME, $secrets.VAR_NAME)
    in a configuration object will be replaced with actual values. Use this to safely audit
    config substitution without exposing secret values, or to debug missing environment references.
    """
    try:
        config = json.loads(config_json)
    except json.JSONDecodeError as e:
        return {"error": f"Invalid config_json: {str(e)}"}

    try:
        env = json.loads(env_vars)
    except json.JSONDecodeError as e:
        return {"error": f"Invalid env_vars JSON: {str(e)}"}

    found_placeholders = []
    missing_placeholders = []
    substituted_config = json.loads(config_json)  # Deep copy via JSON

    env_pattern = re.compile(r'^\$env\.(.+)$')
    secret_pattern = re.compile(r'^\$(secrets|secret)\.(.+)$')

    def traverse_and_substitute(obj, path=""):
        if isinstance(obj, dict):
            for key in obj:
                current_path = f"{path}.{key}" if path else key
                obj[key] = traverse_and_substitute(obj[key], current_path)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                obj[i] = traverse_and_substitute(item, f"{path}[{i}]")
        elif isinstance(obj, str):
            env_match = env_pattern.match(obj)
            secret_match = secret_pattern.match(obj)
            if env_match:
                var_name = env_match.group(1)
                if var_name in env:
                    found_placeholders.append({"path": path, "placeholder": obj, "type": "env", "var_name": var_name, "resolved": True})
                    return env[var_name]
                else:
                    missing_placeholders.append({"path": path, "placeholder": obj, "type": "env", "var_name": var_name})
                    return obj
            elif secret_match:
                var_name = secret_match.group(2)
                prefix = secret_match.group(1)
                if var_name in env:
                    found_placeholders.append({
                        "path": path,
                        "placeholder": obj,
                        "type": "secret",
                        "var_name": var_name,
                        "resolved": True,
                        "value": "***" if redact_secrets else env[var_name]
                    })
                    return "***" if redact_secrets else env[var_name]
                else:
                    missing_placeholders.append({"path": path, "placeholder": obj, "type": "secret", "var_name": var_name})
                    return obj
        return obj

    traverse_and_substitute(substituted_config)

    return {
        "substituted_config": substituted_config,
        "found_placeholders": found_placeholders,
        "missing_placeholders": missing_placeholders,
        "total_found": len(found_placeholders),
        "total_missing": len(missing_placeholders),
        "all_resolved": len(missing_placeholders) == 0,
        "redact_secrets": redact_secrets,
        "summary": f"{len(found_placeholders)} placeholder(s) resolved, {len(missing_placeholders)} missing.",
    }


@mcp.tool()
async def handle_cors_preflight(
    path: str,
    origin: str,
    request_method: str = "GET",
    request_headers: Optional[str] = None,
) -> dict:
    """
    Simulate or test a CORS preflight OPTIONS request against a gateway route to verify
    CORS headers are correctly configured. Use this to diagnose cross-origin issues or
    confirm allowed origins, methods, and headers for a specific path.
    """
    if not GATEWAY_BASE_URL:
        # Simulate CORS preflight locally without making a real request
        return {
            "simulated": True,
            "warning": "GATEWAY_BASE_URL is not set. Performing local simulation only.",
            "path": path,
            "origin": origin,
            "request_method": request_method,
            "request_headers": request_headers,
            "preflight_request": {
                "method": "OPTIONS",
                "url": f"<gateway-base-url>{path}",
                "headers": {
                    "Origin": origin,
                    "Access-Control-Request-Method": request_method,
                    "Access-Control-Request-Headers": request_headers or "",
                }
            },
            "hint": "Set GATEWAY_BASE_URL to test against a real gateway deployment."
        }

    url = GATEWAY_BASE_URL.rstrip("/") + "/" + path.lstrip("/")

    preflight_headers = {
        "Origin": origin,
        "Access-Control-Request-Method": request_method,
    }
    if request_headers:
        preflight_headers["Access-Control-Request-Headers"] = request_headers

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.options(url, headers=preflight_headers)

        cors_headers = {}
        cors_keys = [
            "access-control-allow-origin",
            "access-control-allow-methods",
            "access-control-allow-headers",
            "access-control-max-age",
            "access-control-allow-credentials",
            "access-control-expose-headers",
        ]
        for k, v in response.headers.items():
            if k.lower() in cors_keys:
                cors_headers[k] = v

        origin_allowed = False
        allow_origin = response.headers.get("access-control-allow-origin", "")
        if allow_origin == "*" or allow_origin == origin:
            origin_allowed = True

        method_allowed = False
        allow_methods = response.headers.get("access-control-allow-methods", "")
        if request_method.upper() in [m.strip().upper() for m in allow_methods.split(",")]:
            method_allowed = True

        return {
            "status_code": response.status_code,
            "cors_headers": cors_headers,
            "all_response_headers": dict(response.headers),
            "origin_allowed": origin_allowed,
            "method_allowed": method_allowed,
            "preflight_successful": response.status_code in [200, 204] and origin_allowed,
            "request_details": {
                "url": url,
                "origin": origin,
                "request_method": request_method,
                "request_headers": request_headers,
            },
            "diagnosis": (
                "CORS preflight succeeded." if response.status_code in [200, 204] and origin_allowed
                else f"CORS preflight failed. Status: {response.status_code}. Origin '{origin}' {'allowed' if origin_allowed else 'NOT allowed'}. Method '{request_method}' {'allowed' if method_allowed else 'NOT allowed'}."
            )
        }
    except httpx.RequestError as e:
        return {
            "error": f"CORS preflight request failed: {str(e)}",
            "url": url,
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
