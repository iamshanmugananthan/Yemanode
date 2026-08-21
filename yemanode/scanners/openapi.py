"""
OpenAPI (v2 / v3) & Postman Collection scanner for Yemanode.
Parses API contracts statically and generates targeted passive security probes.
"""
import json
import os
from urllib.parse import urljoin

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

from . import api_security


def parse_spec_file(file_path):
    """
    Parses an OpenAPI (JSON/YAML) or Postman Collection (.json) file.
    Returns a dict with 'type', 'title', 'base_url', and list of 'endpoints'.
    """
    if not os.path.isfile(file_path):
        return None

    content = ""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
    except Exception:
        return None

    data = None
    try:
        data = json.loads(content)
    except Exception:
        if HAS_YAML:
            try:
                data = yaml.safe_load(content)
            except Exception:
                pass

    if not isinstance(data, dict):
        return None

    # Check if Postman Collection
    if "info" in data and ("_postman_id" in data["info"] or "schema" in data["info"]):
        return _parse_postman(data, file_path)

    # Check if OpenAPI / Swagger
    if "openapi" in data or "swagger" in data or "paths" in data:
        return _parse_openapi(data, file_path)

    return None


def _parse_openapi(data, file_path):
    title = data.get("info", {}).get("title", os.path.basename(file_path))
    version = data.get("openapi") or data.get("swagger") or "2.0/3.0"

    # Base URL extraction
    base_url = ""
    if "servers" in data and isinstance(data["servers"], list) and data["servers"]:
        base_url = data["servers"][0].get("url", "")
    elif "host" in data:
        schemes = data.get("schemes", ["https"])
        scheme = schemes[0] if schemes else "https"
        base_path = data.get("basePath", "")
        base_url = f"{scheme}://{data['host']}{base_path}"

    endpoints = []
    paths = data.get("paths", {})
    global_security = data.get("security", [])

    for path_name, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method in ("get", "post", "put", "delete", "patch", "options", "head"):
            if method in path_item:
                op = path_item[method]
                if not isinstance(op, dict):
                    continue
                sec = op.get("security", global_security)
                endpoints.append({
                    "path": path_name,
                    "method": method.upper(),
                    "summary": op.get("summary", ""),
                    "authenticated": bool(sec),
                    "parameters": op.get("parameters", []),
                    "request_body": op.get("requestBody", {}),
                })

    return {
        "spec_type": f"OpenAPI {version}",
        "title": title,
        "base_url": base_url,
        "global_security": bool(global_security),
        "endpoints": endpoints,
        "raw_data": data,
        "file_path": file_path,
    }


def _parse_postman(data, file_path):
    title = data.get("info", {}).get("name", os.path.basename(file_path))
    endpoints = []

    def extract_items(items):
        for item in items:
            if "item" in item:
                extract_items(item["item"])
            elif "request" in item:
                req = item["request"]
                if isinstance(req, dict):
                    method = req.get("method", "GET").upper()
                    url_info = req.get("url", {})
                    path = ""
                    if isinstance(url_info, str):
                        path = url_info
                    elif isinstance(url_info, dict):
                        raw_path = url_info.get("raw", "")
                        path = raw_path
                    endpoints.append({
                        "path": path,
                        "method": method,
                        "summary": item.get("name", ""),
                        "authenticated": bool(req.get("auth")),
                        "parameters": [],
                        "request_body": req.get("body", {}),
                    })

    extract_items(data.get("item", []))

    return {
        "spec_type": "Postman Collection",
        "title": title,
        "base_url": "",
        "global_security": False,
        "endpoints": endpoints,
        "raw_data": data,
        "file_path": file_path,
    }


def audit_spec_statically(parsed_spec):
    """
    Performs static security analysis on the API specification itself:
    - Missing global/operation authentication
    - BOLA / IDOR risk patterns on path parameters
    - Sensitive query parameters (passwords, tokens in URLs)
    - Unauthenticated state-changing methods (PUT, DELETE, PATCH)
    - Insecure HTTP schemes
    """
    findings = []
    if not parsed_spec:
        return findings

    spec_file = parsed_spec["file_path"]
    endpoints = parsed_spec["endpoints"]

    # 1. Check global security / authentication requirement
    if not parsed_spec["global_security"] and endpoints:
        unauth_count = sum(1 for e in endpoints if not e["authenticated"])
        if unauth_count > 0:
            findings.append({
                "type": f"[{parsed_spec['spec_type']}] Endpoints Missing Declared Security / Auth Schemes",
                "severity": "high",
                "file": spec_file,
                "line": 0,
                "cwe": "CWE-306",
                "owasp": "API2:2023-Broken Authentication",
                "cvss": 7.5,
                "snippet": f"{unauth_count} of {len(endpoints)} endpoint(s) lack auth declarations.",
                "fix": "Declare global security requirements (OAuth2, Bearer JWT, apiKey) or specify security per operation in the OpenAPI spec.",
            })

    # 2. Check each endpoint for BOLA/IDOR, state-changing unauth, and sensitive query params
    for e in endpoints:
        path = e["path"]
        method = e["method"]
        is_auth = e["authenticated"]

        # BOLA / IDOR detection (Object-level identifier in path without auth)
        if ("{" in path or "/:" in path) and not is_auth:
            findings.append({
                "type": f"[{parsed_spec['spec_type']}] Potential BOLA / IDOR Risk: Unauthenticated Resource Identifier ({method} {path})",
                "severity": "critical",
                "file": spec_file,
                "line": 0,
                "cwe": "CWE-284",
                "owasp": "API1:2023-Broken Object Level Authorization",
                "cvss": 8.6,
                "snippet": f"{method} {path}",
                "fix": "Enforce object-level access controls and require user session validation before returning resource by ID.",
            })

        # State-changing HTTP methods without authentication
        if method in ("DELETE", "PUT", "PATCH") and not is_auth:
            findings.append({
                "type": f"[{parsed_spec['spec_type']}] Unauthenticated State-Changing Operation ({method} {path})",
                "severity": "high",
                "file": spec_file,
                "line": 0,
                "cwe": "CWE-306",
                "owasp": "API2:2023-Broken Authentication",
                "cvss": 7.5,
                "snippet": f"{method} {path}",
                "fix": "Ensure state-changing endpoints (PUT/DELETE/PATCH) strictly enforce authentication and authorization.",
            })

        # Sensitive Query Parameters (e.g. ?token=, ?password=)
        for param in e.get("parameters", []):
            if isinstance(param, dict) and param.get("in") == "query":
                pname = str(param.get("name", "")).lower()
                if pname in ("password", "passwd", "token", "secret", "api_key", "apikey", "auth"):
                    findings.append({
                        "type": f"[{parsed_spec['spec_type']}] Sensitive Information Passed in Query Parameter ({pname})",
                        "severity": "high",
                        "file": spec_file,
                        "line": 0,
                        "cwe": "CWE-598",
                        "owasp": "API2:2023-Broken Authentication",
                        "cvss": 7.4,
                        "snippet": f"Endpoint: {method} {path} | Query Param: {param.get('name')}",
                        "fix": "Pass sensitive credentials in the Authorization header or request body, never in URL query strings (which get logged in proxies and browser history).",
                    })

    # 3. Check for insecure HTTP scheme declaration
    raw = parsed_spec.get("raw_data", {})
    schemes = raw.get("schemes", [])
    if "http" in schemes and "https" not in schemes:
        findings.append({
            "type": f"[{parsed_spec['spec_type']}] Insecure HTTP Scheme Declared in Contract",
            "severity": "critical",
            "file": spec_file,
            "line": 0,
            "cwe": "CWE-319",
            "owasp": "API2:2023-Broken Authentication",
            "cvss": 9.1,
            "snippet": "schemes: ['http']",
            "fix": "Enforce HTTPS exclusively for all declared API server schemes.",
        })

    return findings


def probe_spec_endpoints(parsed_spec, target_url=None):
    """
    Conducts passive probes against endpoints declared in the spec.
    """
    findings = []
    if not parsed_spec:
        return findings

    base = target_url or parsed_spec.get("base_url", "")
    if not base:
        return findings

    if not base.startswith(("http://", "https://")):
        base = "https://" + base

    endpoints = parsed_spec.get("endpoints", [])
    tested_paths = set()

    for e in endpoints[:20]:
        p = e["path"]
        clean_path = p
        if "{" in clean_path:
            import re
            clean_path = re.sub(r"\{[^}]+\}", "1", clean_path)

        if clean_path in tested_paths:
            continue
        tested_paths.add(clean_path)

        full_url = urljoin(base, clean_path)
        findings.extend(api_security.check_auth_enforcement(full_url))

    return findings
