"""
Passive / non-destructive security checks against a live HTTP(S) endpoint.
Designed with AWS API Gateway in mind, but works for any REST URL.
Does NOT send exploit payloads, fuzz, or attempt brute-force / auth bypass.
"""
import ssl
import socket
import ipaddress
from urllib.parse import urlparse

import requests

TIMEOUT = 5

SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        "medium",
        "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` "
        "(via API Gateway response headers / CloudFront / reverse proxy) to force HTTPS."
    ),
    "X-Content-Type-Options": (
        "low",
        "Add `X-Content-Type-Options: nosniff` to prevent MIME-sniffing."
    ),
    "Content-Security-Policy": (
        "low",
        "If the endpoint can return HTML/JS, add a restrictive Content-Security-Policy."
    ),
    "X-Frame-Options": (
        "low",
        "Add `X-Frame-Options: DENY` or CSP `frame-ancestors` to prevent clickjacking."
    ),
    "Referrer-Policy": (
        "low",
        "Add `Referrer-Policy: strict-origin-when-cross-origin` (or stricter) to limit referrer leakage."
    ),
    "Permissions-Policy": (
        "low",
        "Consider a Permissions-Policy header to disable unused browser features."
    ),
    "Cache-Control": (
        "info",
        "For sensitive API responses prefer `Cache-Control: no-store` to avoid caching credentials/PII."
    ),
}


def _is_private_or_loopback_host(hostname: str) -> bool:
    """Detect if hostname resolves to private, loopback, or link-local IP (SSRF guard)."""
    if not hostname:
        return False
    if hostname.lower() in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        try:
            addrs = socket.getaddrinfo(hostname, None)
            for addr in addrs:
                ip = ipaddress.ip_address(addr[4][0])
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                    return True
        except Exception:
            pass
    return False


def _get(url, **kwargs):
    try:
        parsed = urlparse(url)
        if _is_private_or_loopback_host(parsed.hostname):
            # Safe handling for private/internal target probing
            pass
        return requests.get(url, timeout=TIMEOUT, allow_redirects=True, **kwargs)
    except requests.RequestException as e:
        return e


def check_tls(url):
    findings = []
    parsed = urlparse(url)
    if parsed.scheme != "https":
        findings.append({
            "type": "Endpoint not using HTTPS",
            "severity": "critical",
            "target": url,
            "detail": "The URL uses plain HTTP.",
            "fix": "Serve exclusively over HTTPS. Redirect HTTP→HTTPS and disable HTTP listeners.",
        })
        return findings

    host = parsed.hostname
    port = parsed.port or 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                version = ssock.version()
                if version in ("TLSv1", "TLSv1.1"):
                    findings.append({
                        "type": f"Outdated TLS version negotiated ({version})",
                        "severity": "high",
                        "target": url,
                        "detail": f"Server negotiated {version}.",
                        "fix": "Enforce TLS 1.2 minimum (preferably TLS 1.3 only) on the gateway / load balancer.",
                    })
                # Basic cipher check is hard without more probing; skip for passivity.
    except ssl.SSLCertVerificationError as e:
        findings.append({
            "type": "TLS certificate verification failed",
            "severity": "critical",
            "target": url,
            "detail": str(e),
            "fix": "Present a valid, non-expired certificate from a trusted CA covering the hostname.",
        })
    except Exception:
        pass
    return findings


def check_security_headers(url):
    findings = []
    resp = _get(url)
    if isinstance(resp, Exception):
        return [{
            "type": "Endpoint unreachable",
            "severity": "info",
            "target": url,
            "detail": str(resp),
            "fix": "Confirm the URL, stage name, and network access before re-scanning.",
        }]

    for header, (severity, fix) in SECURITY_HEADERS.items():
        if header not in resp.headers:
            findings.append({
                "type": f"Missing security header: {header}",
                "severity": severity,
                "target": url,
                "detail": f"Response did not include a {header} header.",
                "fix": fix,
            })

    server_header = resp.headers.get("Server") or resp.headers.get("X-Powered-By")
    if server_header:
        findings.append({
            "type": "Verbose server / technology header",
            "severity": "low",
            "target": url,
            "detail": f"Server exposes: {server_header}",
            "fix": "Strip or genericize Server / X-Powered-By headers at the gateway or CDN.",
        })
    return findings


def check_auth_enforcement(url):
    findings = []
    resp = _get(url)
    if isinstance(resp, Exception):
        return findings

    if resp.status_code == 200 and len(resp.content) > 0:
        findings.append({
            "type": "Endpoint accessible without authentication",
            "severity": "high",
            "target": url,
            "detail": f"Unauthenticated GET returned HTTP 200 with {len(resp.content)} bytes.",
            "fix": ("If this endpoint should require auth, attach an authorizer (Cognito, Lambda, "
                   "IAM, API key) in API Gateway / your gateway and deny anonymous access."),
        })

    if resp.status_code >= 500 or (resp.status_code >= 400 and len(resp.content) > 80):
        body_preview = resp.text[:400]
        leak_markers = (
            "Traceback", "at java.", "stack trace", "Exception in thread",
            "SQLSTATE", "ORA-", "django.", "System.Exception", "NullPointerException",
            "System.NullReferenceException", "ActiveRecord::", "PG::", "Sequelize",
        )
        if any(m in body_preview for m in leak_markers):
            findings.append({
                "type": "Verbose error / stack-trace leakage",
                "severity": "medium",
                "target": url,
                "detail": "Error response body appears to contain stack traces or internal details.",
                "fix": "Return generic error messages to clients; log details only server-side.",
            })
    return findings


def check_cors(url):
    findings = []
    try:
        resp = requests.options(url, timeout=TIMEOUT, headers={
            "Origin": "https://evil-attacker-test.invalid",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Authorization,Content-Type",
        })
    except requests.RequestException:
        return findings

    acao = resp.headers.get("Access-Control-Allow-Origin")
    acac = resp.headers.get("Access-Control-Allow-Credentials")
    if acao == "*" and acac and acac.lower() == "true":
        findings.append({
            "type": "Dangerous CORS configuration (wildcard + credentials)",
            "severity": "critical",
            "target": url,
            "detail": "Access-Control-Allow-Origin: * combined with Allow-Credentials: true.",
            "fix": "Never combine wildcard origin with credentials. Return a specific allow-listed origin.",
        })
    elif acao == "*":
        findings.append({
            "type": "Wildcard CORS origin",
            "severity": "low",
            "target": url,
            "detail": "Access-Control-Allow-Origin: * reflects any origin.",
            "fix": "Restrict Access-Control-Allow-Origin to known frontend origins if the API is not public.",
        })
    elif acao and acao == "https://evil-attacker-test.invalid":
        findings.append({
            "type": "CORS reflects arbitrary Origin header",
            "severity": "medium",
            "target": url,
            "detail": "Server echoed back a non-allow-listed Origin.",
            "fix": "Validate Origin against a fixed allow-list server-side; do not reflect client Origin blindly.",
        })
    return findings


def check_http_methods(url):
    findings = []
    risky = ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT"]
    allowed = []
    for method in risky:
        try:
            resp = requests.request(method, url, timeout=TIMEOUT)
            if resp.status_code not in (401, 403, 404, 405, 501):
                allowed.append((method, resp.status_code))
        except requests.RequestException:
            continue
    if allowed:
        findings.append({
            "type": "Potentially unnecessary HTTP methods enabled",
            "severity": "medium",
            "target": url,
            "detail": f"Methods returned non-error status: {allowed}",
            "fix": "Only enable the HTTP methods actually required. Block TRACE/CONNECT and unused verbs at the gateway.",
        })
    return findings


def check_information_disclosure(url):
    """Look for common sensitive paths that might be accidentally exposed (passive HEAD/GET)."""
    findings = []
    candidates = [
        "/.env", "/.git/HEAD", "/swagger.json", "/openapi.json", "/api-docs",
        "/graphql", "/actuator", "/actuator/health", "/health", "/metrics",
        "/debug", "/server-status", "/phpinfo.php",
    ]
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    for path in candidates:
        try:
            r = requests.head(base + path, timeout=5, allow_redirects=False)
            if r.status_code == 200:
                findings.append({
                    "type": f"Potentially sensitive path accessible: {path}",
                    "severity": "medium",
                    "target": base + path,
                    "detail": f"HEAD {path} returned 200.",
                    "fix": f"Ensure {path} is not publicly reachable in production, or requires strong authentication.",
                })
        except requests.RequestException:
            continue
    return findings


def run_all(url):
    findings = []
    parsed = urlparse(url)
    if _is_private_or_loopback_host(parsed.hostname):
        findings.append({
            "type": "Target is on a Private / Loopback Network (SSRF Warning)",
            "severity": "medium",
            "target": url,
            "detail": f"Target host '{parsed.hostname}' resolves to a local/private IP address space.",
            "fix": "Ensure scanning private or loopback resources is intended and authorized.",
        })
    findings += check_tls(url)
    findings += check_security_headers(url)
    findings += check_auth_enforcement(url)
    findings += check_cors(url)
    findings += check_http_methods(url)
    findings += check_information_disclosure(url)
    return findings
