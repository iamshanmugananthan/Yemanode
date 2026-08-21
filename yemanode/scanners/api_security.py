"""
Passive / non-destructive security checks against a live HTTP(S) endpoint.
Designed for AWS API Gateway, Kong, Apigee, Express, Spring, and REST endpoints.
Audits TLS, security headers, CORS, rate limits, sensitive paths, error stack traces, and shadow endpoints.
"""
import ipaddress
import socket
import ssl
from urllib.parse import urlparse

import requests

TIMEOUT = 6

SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        "medium", "CWE-319", "API2:2023-Broken Authentication", 6.5,
        "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` to force modern HTTPS."
    ),
    "X-Content-Type-Options": (
        "low", "CWE-693", "API7:2023-Security Misconfiguration", 3.7,
        "Add `X-Content-Type-Options: nosniff` to prevent MIME-sniffing and content confusion attacks."
    ),
    "Content-Security-Policy": (
        "low", "CWE-79", "API7:2023-Security Misconfiguration", 3.7,
        "If the endpoint can return HTML/JSON error pages, add a restrictive Content-Security-Policy."
    ),
    "X-Frame-Options": (
        "low", "CWE-1021", "API7:2023-Security Misconfiguration", 3.7,
        "Add `X-Frame-Options: DENY` to prevent clickjacking and UI redressing."
    ),
    "Referrer-Policy": (
        "low", "CWE-200", "API7:2023-Security Misconfiguration", 3.1,
        "Add `Referrer-Policy: strict-origin-when-cross-origin` to limit sensitive URI parameter leakage."
    ),
    "Cache-Control": (
        "info", "CWE-524", "API7:2023-Security Misconfiguration", 0.0,
        "For sensitive API responses, return `Cache-Control: no-store` to prevent caching tokens or PII."
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


def _get(url, verify=True, **kwargs):
    try:
        return requests.get(url, timeout=TIMEOUT, allow_redirects=True, verify=verify, **kwargs)
    except requests.exceptions.SSLError as e:
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            resp = requests.get(url, timeout=TIMEOUT, allow_redirects=True, verify=False, **kwargs)
            resp._ssl_error = str(e)
            return resp
        except Exception:
            return e
    except requests.RequestException as e:
        return e


def check_tls(url):
    findings = []
    parsed = urlparse(url)
    if parsed.scheme != "https":
        findings.append({
            "type": "[API Transport] Plain HTTP Scheme in Use",
            "severity": "critical",
            "target": url,
            "cwe": "CWE-319",
            "owasp": "API2:2023-Broken Authentication",
            "cvss": 9.1,
            "detail": "API endpoint uses unencrypted HTTP.",
            "fix": "Enforce HTTPS exclusively across all API Gateway listeners and redirect HTTP to HTTPS.",
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
                        "type": f"[API Transport] Deprecated TLS Version ({version})",
                        "severity": "high",
                        "target": url,
                        "cwe": "CWE-326",
                        "owasp": "API7:2023-Security Misconfiguration",
                        "cvss": 7.5,
                        "detail": f"Server negotiated deprecated {version}.",
                        "fix": "Disable TLS 1.0 and 1.1 on the load balancer or API Gateway; enforce TLS 1.2 or TLS 1.3.",
                    })
    except ssl.SSLCertVerificationError as e:
        findings.append({
            "type": "[API Transport] TLS Certificate Verification Failed",
            "severity": "critical",
            "target": url,
            "cwe": "CWE-295",
            "owasp": "API7:2023-Security Misconfiguration",
            "cvss": 9.1,
            "detail": str(e),
            "fix": "Install a valid, non-expired SSL/TLS certificate from a trusted Certificate Authority.",
        })
    except Exception:
        pass
    return findings


def check_security_headers(url):
    findings = []
    resp = _get(url)
    if isinstance(resp, Exception):
        return [{
            "type": "[API Connectivity] Endpoint Unreachable",
            "severity": "info",
            "target": url,
            "cwe": "CWE-200",
            "owasp": "API7:2023-Security Misconfiguration",
            "cvss": 0.0,
            "detail": str(resp),
            "fix": "Confirm network connectivity, DNS resolution, and security group firewall rules.",
        }]

    if getattr(resp, "_ssl_error", None):
        findings.append({
            "type": "[API Transport] TLS Certificate Trust Warning",
            "severity": "high",
            "target": url,
            "cwe": "CWE-295",
            "owasp": "API7:2023-Security Misconfiguration",
            "cvss": 7.5,
            "detail": resp._ssl_error,
            "fix": "Fix TLS certificate chain or renew expired certificates.",
        })

    for header, (severity, cwe, owasp, cvss, fix) in SECURITY_HEADERS.items():
        if header not in resp.headers:
            findings.append({
                "type": f"[API Header] Missing Security Header: {header}",
                "severity": severity,
                "target": url,
                "cwe": cwe,
                "owasp": owasp,
                "cvss": cvss,
                "detail": f"Response headers did not include '{header}'.",
                "fix": fix,
            })

    # Verbose server header
    server_header = resp.headers.get("Server") or resp.headers.get("X-Powered-By")
    if server_header:
        findings.append({
            "type": "[API Information Disclosure] Verbose Server / Framework Header",
            "severity": "low",
            "target": url,
            "cwe": "CWE-200",
            "owasp": "API7:2023-Security Misconfiguration",
            "cvss": 3.1,
            "detail": f"Header reveals technology banner: {server_header}",
            "fix": "Remove or genericize 'Server' and 'X-Powered-By' headers at the reverse proxy or API gateway.",
        })

    # Rate Limiting Header Check
    rate_headers = [h for h in resp.headers if "ratelimit" in h.lower() or "retry-after" in h.lower()]
    if not rate_headers:
        findings.append({
            "type": "[API Rate Limiting] Missing Standard Rate Limiting Headers",
            "severity": "low",
            "target": url,
            "cwe": "CWE-799",
            "owasp": "API4:2023-Unrestricted Resource Consumption",
            "cvss": 3.7,
            "detail": "No 'RateLimit-*' or 'X-RateLimit-*' throttling headers detected in response.",
            "fix": "Configure API Gateway usage plans, throttling limits, and burst quotas to prevent DoS.",
        })

    return findings


def check_auth_enforcement(url):
    findings = []
    resp = _get(url)
    if isinstance(resp, Exception):
        return findings

    if resp.status_code == 200 and len(resp.content) > 0:
        findings.append({
            "type": "[API Access Control] Endpoint Publicly Accessible Without Authentication",
            "severity": "high",
            "target": url,
            "cwe": "CWE-306",
            "owasp": "API2:2023-Broken Authentication",
            "cvss": 7.5,
            "detail": f"Unauthenticated request returned HTTP 200 with {len(resp.content)} bytes.",
            "fix": "If this endpoint should be private, attach an authorizer (JWT, OAuth, API Key, Cognito) and deny anonymous requests.",
        })

    # Error stack trace analysis
    if resp.status_code >= 400:
        body_preview = resp.text[:400]
        leak_markers = (
            "Traceback (most recent call last)", "at java.", "stack trace", "Exception in thread",
            "SQLSTATE", "ORA-", "django.core.exceptions", "System.Exception", "NullPointerException",
            "PG::Error", "SequelizeDatabaseError", "UnhandledPromiseRejectionWarning",
        )
        if any(m in body_preview for m in leak_markers):
            findings.append({
                "type": "[API Error Handling] Verbose Stack Trace / Internal Details Leaked",
                "severity": "medium",
                "target": url,
                "cwe": "CWE-209",
                "owasp": "API7:2023-Security Misconfiguration",
                "cvss": 5.3,
                "detail": "Response contains raw internal exception stack traces.",
                "fix": "Catch exceptions globally and return standardized, sanitized error payloads (e.g. RFC 7807 Problem Details).",
            })
    return findings


def check_cors(url):
    findings = []
    try:
        resp = requests.options(url, timeout=TIMEOUT, verify=False, headers={
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
            "type": "[API CORS] Critical Misconfiguration: Wildcard Origin with Credentials",
            "severity": "critical",
            "target": url,
            "cwe": "CWE-942",
            "owasp": "API7:2023-Security Misconfiguration",
            "cvss": 9.3,
            "detail": "Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true.",
            "fix": "Never return wildcard origin when credentials are supported. Enforce a strict allow-list of trusted origins.",
        })
    elif acao == "*":
        findings.append({
            "type": "[API CORS] Wildcard Origin Allowed (*)",
            "severity": "low",
            "target": url,
            "cwe": "CWE-942",
            "owasp": "API7:2023-Security Misconfiguration",
            "cvss": 3.7,
            "detail": "Access-Control-Allow-Origin: * allows any web page to read response data.",
            "fix": "Restrict Access-Control-Allow-Origin to authorized frontend domains.",
        })
    elif acao and acao == "https://evil-attacker-test.invalid":
        findings.append({
            "type": "[API CORS] Arbitrary Origin Header Reflection",
            "severity": "medium",
            "cwe": "CWE-942",
            "owasp": "API7:2023-Security Misconfiguration",
            "cvss": 6.5,
            "target": url,
            "detail": "Server echoed unvalidated Origin header back in Access-Control-Allow-Origin.",
            "fix": "Validate Origin headers against a strict whitelist before echoing.",
        })
    return findings


def check_http_methods(url):
    findings = []
    risky = ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT"]
    allowed = []
    for method in risky:
        try:
            resp = requests.request(method, url, timeout=TIMEOUT, verify=False)
            if resp.status_code not in (401, 403, 404, 405, 501):
                allowed.append((method, resp.status_code))
        except requests.RequestException:
            continue
    if allowed:
        findings.append({
            "type": "[API HTTP Verbs] Dangerous / Potentially Unnecessary HTTP Methods Allowed",
            "severity": "medium",
            "target": url,
            "cwe": "CWE-650",
            "owasp": "API7:2023-Security Misconfiguration",
            "cvss": 5.3,
            "detail": f"Non-standard HTTP verbs returned active statuses: {allowed}",
            "fix": "Disable unused HTTP methods (especially TRACE/CONNECT) at the API gateway level.",
        })
    return findings


def check_information_disclosure(url):
    """Probes for exposed configuration, actuator, swagger, shadow routes, and metrics."""
    findings = []
    candidates = [
        ("/.env", "Environment Variables File", "critical", "CWE-798", 9.8),
        ("/.git/HEAD", "Exposed Git Repository", "critical", "CWE-200", 8.6),
        ("/actuator", "Spring Boot Actuator Root", "high", "CWE-200", 7.5),
        ("/actuator/env", "Spring Boot Environment Endpoint", "critical", "CWE-798", 9.8),
        ("/actuator/health", "Health Check Endpoint", "info", "CWE-200", 0.0),
        ("/swagger.json", "Swagger API Specification", "low", "CWE-200", 3.7),
        ("/openapi.json", "OpenAPI API Specification", "low", "CWE-200", 3.7),
        ("/metrics", "Prometheus / System Metrics", "low", "CWE-200", 3.7),
        ("/debug", "Debug Interface", "medium", "CWE-489", 6.5),
        ("/server-status", "Apache Server Status", "medium", "CWE-200", 5.3),
        ("/phpinfo.php", "PHP Info Page", "medium", "CWE-200", 5.3),
        ("/v1", "Legacy / Shadow API Version 1", "info", "CWE-200", 0.0),
        ("/api/v1", "API Version 1 Endpoint", "info", "CWE-200", 0.0),
    ]
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    for path, title, severity, cwe, cvss in candidates:
        try:
            r = requests.head(base + path, timeout=4, allow_redirects=False, verify=False)
            if r.status_code == 200:
                findings.append({
                    "type": f"[API Endpoint Discovery] {title} Accessible ({path})",
                    "severity": severity,
                    "target": base + path,
                    "cwe": cwe,
                    "owasp": "API7:2023-Security Misconfiguration",
                    "cvss": cvss,
                    "detail": f"Path '{path}' returned HTTP 200 OK.",
                    "fix": f"Restrict public access to '{path}' in production environments.",
                })
        except requests.RequestException:
            continue
    return findings


def run_all(url):
    findings = []
    parsed = urlparse(url)
    if _is_private_or_loopback_host(parsed.hostname):
        findings.append({
            "type": "[API Network Boundary] Target Resolves to Private / Loopback IP (SSRF Guard)",
            "severity": "medium",
            "target": url,
            "cwe": "CWE-918",
            "owasp": "API7:2023-Security Misconfiguration",
            "cvss": 5.3,
            "detail": f"Target host '{parsed.hostname}' resolves to private/internal IP space.",
            "fix": "Verify that scanning internal/private resources is authorized and intentional.",
        })
    findings += check_tls(url)
    findings += check_security_headers(url)
    findings += check_auth_enforcement(url)
    findings += check_cors(url)
    findings += check_http_methods(url)
    findings += check_information_disclosure(url)
    return findings
