"""
Website URL Loophole & Security Auditor for Yemanode.
Performs comprehensive ethical security auditing against live websites and web applications.
Audits: TLS/SSL, Security Headers, Cookies, CORS, HTTP Methods, Exposed Sensitive Files,
Admin Portals, robots.txt, security.txt, DOM/HTML Security, Leaked Secrets, Open Redirects,
Error Stack Traces, and synthesizes Vulnerability Attack Chains with actionable fix guides.
"""
import concurrent.futures
import datetime
import html
import ipaddress
import json
import os
import re
import socket
import ssl
from urllib.parse import parse_qs, urljoin, urlparse

import requests

from .. import report

# Request configuration
DEFAULT_TIMEOUT = 8
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Yemanode/2.0"

# Security Headers Specification & Remediation Mapping
SECURITY_HEADERS_SPEC = {
    "Strict-Transport-Security": {
        "severity": "high",
        "cwe": "CWE-319",
        "owasp": "A02:2021-Cryptographic Failures",
        "cvss": 7.5,
        "title": "Missing HTTP Strict Transport Security (HSTS) Header",
        "desc": "The server does not enforce HTTPS via HSTS. Browsers may downgrade connections to unencrypted HTTP, exposing users to Man-in-the-Middle (MitM) and SSL-stripping attacks.",
        "fix": "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` in production web server configuration.",
        "config_nginx": "add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload' always;",
        "config_apache": "Header always set Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload'",
        "config_express": "app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));",
    },
    "Content-Security-Policy": {
        "severity": "high",
        "cwe": "CWE-79",
        "owasp": "A03:2021-Injection",
        "cvss": 7.8,
        "title": "Missing Content Security Policy (CSP)",
        "desc": "No Content-Security-Policy header is configured. Without CSP, the application is vulnerable to Cross-Site Scripting (XSS), data exfiltration, clickjacking, and malicious script injection.",
        "fix": "Define a restrictive Content-Security-Policy that limits script sources, disables unsafe-inline/eval, and restricts object-src and frame-ancestors.",
        "config_nginx": "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';\" always;",
        "config_apache": "Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';\"",
        "config_express": "app.use(helmet.contentSecurityPolicy({ directives: { defaultSrc: [\"'self'\"], scriptSrc: [\"'self'\"], objectSrc: [\"'none'\"] } }));",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "cwe": "CWE-1021",
        "owasp": "A05:2021-Security Misconfiguration",
        "cvss": 6.1,
        "title": "Missing X-Frame-Options (Clickjacking Risk)",
        "desc": "The application does not set X-Frame-Options or frame-ancestors. Attackers can embed your site in a malicious <iframe> to trick authenticated users into executing unintended clicks (Clickjacking / UI Redressing).",
        "fix": "Set `X-Frame-Options: DENY` or `X-Frame-Options: SAMEORIGIN`.",
        "config_nginx": "add_header X-Frame-Options 'DENY' always;",
        "config_apache": "Header always set X-Frame-Options 'DENY'",
        "config_express": "app.use(helmet.frameguard({ action: 'deny' }));",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "cwe": "CWE-693",
        "owasp": "A05:2021-Security Misconfiguration",
        "cvss": 4.3,
        "title": "Missing X-Content-Type-Options: nosniff",
        "desc": "The server does not prevent MIME-type sniffing. Browsers may execute uploaded user content (such as images containing HTML/JS) as executable scripts (MIME confusion attack).",
        "fix": "Add `X-Content-Type-Options: nosniff` header across all responses.",
        "config_nginx": "add_header X-Content-Type-Options 'nosniff' always;",
        "config_apache": "Header always set X-Content-Type-Options 'nosniff'",
        "config_express": "app.use(helmet.noSniff());",
    },
    "Referrer-Policy": {
        "severity": "low",
        "cwe": "CWE-200",
        "owasp": "A01:2021-Broken Access Control",
        "cvss": 3.7,
        "title": "Missing or Insecure Referrer-Policy",
        "desc": "Without a restrictive Referrer-Policy, full URLs containing sensitive tokens, user IDs, or query parameters may be leaked in the Referer header to external third-party domains.",
        "fix": "Set `Referrer-Policy: strict-origin-when-cross-origin` or `no-referrer`.",
        "config_nginx": "add_header Referrer-Policy 'strict-origin-when-cross-origin' always;",
        "config_apache": "Header always set Referrer-Policy 'strict-origin-when-cross-origin'",
        "config_express": "app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));",
    },
    "Permissions-Policy": {
        "severity": "low",
        "cwe": "CWE-693",
        "owasp": "A05:2021-Security Misconfiguration",
        "cvss": 3.1,
        "title": "Missing Permissions-Policy Header",
        "desc": "The application does not restrict access to browser hardware APIs (camera, microphone, geolocation, payment). Embedded third-party iframes or scripts could access sensitive device sensors.",
        "fix": "Set `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()`.",
        "config_nginx": "add_header Permissions-Policy 'camera=(), microphone=(), geolocation=(), payment=()' always;",
        "config_apache": "Header always set Permissions-Policy 'camera=(), microphone=(), geolocation=(), payment=()'",
        "config_express": "app.use((req, res, next) => { res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()'); next(); });",
    },
    "Cross-Origin-Opener-Policy": {
        "severity": "low",
        "cwe": "CWE-693",
        "owasp": "A05:2021-Security Misconfiguration",
        "cvss": 3.1,
        "title": "Missing Cross-Origin-Opener-Policy (COOP)",
        "desc": "Without COOP, malicious top-level documents can open this site in a popup and retain reference via window.opener, enabling XS-Leaks and side-channel cross-origin attacks (Spectre).",
        "fix": "Add `Cross-Origin-Opener-Policy: same-origin` to isolate your browsing context group.",
        "config_nginx": "add_header Cross-Origin-Opener-Policy 'same-origin' always;",
        "config_apache": "Header always set Cross-Origin-Opener-Policy 'same-origin'",
        "config_express": "app.use(helmet.crossOriginOpenerPolicy({ policy: 'same-origin' }));",
    },
}

# Sensitive reconnaissance paths
SENSITIVE_PROBE_PATHS = [
    # Environment & Secrets
    ("/.env", "Environment Variables File", "critical", "CWE-798", 9.8, ["DB_PASSWORD", "SECRET_KEY", "AWS_ACCESS_KEY", "API_KEY", "DATABASE_URL", "APP_ENV"]),
    ("/.env.local", "Local Environment File", "critical", "CWE-798", 9.8, ["SECRET", "PASSWORD", "KEY", "TOKEN"]),
    ("/.env.production", "Production Environment File", "critical", "CWE-798", 9.8, ["SECRET", "PASSWORD", "KEY", "TOKEN"]),
    ("/.env.staging", "Staging Environment File", "critical", "CWE-798", 9.8, ["SECRET", "PASSWORD", "KEY", "TOKEN"]),
    ("/.env.backup", "Backup Environment File", "critical", "CWE-798", 9.8, ["SECRET", "PASSWORD", "KEY", "TOKEN"]),
    
    # Version Control Exposure
    ("/.git/HEAD", "Exposed Git Repository (HEAD pointer)", "critical", "CWE-200", 8.9, ["ref: refs/heads/", "ref: refs/"]),
    ("/.git/config", "Exposed Git Config File", "critical", "CWE-200", 8.6, ["[core]", "[remote \"origin\"]"]),
    ("/.gitignore", "Exposed .gitignore File", "low", "CWE-200", 3.7, ["node_modules", ".env", "*.log"]),
    ("/.svn/entries", "Exposed SVN Repository Entries", "high", "CWE-200", 7.5, ["svn:", "dir"]),
    
    # Config & Server Files
    ("/web.config", "Microsoft IIS Configuration File", "high", "CWE-200", 7.5, ["<configuration>", "<system.webServer>"]),
    ("/.htaccess", "Apache .htaccess Configuration", "high", "CWE-200", 7.5, ["RewriteEngine", "Deny from", "AuthType"]),
    ("/.htpasswd", "Apache .htpasswd Password Hashes", "critical", "CWE-256", 9.1, [":$apr1$", ":$2y$", ":{SHA}"]),
    ("/Dockerfile", "Source Dockerfile", "medium", "CWE-200", 5.3, ["FROM ", "WORKDIR", "ENTRYPOINT"]),
    ("/docker-compose.yml", "Docker Compose Infrastructure Spec", "high", "CWE-200", 7.5, ["version:", "services:", "image:"]),
    
    # Database & Backup Archives
    ("/backup.zip", "Full System Backup Archive", "critical", "CWE-200", 9.8, ["PK"]),
    ("/database.sql", "Raw SQL Database Dump", "critical", "CWE-200", 9.8, ["INSERT INTO", "CREATE TABLE", "DROP TABLE", "-- MySQL dump", "pg_dump"]),
    ("/db.sql", "Database SQL File", "critical", "CWE-200", 9.8, ["INSERT INTO", "CREATE TABLE", "-- MySQL dump"]),
    ("/dump.sql", "Database Dump File", "critical", "CWE-200", 9.8, ["INSERT INTO", "CREATE TABLE"]),
    ("/config.php.bak", "Backup PHP Config File", "critical", "CWE-798", 9.8, ["<?php", "$db", "$password"]),
    ("/index.php.bak", "Backup Source File", "medium", "CWE-200", 6.5, ["<?php"]),
    ("/.DS_Store", "macOS Directory Metadata File", "low", "CWE-200", 3.7, ["Bud1", "\x00\x00\x00\x01Bud1"]),
    
    # Diagnostics & Internal Debug Portals
    ("/phpinfo.php", "PHP Info Diagnostic Page", "high", "CWE-200", 7.5, ["PHP Version", "Configuration File (php.ini)", "Server API"]),
    ("/info.php", "PHP Diagnostic Page", "high", "CWE-200", 7.5, ["PHP Version", "phpinfo()"]),
    ("/actuator", "Spring Boot Actuator Root", "high", "CWE-200", 7.5, ["_links", "self", "health"]),
    ("/actuator/env", "Spring Boot Actuator Environment & Credentials", "critical", "CWE-798", 9.8, ["activeProfiles", "propertySources"]),
    ("/actuator/health", "Spring Boot Actuator Health", "info", "CWE-200", 0.0, ["status", "UP", "DOWN"]),
    ("/actuator/beans", "Spring Boot Actuator Beans", "medium", "CWE-200", 5.3, ["beans", "context"]),
    ("/actuator/httptrace", "Spring Boot HTTP Request Trace History", "critical", "CWE-200", 9.1, ["traces", "request", "headers"]),
    ("/metrics", "Prometheus / System Metrics Endpoint", "low", "CWE-200", 3.7, ["# HELP", "# TYPE", "process_cpu_seconds"]),
    ("/debug", "Debug Console / Interface", "medium", "CWE-489", 6.5, ["debug", "console", "terminal"]),
    ("/_debugbar", "Laravel Debugbar", "high", "CWE-489", 7.5, ["PhpDebugBar", "debugbar"]),
    ("/server-status", "Apache Server Status Page", "medium", "CWE-200", 5.3, ["Apache Server Status", "Server Version"]),
    
    # API Specifications & GraphQL
    ("/swagger.json", "Exposed Swagger API Specification", "low", "CWE-200", 3.7, ["swagger", "paths", "info"]),
    ("/openapi.json", "Exposed OpenAPI Specification", "low", "CWE-200", 3.7, ["openapi", "paths", "components"]),
    ("/api-docs", "API Documentation Interface", "low", "CWE-200", 3.7, ["api-docs", "swagger", "redoc"]),
    ("/graphql", "GraphQL Endpoint (Introspection Risk)", "low", "CWE-200", 3.7, ["GraphQL", "errors", "query"]),
    
    # Administrative & Management Panels
    ("/admin", "Administrative Portal Interface", "medium", "CWE-284", 5.3, ["login", "admin", "dashboard", "password"]),
    ("/administrator", "Joomla / CMS Administrator Panel", "medium", "CWE-284", 5.3, ["login", "administrator", "joomla"]),
    ("/wp-admin/", "WordPress Admin Dashboard", "medium", "CWE-284", 5.3, ["wp-login.php", "WordPress"]),
    ("/wp-login.php", "WordPress Login Portal", "medium", "CWE-284", 5.3, ["user_login", "user_pass", "wp-submit"]),
    ("/cpanel", "cPanel Web Hosting Manager", "medium", "CWE-284", 5.3, ["cPanel", "login"]),
    ("/phpmyadmin/", "phpMyAdmin Database Management Panel", "high", "CWE-284", 7.5, ["phpMyAdmin", "pma_username"]),
    ("/manager/html", "Apache Tomcat Web Application Manager", "high", "CWE-284", 7.5, ["Tomcat Web Application Manager"]),
]

# Common secret regex patterns for HTML/JS scanning
SECRET_PATTERNS = [
    ("AWS Access Key ID in Client Source", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "critical", "CWE-798", 9.8, "Revoke the exposed AWS key in IAM console immediately and rotate all credentials."),
    ("Google API Key in Client Source", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "medium", "CWE-798", 5.3, "Restrict this Google API key in Google Cloud Console with HTTP referrer restrictions and API restrictions."),
    ("Stripe Secret Key in Client Source", re.compile(r"\bsk_(live|test)_[0-9a-zA-Z]{24,}\b"), "critical", "CWE-798", 9.8, "Immediately roll your Stripe secret key in the Stripe Dashboard. Never ship secret keys in frontend code."),
    ("Stripe Publishable Key in Client Source", re.compile(r"\bpk_(live|test)_[0-9a-zA-Z]{24,}\b"), "info", "CWE-200", 0.0, "Publishable Stripe key detected. Ensure secret keys are not exposed."),
    ("Firebase API / Database Config in Client Source", re.compile(r"firebaseConfig\s*=\s*\{[^}]*apiKey\s*:\s*['\"][^'\"]+['\"]"), "medium", "CWE-200", 5.3, "Ensure Firebase Security Rules (Firestore / Realtime DB / Storage) strictly enforce user authentication and authorization."),
    ("Generic Private / Secret Token in Client Source", re.compile(r"(?i)(api[_-]?secret|private[_-]?key|client[_-]?secret)\s*[:=]\s*['\"][A-Za-z0-9\-_/+=]{16,}['\"]"), "high", "CWE-798", 7.8, "Remove hardcoded secret tokens from client-side HTML/JavaScript. Keep secrets on the backend server."),
    ("Hardcoded JWT Token in Client Source", re.compile(r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b"), "medium", "CWE-798", 5.5, "Avoid baking static JWT tokens into frontend scripts. Issue tokens dynamically upon login."),
]


def normalize_target_url(raw_url: str) -> str:
    """Normalizes raw user input into a valid HTTP/HTTPS URL."""
    url = raw_url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def resolve_target_host(hostname: str) -> dict:
    """Resolves DNS and IP addresses for target host."""
    res = {
        "hostname": hostname,
        "ipv4": [],
        "ipv6": [],
        "is_private": False,
        "is_loopback": False,
    }
    if not hostname:
        return res

    try:
        addrs = socket.getaddrinfo(hostname, None)
        for addr in addrs:
            ip_str = addr[4][0]
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.version == 4 and ip_str not in res["ipv4"]:
                res["ipv4"].append(ip_str)
            elif ip_obj.version == 6 and ip_str not in res["ipv6"]:
                res["ipv6"].append(ip_str)

            if ip_obj.is_private:
                res["is_private"] = True
            if ip_obj.is_loopback:
                res["is_loopback"] = True
    except Exception:
        pass
    return res


def detect_waf_and_technologies(headers: dict, body: str) -> dict:
    """Fingerprints WAFs, web servers, and application frameworks."""
    tech = {
        "waf": None,
        "server": headers.get("Server"),
        "powered_by": headers.get("X-Powered-By"),
        "frameworks": [],
    }

    # WAF signatures
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
    if "cf-ray" in headers_lower or "cf-cache-status" in headers_lower or "cloudflare" in headers_lower.get("server", ""):
        tech["waf"] = "Cloudflare WAF / CDN"
    elif "x-amz-cf-id" in headers_lower or "x-amz-cf-pop" in headers_lower or "cloudfront" in headers_lower.get("server", ""):
        tech["waf"] = "AWS CloudFront / AWS WAF"
    elif "akamai" in headers_lower.get("server", "") or "x-akamai-transformed" in headers_lower:
        tech["waf"] = "Akamai Kona WAF"
    elif "x-sucuri-id" in headers_lower or "x-sucuri-cache" in headers_lower:
        tech["waf"] = "Sucuri CloudProxy WAF"
    elif "x-cdn" in headers_lower and "imperva" in headers_lower.get("x-cdn", "") or "incap_ses" in str(headers_lower):
        tech["waf"] = "Imperva Incapsula WAF"
    elif "fastly" in headers_lower.get("server", "") or "x-fastly-request-id" in headers_lower:
        tech["waf"] = "Fastly WAF / CDN"

    # Framework & CMS fingerprinting
    body_sample = body[:10000].lower() if body else ""
    if "wp-content" in body_sample or "wp-includes" in body_sample:
        tech["frameworks"].append("WordPress CMS")
    if "next.js" in body_sample or "/_next/" in body_sample:
        tech["frameworks"].append("Next.js (React)")
    if "nuxt" in body_sample or "/_nuxt/" in body_sample:
        tech["frameworks"].append("Nuxt.js (Vue)")
    if "laravel_session" in str(headers_lower):
        tech["frameworks"].append("Laravel (PHP)")
    if "csrftoken" in str(headers_lower) or "django" in body_sample:
        tech["frameworks"].append("Django (Python)")
    if "express" in str(headers_lower.get("x-powered-by", "")):
        tech["frameworks"].append("Express.js (Node.js)")
    if "asp.net" in str(headers_lower.get("x-powered-by", "")):
        tech["frameworks"].append("ASP.NET (Microsoft)")
    if "drupal" in body_sample:
        tech["frameworks"].append("Drupal CMS")
    if "joomla" in body_sample:
        tech["frameworks"].append("Joomla CMS")

    return tech


def audit_tls_and_transport(url: str, timeout: int = DEFAULT_TIMEOUT) -> tuple:
    """Audits TLS version, certificate validation, HTTPS enforcement, and HSTS."""
    findings = []
    parsed = urlparse(url)
    tls_info = {"scheme": parsed.scheme, "tls_version": None, "cert_valid": False, "cert_expiry": None, "cert_issuer": None}

    # 1. Plain HTTP check
    if parsed.scheme != "https":
        findings.append({
            "type": "[Loophole: Transport] Insecure Plain HTTP Scheme in Use",
            "category": "Transport & Cryptography",
            "severity": "critical",
            "target": url,
            "cwe": "CWE-319",
            "owasp": "A02:2021-Cryptographic Failures",
            "cvss": 9.1,
            "evidence": f"URL uses plain unencrypted HTTP protocol: {url}",
            "detail": "Website transmits traffic over unencrypted cleartext HTTP. Passwords, session cookies, and personal data can be intercepted by adversaries on the network.",
            "impact": "Man-in-the-Middle (MitM) eavesdropping, session hijacking, and DNS/packet spoofing.",
            "fix": "Obtain an SSL/TLS certificate (e.g. Let's Encrypt / Cloudflare) and enforce HTTPS for all incoming requests.",
            "code_remediation": "# Nginx configuration:\nserver {\n    listen 80 default_server;\n    server_name _;\n    return 301 https://$host$request_uri;\n}",
        })
        return findings, tls_info

    # 2. Check HTTP to HTTPS redirect behavior
    http_url = f"http://{parsed.netloc}{parsed.path}"
    try:
        r_http = requests.get(http_url, timeout=timeout, allow_redirects=False, headers={"User-Agent": DEFAULT_USER_AGENT})
        if r_http.status_code not in (301, 302, 307, 308):
            findings.append({
                "type": "[Loophole: Transport] HTTP Traffic Does Not Redirect to HTTPS",
                "category": "Transport & Cryptography",
                "severity": "high",
                "target": http_url,
                "cwe": "CWE-319",
                "owasp": "A02:2021-Cryptographic Failures",
                "cvss": 7.5,
                "evidence": f"HTTP request to '{http_url}' returned HTTP {r_http.status_code} instead of 301 Redirect.",
                "detail": "The HTTP port is open and serves content over cleartext without automatically redirecting visitors to HTTPS.",
                "impact": "Users typing the domain without 'https://' remain on unencrypted channels vulnerable to packet inspection.",
                "fix": "Configure permanent 301 redirects from HTTP port 80 to HTTPS port 443.",
                "code_remediation": "# Nginx redirect block:\nserver {\n    listen 80;\n    server_name example.com www.example.com;\n    return 301 https://$host$request_uri;\n}",
            })
        elif r_http.status_code in (302, 307):
            findings.append({
                "type": "[Loophole: Transport] Temporary Redirect (302/307) Used for HTTPS Enforcement",
                "category": "Transport & Cryptography",
                "severity": "low",
                "target": http_url,
                "cwe": "CWE-319",
                "owasp": "A05:2021-Security Misconfiguration",
                "cvss": 3.7,
                "evidence": f"HTTP endpoint returned HTTP {r_http.status_code} redirect instead of 301 Permanent.",
                "detail": "Temporary redirects are not cached by browsers and search engines, resulting in repeated cleartext round trips.",
                "fix": "Switch HTTP to HTTPS redirection to HTTP 301 (Permanent Redirect).",
                "code_remediation": "return 301 https://$host$request_uri;",
            })
    except Exception:
        pass

    # 3. Direct SSL Socket Handshake & Certificate Verification
    host = parsed.hostname
    port = parsed.port or 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                version = ssock.version()
                tls_info["tls_version"] = version
                tls_info["cert_valid"] = True
                cert = ssock.getpeercert()

                # Protocol deprecation checks
                if version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    findings.append({
                        "type": f"[Loophole: TLS] Deprecated Protocol Version Supported ({version})",
                        "category": "Transport & Cryptography",
                        "severity": "high",
                        "cwe": "CWE-326",
                        "owasp": "A02:2021-Cryptographic Failures",
                        "cvss": 7.5,
                        "target": url,
                        "evidence": f"Server negotiated legacy protocol version: {version}",
                        "detail": f"TLS 1.0 and 1.1 contain cryptographic weaknesses (POODLE, BEAST) and are deprecated by NIST, PCI-DSS, and major browsers.",
                        "impact": "Adversaries can exploit cryptographic protocol flaws to decrypt encrypted communication.",
                        "fix": "Disable TLS 1.0/1.1 and legacy SSL versions. Enforce TLS 1.2 and TLS 1.3 exclusively.",
                        "code_remediation": "# Nginx:\nssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers HIGH:!aNULL:!MD5;",
                    })

                # Certificate expiration check
                if cert and "notAfter" in cert:
                    expire_date_str = cert["notAfter"]
                    try:
                        expire_dt = datetime.datetime.strptime(expire_date_str, "%b %d %H:%M:%S %Y %Z")
                        tls_info["cert_expiry"] = expire_dt.strftime("%Y-%m-%d")
                        now = datetime.datetime.utcnow()
                        days_left = (expire_dt - now).days
                        if days_left < 0:
                            findings.append({
                                "type": "[Loophole: TLS] SSL/TLS Certificate Has Expired",
                                "category": "Transport & Cryptography",
                                "severity": "critical",
                                "cwe": "CWE-298",
                                "owasp": "A02:2021-Cryptographic Failures",
                                "cvss": 9.1,
                                "target": url,
                                "evidence": f"Certificate expired on {expire_dt.strftime('%Y-%m-%d')} ({abs(days_left)} days ago)",
                                "detail": "The server presents an expired SSL/TLS certificate, triggering browser security warning screens.",
                                "impact": "Users will be blocked from accessing the site by modern browser warnings, eroding trust.",
                                "fix": "Renew and install an active SSL/TLS certificate immediately (e.g. via certbot renew).",
                                "code_remediation": "sudo certbot renew --force-renewal",
                            })
                        elif days_left < 14:
                            findings.append({
                                "type": f"[Loophole: TLS] SSL/TLS Certificate Expiring Soon ({days_left} Days Left)",
                                "category": "Transport & Cryptography",
                                "severity": "medium",
                                "cwe": "CWE-298",
                                "owasp": "A02:2021-Cryptographic Failures",
                                "cvss": 5.3,
                                "target": url,
                                "evidence": f"Certificate will expire on {expire_dt.strftime('%Y-%m-%d')} in {days_left} day(s)",
                                "detail": "Certificate renewal is imminent. Ensure automated certificate renewal (ACME / Certbot) is active.",
                                "impact": "If left unrenewed, the website will become inaccessible within days.",
                                "fix": "Verify ACME cron / certbot timer or trigger manual certificate renewal.",
                                "code_remediation": "sudo certbot renew --dry-run",
                            })
                    except Exception:
                        pass

                # Certificate Issuer
                if cert and "issuer" in cert:
                    issuer_dict = dict(x[0] for x in cert["issuer"])
                    tls_info["cert_issuer"] = issuer_dict.get("organizationName") or issuer_dict.get("commonName")

    except ssl.SSLCertVerificationError as e:
        tls_info["cert_valid"] = False
        findings.append({
            "type": "[Loophole: TLS] Invalid or Untrusted SSL/TLS Certificate",
            "category": "Transport & Cryptography",
            "severity": "critical",
            "cwe": "CWE-295",
            "owasp": "A02:2021-Cryptographic Failures",
            "cvss": 9.1,
            "target": url,
            "evidence": f"Certificate validation error: {str(e)}",
            "detail": "Certificate is self-signed, untrusted, or has a mismatched hostname/Subject Alternative Name.",
            "impact": "Browser security warnings, complete breakdown of transport security trust.",
            "fix": "Install a valid certificate issued by a recognized public Certificate Authority (Let's Encrypt, DigiCert, AWS ACM).",
            "code_remediation": "sudo certbot certonly --standalone -d yourdomain.com",
        })
    except Exception:
        tls_info["cert_valid"] = False

    return findings, tls_info


def audit_security_headers(headers: dict, url: str) -> list:
    """Evaluates HTTP security response headers and identifies missing or weak defenses."""
    findings = []
    headers_lower = {k.lower(): (k, v) for k, v in headers.items()}

    # 1. Standard Security Headers presence & configuration
    for h_name, spec in SECURITY_HEADERS_SPEC.items():
        key = h_name.lower()
        if key not in headers_lower:
            findings.append({
                "type": f"[Loophole: Header] {spec['title']}",
                "category": "Security Headers & Browser Protections",
                "severity": spec["severity"],
                "cwe": spec["cwe"],
                "owasp": spec["owasp"],
                "cvss": spec["cvss"],
                "target": url,
                "evidence": f"Response header '{h_name}' is missing.",
                "detail": spec["desc"],
                "impact": f"Missing browser defense mechanism ({h_name}).",
                "fix": spec["fix"],
                "code_remediation": f"# Nginx:\n{spec['config_nginx']}\n\n# Apache:\n{spec['config_apache']}\n\n# Express.js (Node):\n{spec['config_express']}",
            })
        else:
            orig_name, val = headers_lower[key]
            val_lower = val.lower()

            # Inspect HSTS Quality
            if key == "strict-transport-security":
                if "max-age" in val_lower:
                    match = re.search(r"max-age=(\d+)", val_lower)
                    if match:
                        max_age = int(match.group(1))
                        if max_age < 31536000:  # less than 1 year
                            findings.append({
                                "type": "[Loophole: Header] HSTS max-age Duration Too Short",
                                "category": "Security Headers & Browser Protections",
                                "severity": "medium",
                                "cwe": "CWE-319",
                                "owasp": "A02:2021-Cryptographic Failures",
                                "cvss": 5.3,
                                "target": url,
                                "evidence": f"Strict-Transport-Security: {val} (max-age is {max_age}s, recommended: 31536000s)",
                                "detail": "HSTS max-age is configured for less than 1 year (31,536,000 seconds).",
                                "impact": "Browser forgets HTTPS enforcement quickly, leaving periodic windows for SSL-stripping.",
                                "fix": "Increase HSTS max-age to at least 31536000 (1 year) and include includeSubDomains and preload.",
                                "code_remediation": "add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload' always;",
                            })
                if "includesubdomains" not in val_lower:
                    findings.append({
                        "type": "[Loophole: Header] HSTS Missing 'includeSubDomains' Directive",
                        "category": "Security Headers & Browser Protections",
                        "severity": "low",
                        "cwe": "CWE-319",
                        "owasp": "A02:2021-Cryptographic Failures",
                        "cvss": 3.7,
                        "target": url,
                        "evidence": f"Strict-Transport-Security: {val}",
                        "detail": "HSTS does not protect subdomains. Attackers could target insecure subdomains on the same parent domain.",
                        "impact": "Subdomains remain vulnerable to cookie injection and cleartext interception.",
                        "fix": "Append `includeSubDomains` to the HSTS header.",
                        "code_remediation": "add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload' always;",
                    })

            # Inspect CSP Quality
            elif key == "content-security-policy":
                if "'unsafe-inline'" in val:
                    findings.append({
                        "type": "[Loophole: CSP] Content Security Policy Allows 'unsafe-inline'",
                        "category": "Security Headers & Browser Protections",
                        "severity": "medium",
                        "cwe": "CWE-79",
                        "owasp": "A03:2021-Injection",
                        "cvss": 6.5,
                        "target": url,
                        "evidence": f"Content-Security-Policy contains 'unsafe-inline'",
                        "detail": "Allowing 'unsafe-inline' scripts negates the primary Cross-Site Scripting (XSS) defense of CSP.",
                        "impact": "Attackers can execute injected inline JavaScript payloads via XSS vectors.",
                        "fix": "Refactor inline scripts into external files or use cryptographic nonces: `script-src 'nonce-{RANDOM}'`.",
                        "code_remediation": "Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-rAnd0m123';",
                    })
                if "'unsafe-eval'" in val:
                    findings.append({
                        "type": "[Loophole: CSP] Content Security Policy Allows 'unsafe-eval'",
                        "category": "Security Headers & Browser Protections",
                        "severity": "medium",
                        "cwe": "CWE-79",
                        "owasp": "A03:2021-Injection",
                        "cvss": 6.1,
                        "target": url,
                        "evidence": f"Content-Security-Policy contains 'unsafe-eval'",
                        "detail": "Allowing 'unsafe-eval' permits dynamic string execution (eval, Function constructor), increasing script injection impact.",
                        "impact": "Attackers can evaluate arbitrary strings as executable code.",
                        "fix": "Remove 'unsafe-eval' from your CSP script-src directives.",
                        "code_remediation": "Content-Security-Policy: default-src 'self'; script-src 'self';",
                    })
                if "frame-ancestors" not in val_lower and "x-frame-options" not in headers_lower:
                    findings.append({
                        "type": "[Loophole: CSP] CSP Missing 'frame-ancestors' Directive (Clickjacking)",
                        "category": "Security Headers & Browser Protections",
                        "severity": "medium",
                        "cwe": "CWE-1021",
                        "owasp": "A05:2021-Security Misconfiguration",
                        "cvss": 5.3,
                        "target": url,
                        "evidence": "CSP lacks frame-ancestors and X-Frame-Options is absent.",
                        "detail": "Without frame-ancestors, attackers can frame this website inside malicious pages.",
                        "impact": "UI Redressing / Clickjacking attacks against authenticated users.",
                        "fix": "Add `frame-ancestors 'none';` or `frame-ancestors 'self';` to Content-Security-Policy.",
                        "code_remediation": "Content-Security-Policy: default-src 'self'; frame-ancestors 'none';",
                    })

    # Check for CSP Report-Only mode without enforced CSP
    if "content-security-policy-report-only" in headers_lower and "content-security-policy" not in headers_lower:
        findings.append({
            "type": "[Loophole: CSP] Content Security Policy Only in Report-Only Mode",
            "category": "Security Headers & Browser Protections",
            "severity": "medium",
            "cwe": "CWE-79",
            "owasp": "A05:2021-Security Misconfiguration",
            "cvss": 5.3,
            "target": url,
            "evidence": "Found Content-Security-Policy-Report-Only without active enforced Content-Security-Policy header.",
            "detail": "Report-Only mode logs violations but does NOT block malicious scripts or objects in the browser.",
            "impact": "Malicious XSS payloads will still execute in victims' browsers.",
            "fix": "Transition policy from `Content-Security-Policy-Report-Only` to enforced `Content-Security-Policy`.",
            "code_remediation": "add_header Content-Security-Policy \"default-src 'self'; script-src 'self';\" always;",
        })

    # 2. Information Disclosure via Technology Banners
    server_header = headers.get("Server")
    if server_header and any(c.isdigit() for c in server_header):
        findings.append({
            "type": "[Loophole: Disclosure] Verbose Server Header Disclosing Exact Version",
            "category": "Information Disclosure",
            "severity": "low",
            "cwe": "CWE-200",
            "owasp": "A05:2021-Security Misconfiguration",
            "cvss": 3.7,
            "target": url,
            "evidence": f"Server: {server_header}",
            "detail": f"The 'Server' header exposes specific web server software and version numbers ({server_header}).",
            "impact": "Assists attackers in mapping known CVEs and targeting version-specific exploits against your server.",
            "fix": "Disable server signature tokens in your web server configuration.",
            "code_remediation": "# Nginx:\nserver_tokens off;\n\n# Apache (httpd.conf):\nServerTokens Prod\nServerSignature Off",
        })

    powered_by = headers.get("X-Powered-By")
    if powered_by:
        findings.append({
            "type": "[Loophole: Disclosure] Leaked X-Powered-By Technology Header",
            "category": "Information Disclosure",
            "severity": "low",
            "cwe": "CWE-200",
            "owasp": "A05:2021-Security Misconfiguration",
            "cvss": 3.1,
            "target": url,
            "evidence": f"X-Powered-By: {powered_by}",
            "detail": f"The 'X-Powered-By' header reveals backend technologies ({powered_by}).",
            "impact": "Provides adversaries with technology stack reconnaissance data.",
            "fix": "Remove or strip 'X-Powered-By' headers in your framework or reverse proxy.",
            "code_remediation": "# Express.js (Node):\napp.disable('x-powered-by');\n\n# PHP (php.ini):\nexpose_php = Off\n\n# Nginx:\nproxy_hide_header X-Powered-By;",
        })

    return findings


def audit_cookie_security(raw_cookies: list, url: str) -> list:
    """Audits Set-Cookie headers for missing HttpOnly, Secure, SameSite, and Cookie Prefixes."""
    findings = []
    if not raw_cookies:
        return findings

    session_names = ("session", "token", "jwt", "auth", "sid", "phpsessid", "jsessionid", "connect.sid", "remember", "user")

    for raw_c in raw_cookies:
        c_parts = [p.strip() for p in raw_c.split(";")]
        if not c_parts:
            continue

        c_name_val = c_parts[0]
        c_name = c_name_val.split("=")[0].strip() if "=" in c_name_val else c_name_val
        flags = [p.lower() for p in c_parts[1:]]

        is_session_like = any(s in c_name.lower() for s in session_names)

        # 1. Missing HttpOnly
        if not any(f.startswith("httponly") for f in flags):
            sev = "high" if is_session_like else "medium"
            cvss = 7.5 if is_session_like else 5.3
            findings.append({
                "type": f"[Loophole: Cookie] Missing HttpOnly Flag on Cookie '{c_name}'",
                "category": "Cookie & Session Security",
                "severity": sev,
                "cwe": "CWE-1004",
                "owasp": "A07:2021-Identification and Authentication Failures",
                "cvss": cvss,
                "target": url,
                "evidence": f"Set-Cookie: {raw_c}",
                "detail": f"The cookie '{c_name}' is accessible to client-side JavaScript via `document.cookie`.",
                "impact": "If an XSS vulnerability exists, attackers can immediately steal session cookies and hijack user accounts.",
                "fix": "Set the `HttpOnly` attribute on the cookie during generation.",
                "code_remediation": "# Express session:\napp.use(session({ cookie: { httpOnly: true, secure: true, sameSite: 'lax' } }));\n\n# PHP:\nsession_set_cookie_params(['httponly' => true, 'secure' => true, 'samesite' => 'Lax']);",
            })

        # 2. Missing Secure Flag
        if not any(f.startswith("secure") for f in flags):
            sev = "high" if is_session_like else "medium"
            cvss = 7.5 if is_session_like else 5.3
            findings.append({
                "type": f"[Loophole: Cookie] Missing Secure Flag on Cookie '{c_name}'",
                "category": "Cookie & Session Security",
                "severity": sev,
                "cwe": "CWE-614",
                "owasp": "A02:2021-Cryptographic Failures",
                "cvss": cvss,
                "target": url,
                "evidence": f"Set-Cookie: {raw_c}",
                "detail": f"The cookie '{c_name}' lacks the `Secure` flag and can be transmitted over unencrypted HTTP.",
                "impact": "Network eavesdroppers can capture cookies transmitted in plain text on insecure Wi-Fi or networks.",
                "fix": "Ensure all cookies are marked `Secure` so browsers only transmit them over HTTPS connections.",
                "code_remediation": "# Set-Cookie header syntax:\nSet-Cookie: session_id=xyz; Secure; HttpOnly; SameSite=Lax",
            })

        # 3. Missing or Weak SameSite Flag
        samesite_flag = [f for f in flags if f.startswith("samesite")]
        if not samesite_flag:
            findings.append({
                "type": f"[Loophole: Cookie] Missing SameSite Attribute on Cookie '{c_name}'",
                "category": "Cookie & Session Security",
                "severity": "medium",
                "cwe": "CWE-1275",
                "owasp": "A01:2021-Broken Access Control",
                "cvss": 6.5,
                "target": url,
                "evidence": f"Set-Cookie: {raw_c}",
                "detail": f"Cookie '{c_name}' does not define `SameSite=Lax` or `SameSite=Strict`.",
                "impact": "Browser will send this cookie with cross-site requests, exposing state-changing endpoints to Cross-Site Request Forgery (CSRF).",
                "fix": "Add `SameSite=Lax` (recommended default) or `SameSite=Strict` to cookie settings.",
                "code_remediation": "Set-Cookie: auth_token=xyz; SameSite=Lax; Secure; HttpOnly",
            })
        elif any("none" in f for f in samesite_flag) and not any(f.startswith("secure") for f in flags):
            findings.append({
                "type": f"[Loophole: Cookie] Insecure SameSite=None without Secure Flag on '{c_name}'",
                "category": "Cookie & Session Security",
                "severity": "high",
                "cwe": "CWE-1275",
                "owasp": "A01:2021-Broken Access Control",
                "cvss": 7.5,
                "target": url,
                "evidence": f"Set-Cookie: {raw_c}",
                "detail": "SameSite=None was specified without the mandatory Secure attribute.",
                "impact": "Modern browsers reject SameSite=None cookies lacking Secure, leading to authentication session breakage.",
                "fix": "Ensure `Secure` is always set whenever `SameSite=None` is required.",
                "code_remediation": "Set-Cookie: cookie_name=xyz; SameSite=None; Secure; HttpOnly",
            })

        # 4. Cookie Prefix recommendations for high-value tokens
        if is_session_like and not (c_name.startswith("__Host-") or c_name.startswith("__Secure-")):
            findings.append({
                "type": f"[Loophole: Cookie] Session Cookie '{c_name}' Does Not Use Hardened Cookie Prefixes",
                "category": "Cookie & Session Security",
                "severity": "low",
                "cwe": "CWE-1275",
                "owasp": "A05:2021-Security Misconfiguration",
                "cvss": 3.7,
                "target": url,
                "evidence": f"Cookie name: '{c_name}'",
                "detail": "Using `__Host-` prefix enforces that the cookie must be Secure, origin-scoped (no subdomains), and have path=/.",
                "impact": "Without cookie prefixes, vulnerable subdomains could overwrite parent domain session cookies (Cookie Tossing attack).",
                "fix": "Rename critical session identifiers to `__Host-session` or `__Secure-session`.",
                "code_remediation": "Set-Cookie: __Host-sessionid=12345; Secure; HttpOnly; SameSite=Strict; Path=/",
            })

    return findings


def audit_cors_configuration(url: str, timeout: int = DEFAULT_TIMEOUT) -> list:
    """Probes Cross-Origin Resource Sharing (CORS) policies for dangerous wildcard or reflective origins."""
    findings = []
    test_origin = "https://evil-hacker-cors-probe.invalid"

    try:
        resp = requests.options(
            url,
            timeout=timeout,
            headers={
                "Origin": test_origin,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "Authorization,Content-Type",
                "User-Agent": DEFAULT_USER_AGENT,
            },
            verify=False,
        )
    except Exception:
        return findings

    acao = resp.headers.get("Access-Control-Allow-Origin")
    acac = resp.headers.get("Access-Control-Allow-Credentials")

    if acao == "*" and acac and acac.lower() == "true":
        findings.append({
            "type": "[Loophole: CORS] Critical Misconfiguration: Wildcard Origin Allowed with Credentials",
            "category": "CORS & Cross-Origin Security",
            "severity": "critical",
            "cwe": "CWE-942",
            "owasp": "A01:2021-Broken Access Control",
            "cvss": 9.3,
            "target": url,
            "evidence": f"Access-Control-Allow-Origin: * | Access-Control-Allow-Credentials: true",
            "detail": "The server allows any origin (`*`) while enabling credentials (`true`).",
            "impact": "Any malicious web page visited by an authenticated user can read private API responses and exfiltrate confidential data.",
            "fix": "Never return wildcard origin with credentials. Maintain a strict whitelist of approved frontend domains.",
            "code_remediation": "# Node.js Express cors:\napp.use(cors({\n  origin: ['https://yourdomain.com', 'https://app.yourdomain.com'],\n  credentials: true\n}));",
        })
    elif acao == test_origin:
        findings.append({
            "type": "[Loophole: CORS] Insecure Arbitrary Origin Header Reflection",
            "category": "CORS & Cross-Origin Security",
            "severity": "high",
            "cwe": "CWE-942",
            "owasp": "A01:2021-Broken Access Control",
            "cvss": 7.5,
            "target": url,
            "evidence": f"Request Origin '{test_origin}' was echoed back in Access-Control-Allow-Origin.",
            "detail": "The application dynamically reflects unvalidated Origin headers directly into Access-Control-Allow-Origin.",
            "impact": "Attacker-controlled websites can issue cross-origin AJAX requests and read private user response data.",
            "fix": "Validate request Origin headers against an explicit, hardcoded allowlist before setting Access-Control-Allow-Origin.",
            "code_remediation": "const allowedOrigins = ['https://trusted.com'];\nif (allowedOrigins.includes(req.headers.origin)) {\n  res.setHeader('Access-Control-Allow-Origin', req.headers.origin);\n}",
        })
    elif acao == "*":
        findings.append({
            "type": "[Loophole: CORS] Permissive Wildcard Origin Header (*)",
            "category": "CORS & Cross-Origin Security",
            "severity": "low",
            "cwe": "CWE-942",
            "owasp": "A05:2021-Security Misconfiguration",
            "cvss": 3.7,
            "target": url,
            "evidence": "Access-Control-Allow-Origin: *",
            "detail": "Access-Control-Allow-Origin is set to wildcard `*`. If this endpoint serves sensitive data, it can be read from any website.",
            "impact": "Publicly exposes unauthenticated response bodies to arbitrary third-party scripts.",
            "fix": "Restrict Access-Control-Allow-Origin to authorized frontend domain origins.",
            "code_remediation": "Access-Control-Allow-Origin: https://app.example.com",
        })

    return findings


def audit_http_methods(url: str, timeout: int = DEFAULT_TIMEOUT) -> list:
    """Tests dangerous HTTP methods (TRACE, PUT, DELETE, OPTIONS)."""
    findings = []
    
    # 1. TRACE / Cross-Site Tracing (XST)
    try:
        r_trace = requests.request("TRACE", url, timeout=timeout, verify=False, headers={"User-Agent": DEFAULT_USER_AGENT})
        if r_trace.status_code == 200 and "TRACE" in r_trace.text:
            findings.append({
                "type": "[Loophole: HTTP Verbs] HTTP TRACE Method Enabled (Cross-Site Tracing / XST)",
                "category": "HTTP Methods & Verb Security",
                "severity": "medium",
                "cwe": "CWE-650",
                "owasp": "A05:2021-Security Misconfiguration",
                "cvss": 5.3,
                "target": url,
                "evidence": f"TRACE request returned HTTP 200 OK echoing headers.",
                "detail": "HTTP TRACE echoes back submitted headers including HttpOnly cookies and authorization tokens.",
                "impact": "Attackers leveraging XSS can bypass HttpOnly cookie protections using TRACE to read session cookies.",
                "fix": "Disable HTTP TRACE/TRACK methods on the web server or load balancer.",
                "code_remediation": "# Apache (httpd.conf):\nTraceEnable Off\n\n# Nginx:\nif ($request_method ~ ^(TRACE|TRACK)$) {\n    return 405;\n}",
            })
    except Exception:
        pass

    # 2. Arbitrary PUT / DELETE checks
    for method in ("PUT", "DELETE"):
        try:
            r = requests.request(method, url, timeout=timeout, verify=False, headers={"User-Agent": DEFAULT_USER_AGENT})
            if r.status_code in (200, 201, 204):
                findings.append({
                    "type": f"[Loophole: HTTP Verbs] Unauthenticated HTTP {method} Method Accepted",
                    "category": "HTTP Methods & Verb Security",
                    "severity": "high",
                    "cwe": "CWE-650",
                    "owasp": "A01:2021-Broken Access Control",
                    "cvss": 7.5,
                    "target": url,
                    "evidence": f"HTTP {method} returned HTTP {r.status_code}.",
                    "detail": f"The root URL accepts unauthenticated HTTP {method} requests.",
                    "impact": "Attackers may modify, overwrite, or delete resources without authentication.",
                    "fix": f"Restrict {method} methods to authorized users and return 405 Method Not Allowed for unauthenticated requests.",
                    "code_remediation": "if ($request_method !~ ^(GET|POST|HEAD)$) { return 405; }",
                })
        except Exception:
            pass

    return findings


def audit_sensitive_recon_paths(base_url: str, timeout: int = 5) -> list:
    """Probes for exposed environment files, git repos, backup archives, debuggers, and admin portals."""
    findings = []
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    def _probe_path(entry):
        path, title, severity, cwe, cvss, keywords = entry
        target_path_url = origin + path
        try:
            r = requests.get(target_path_url, timeout=timeout, allow_redirects=False, verify=False, headers={"User-Agent": DEFAULT_USER_AGENT})
            if r.status_code == 200 and len(r.content) > 0:
                body_sample = r.text[:2000]
                
                # Verify keywords if specified to avoid single-page-app 200 fallback false-positives
                if keywords:
                    matched = any(kw.lower() in body_sample.lower() for kw in keywords)
                    if not matched:
                        return None

                # Check if it looks like an HTML error or standard index fallback
                if path.endswith((".json", ".sql", ".zip", "HEAD", "config", ".yml", ".env")) and "<!doctype html" in body_sample.lower():
                    # HTML returned for non-HTML file -> SPA redirect false positive
                    return None

                return {
                    "type": f"[Loophole: Recon] {title} Accessible ({path})",
                    "category": "Information Disclosure & Reconnaissance",
                    "severity": severity,
                    "cwe": cwe,
                    "owasp": "A01:2021-Broken Access Control",
                    "cvss": cvss,
                    "target": target_path_url,
                    "evidence": f"Path '{path}' returned HTTP 200 ({len(r.content)} bytes). Preview:\n{body_sample[:250]}...",
                    "detail": f"Sensitive file or administrative path '{path}' is publicly reachable without authentication.",
                    "impact": "Adversaries can extract secret credentials, source repositories, database dumps, or access privileged admin panels.",
                    "fix": f"Block public access to '{path}' immediately in reverse proxy/web server config or delete sensitive backup files.",
                    "code_remediation": f"# Nginx:\nlocation ~* /\\.(env|git|htaccess|htpasswd) {{\n    deny all;\n    return 404;\n}}",
                }
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        results = executor.map(_probe_path, SENSITIVE_PROBE_PATHS)
        for res in results:
            if res:
                findings.append(res)

    return findings


def audit_robots_and_security_txt(base_url: str, timeout: int = DEFAULT_TIMEOUT) -> list:
    """Audits robots.txt for sensitive path leaks and checks security.txt compliance."""
    findings = []
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    # 1. robots.txt audit
    robots_url = origin + "/robots.txt"
    try:
        r = requests.get(robots_url, timeout=timeout, allow_redirects=True, verify=False, headers={"User-Agent": DEFAULT_USER_AGENT})
        if r.status_code == 200 and "user-agent" in r.text.lower():
            sensitive_keywords = ["admin", "secret", "private", "backup", "staging", "api", "internal", "config", "debug", "dev"]
            leaked_paths = []
            for line in r.text.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if any(kw in path.lower() for kw in sensitive_keywords):
                        leaked_paths.append(path)

            if leaked_paths:
                findings.append({
                    "type": "[Loophole: Recon] Sensitive Internal Paths Leaked in robots.txt",
                    "category": "Information Disclosure & Reconnaissance",
                    "severity": "low",
                    "cwe": "CWE-200",
                    "owasp": "A01:2021-Broken Access Control",
                    "cvss": 3.7,
                    "target": robots_url,
                    "evidence": f"Disallowed paths in robots.txt: {', '.join(leaked_paths[:8])}",
                    "detail": "robots.txt reveals hidden administrative or internal directories to attackers and crawlers.",
                    "impact": "Attackers discover high-value target paths to probe for vulnerabilities and bypass mechanisms.",
                    "fix": "Do not rely on robots.txt for security. Protect sensitive endpoints with authentication and remove sensitive path names.",
                    "code_remediation": "# Restrict admin paths via authentication rather than listing in robots.txt",
                })
    except Exception:
        pass

    # 2. security.txt audit (RFC 9116)
    security_txt_url = origin + "/.well-known/security.txt"
    try:
        r_sec = requests.get(security_txt_url, timeout=timeout, allow_redirects=True, verify=False, headers={"User-Agent": DEFAULT_USER_AGENT})
        if r_sec.status_code != 200 or "contact:" not in r_sec.text.lower():
            findings.append({
                "type": "[Loophole: Best Practice] Missing RFC 9116 security.txt Vulnerability Disclosure Policy",
                "category": "Defensive Posture & Best Practices",
                "severity": "info",
                "cwe": "CWE-200",
                "owasp": "A05:2021-Security Misconfiguration",
                "cvss": 0.0,
                "target": security_txt_url,
                "evidence": f"GET {security_txt_url} returned HTTP {r_sec.status_code}",
                "detail": "No `/.well-known/security.txt` file found. RFC 9116 defines a standard location for ethical hackers and researchers to report security vulnerabilities.",
                "impact": "Security researchers have no direct channel to report zero-day vulnerabilities discovered on your site.",
                "fix": "Create `/.well-known/security.txt` declaring your security contact email or disclosure program.",
                "code_remediation": "# Example /.well-known/security.txt:\nContact: mailto:security@yourdomain.com\nExpires: 2027-12-31T23:59:59.000Z\nPreferred-Languages: en",
            })
    except Exception:
        pass

    return findings


def audit_html_dom_security(html_content: str, url: str) -> list:
    """Audits DOM, HTML markup, forms, reverse tabnabbing, mixed content, and leaked client-side secrets."""
    findings = []
    if not html_content:
        return findings

    # 1. Reverse Tabnabbing (target="_blank" without rel="noopener noreferrer")
    tabnab_regex = re.compile(r'<a\s+[^>]*href=[\'"]([^\'"]+)[\'"][^>]*target=[\'"]_blank[\'"][^>]*>', re.IGNORECASE)
    matches = tabnab_regex.findall(html_content)
    unsafe_links = []
    for tag_match in tabnab_regex.finditer(html_content):
        tag_str = tag_match.group(0)
        if "rel=" not in tag_str.lower() or not any(kw in tag_str.lower() for kw in ("noopener", "noreferrer")):
            href_match = re.search(r'href=[\'"]([^\'"]+)[\'"]', tag_str, re.IGNORECASE)
            if href_match:
                href = href_match.group(1)
                if href.startswith(("http://", "https://", "//")):
                    unsafe_links.append(href)

    if unsafe_links:
        findings.append({
            "type": f"[Loophole: DOM] Reverse Tabnabbing Vulnerability ({len(unsafe_links)} Link(s) Found)",
            "category": "HTML & DOM Client-Side Security",
            "severity": "medium",
            "cwe": "CWE-1022",
            "owasp": "A03:2021-Injection",
            "cvss": 5.3,
            "target": url,
            "evidence": f"Unsafe target='_blank' links without rel='noopener noreferrer':\n" + "\n".join(f"- {l}" for l in unsafe_links[:5]),
            "detail": "External links opening in a new tab (`target=\"_blank\"`) without `rel=\"noopener noreferrer\"` grant the destination page control over `window.opener`.",
            "impact": "Malicious target websites can redirect the victim's original tab to a realistic phishing clone page (`window.opener.location = 'https://fake-login.com'`).",
            "fix": "Always append `rel=\"noopener noreferrer\"` to all links using `target=\"_blank\"`.",
            "code_remediation": '<a href="https://external.com" target="_blank" rel="noopener noreferrer">External Link</a>',
        })

    # 2. Insecure Form Submissions (HTTP action on HTTPS site or unencrypted password submit)
    forms = re.findall(r'<form\b[^>]*>', html_content, re.IGNORECASE)
    for f_tag in forms:
        action_match = re.search(r'action=[\'"]([^\'"]+)[\'"]', f_tag, re.IGNORECASE)
        if action_match:
            act = action_match.group(1).strip()
            if act.startswith("http://"):
                findings.append({
                    "type": "[Loophole: DOM] Insecure Form Submission over Plain HTTP",
                    "category": "HTML & DOM Client-Side Security",
                    "severity": "high",
                    "cwe": "CWE-319",
                    "owasp": "A02:2021-Cryptographic Failures",
                    "cvss": 7.5,
                    "target": url,
                    "evidence": f"Form action: `{f_tag}`",
                    "detail": "Form transmits user input to an unencrypted HTTP endpoint (`http://`).",
                    "impact": "Submitted user input, passwords, or personal data will be sent in plain text over the network.",
                    "fix": "Ensure all form `action` attributes point to secure `https://` URLs or relative paths.",
                    "code_remediation": '<form action="/api/submit" method="POST">',
                })

    # 3. Missing CSRF Token in POST Forms
    post_forms = [f for f in forms if re.search(r'method=[\'"]post[\'"]', f, re.IGNORECASE)]
    if post_forms:
        csrf_inputs = re.findall(r'<input\b[^>]*name=[\'"][^\'"]*(?:csrf|xsrf|token|_token|authenticity)[^\'"]*[\'"][^>]*>', html_content, re.IGNORECASE)
        if not csrf_inputs:
            findings.append({
                "type": "[Loophole: DOM] Missing Anti-CSRF Token in HTML POST Forms",
                "category": "HTML & DOM Client-Side Security",
                "severity": "medium",
                "cwe": "CWE-352",
                "owasp": "A01:2021-Broken Access Control",
                "cvss": 6.5,
                "target": url,
                "evidence": f"Found {len(post_forms)} POST form(s) lacking hidden anti-CSRF token input fields.",
                "detail": "HTML forms utilizing HTTP POST do not contain embedded anti-CSRF tokens.",
                "impact": "Adversaries can forge requests from external sites to trigger unauthorized actions on behalf of authenticated users.",
                "fix": "Implement anti-CSRF protection tokens (e.g. Synchronizer Token Pattern or SameSite cookies).",
                "code_remediation": '<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">',
            })

    # 4. Mixed Content over HTTPS
    if url.startswith("https://"):
        mixed_scripts = re.findall(r'<script\b[^>]*src=[\'"]http://[^\'"]+[\'"]', html_content, re.IGNORECASE)
        mixed_links = re.findall(r'<link\b[^>]*href=[\'"]http://[^\'"]+[\'"]', html_content, re.IGNORECASE)
        if mixed_scripts or mixed_links:
            findings.append({
                "type": "[Loophole: DOM] Active Mixed Content (Insecure HTTP Assets on HTTPS Page)",
                "category": "HTML & DOM Client-Side Security",
                "severity": "high",
                "cwe": "CWE-311",
                "owasp": "A02:2021-Cryptographic Failures",
                "cvss": 7.5,
                "target": url,
                "evidence": f"Found {len(mixed_scripts)} insecure script(s) and {len(mixed_links)} insecure stylesheet(s) loaded over http://",
                "detail": "Page loaded over HTTPS references scripts or stylesheets over unencrypted HTTP.",
                "impact": "Man-in-the-Middle attackers can modify the unencrypted HTTP scripts to inject arbitrary malicious JavaScript.",
                "fix": "Update all asset references to HTTPS or protocol-relative paths (`//`).",
                "code_remediation": '<script src="https://cdn.example.com/app.js"></script>',
            })

    # 5. Sensitive Comments in HTML
    comments = re.findall(r'<!--(.*?)-->', html_content, re.DOTALL)
    sensitive_comment_triggers = ["todo", "fixme", "bug", "password", "token", "api_key", "secret", "internal ip", "staging"]
    leaked_comments = []
    for c in comments:
        c_clean = c.strip()
        if any(trig in c_clean.lower() for trig in sensitive_comment_triggers) and len(c_clean) < 300:
            leaked_comments.append(c_clean)

    if leaked_comments:
        findings.append({
            "type": "[Loophole: Disclosure] Sensitive Developer Comments Leaked in HTML Source",
            "category": "Information Disclosure",
            "severity": "low",
            "cwe": "CWE-615",
            "owasp": "A05:2021-Security Misconfiguration",
            "cvss": 3.7,
            "target": url,
            "evidence": "Leaked HTML comments:\n" + "\n".join(f"- `<!-- {c} -->`" for c in leaked_comments[:3]),
            "detail": "HTML source code contains developer comments referencing internal tasks, bugs, or credentials.",
            "impact": "Exposes internal implementation details and potential software flaws to adversaries.",
            "fix": "Strip HTML comments in production build pipelines (e.g. via HTML minifiers).",
            "code_remediation": "# Webpack / Vite / Gulp: Enable HTML minifier 'removeComments: true'",
        })

    # 6. Hardcoded Secrets & API Keys in HTML / Script blocks
    for name, pattern, severity, cwe, cvss, fix in SECRET_PATTERNS:
        match = pattern.search(html_content)
        if match:
            secret_preview = match.group(0)
            if len(secret_preview) > 60:
                secret_preview = secret_preview[:25] + "..." + secret_preview[-15:]
            findings.append({
                "type": f"[Loophole: Credentials] {name}",
                "category": "Credentials & Secrets",
                "severity": severity,
                "cwe": cwe,
                "owasp": "A01:2021-Broken Access Control",
                "cvss": cvss,
                "target": url,
                "evidence": f"Matched secret in page source: `{secret_preview}`",
                "detail": f"A secret token matching pattern '{name}' was discovered in client-side HTML/JavaScript.",
                "impact": "Attacker can copy the exposed credential directly from page source and access private services.",
                "fix": fix,
                "code_remediation": "# Store keys in server-side environment variables (.env), never in client bundle.",
            })

    return findings


def audit_open_redirect(url: str, timeout: int = DEFAULT_TIMEOUT) -> list:
    """Detects open redirect parameters in target URL."""
    findings = []
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)

    redirect_params = ["redirect", "redirect_to", "return", "return_to", "next", "url", "dest", "destination", "goto", "continue", "target", "out", "forward"]
    found_params = [p for p in qs.keys() if p.lower() in redirect_params]

    if found_params:
        test_payload = "https://evil-attacker-open-redirect-test.invalid"
        for param in found_params:
            test_qs = dict(qs)
            test_qs[param] = [test_payload]
            from urllib.parse import urlencode
            probe_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_qs, doseq=True)}"
            try:
                r = requests.get(probe_url, timeout=timeout, allow_redirects=False, verify=False, headers={"User-Agent": DEFAULT_USER_AGENT})
                loc = r.headers.get("Location", "")
                if r.status_code in (301, 302, 307, 308) and test_payload in loc:
                    findings.append({
                        "type": f"[Loophole: Redirect] Open Redirect Vulnerability in Parameter '{param}'",
                        "category": "Access Control & Input Validation",
                        "severity": "high",
                        "cwe": "CWE-601",
                        "owasp": "A01:2021-Broken Access Control",
                        "cvss": 7.4,
                        "target": probe_url,
                        "evidence": f"Request to '{probe_url}' redirected to '{loc}'",
                        "detail": f"The query parameter '{param}' accepts arbitrary external URLs and issues a redirect without domain validation.",
                        "impact": "Attackers construct legitimate-looking links (`https://yourbank.com/login?redirect=https://evil.com`) to direct users to phishing clones after login.",
                        "fix": "Validate redirect URLs against a whitelist of approved domain paths or enforce relative redirects only (`path.startsWith('/') && !path.startsWith('//')`).",
                        "code_remediation": "# Safe redirect validation:\nfunction isSafeRedirect(url) {\n  return url.startsWith('/') && !url.startsWith('//');\n}",
                    })
            except Exception:
                pass

    return findings


def audit_error_stack_traces(base_url: str, timeout: int = DEFAULT_TIMEOUT) -> list:
    """Probes intentional 404/malformed routes for verbose framework stack trace leaks."""
    findings = []
    parsed = urlparse(base_url)
    probe_url = f"{parsed.scheme}://{parsed.netloc}/_yemanode_loophole_probe_404_leak_test"

    try:
        r = requests.get(probe_url, timeout=timeout, allow_redirects=False, verify=False, headers={"User-Agent": DEFAULT_USER_AGENT})
        body = r.text[:3000]

        stack_markers = [
            ("Python Django Debug Stack Trace", ["Traceback (most recent call last):", "Request Method:", "Django Version:", "Exception Type:"], "high", "CWE-209", 7.5),
            ("Python Werkzeug / Flask Debugger", ["Werkzeug Debugger", "Traceback", "console.png"], "critical", "CWE-489", 9.8),
            ("Java Tomcat / Spring Stack Trace", ["org.springframework.", "org.apache.catalina.", "Whitelabel Error Page", "NullPointerException"], "medium", "CWE-209", 5.3),
            ("Node.js Express / V8 Stack Trace", ["ReferenceError:", "TypeError:", "at Module._compile", "UnhandledPromiseRejectionWarning"], "medium", "CWE-209", 5.3),
            ("PHP Error / Fatal Stack Trace", ["Fatal error:", "Uncaught exception", "Stack trace:", "in /var/www/"], "medium", "CWE-209", 5.3),
            ("Ruby on Rails Error Trace", ["ActionController::RoutingError", "Rails.root:", "vendor/bundle"], "high", "CWE-209", 7.5),
            ("Microsoft ASP.NET Yellow Screen", ["Server Error in '/' Application", "System.Web.HttpException", "Stack Trace:"], "medium", "CWE-209", 5.3),
            ("Database Syntax Error Leakage", ["SQLSTATE[", "syntax error at or near", "ORA-00942", "You have an error in your SQL syntax"], "high", "CWE-209", 7.5),
        ]

        for title, markers, severity, cwe, cvss in stack_markers:
            if any(m in body for m in markers):
                findings.append({
                    "type": f"[Loophole: Errors] {title} Leaked on 404 Error Page",
                    "category": "Error Handling & Diagnostics",
                    "severity": severity,
                    "cwe": cwe,
                    "owasp": "A05:2021-Security Misconfiguration",
                    "cvss": cvss,
                    "target": probe_url,
                    "evidence": f"Error response body contains stack markers:\n{body[:250]}...",
                    "detail": "The web server returns raw debug stack traces with file system paths, database queries, and code lines on error pages.",
                    "impact": "Assists adversaries in crafting targeted exploits and reveals backend file paths, database schemas, and framework internals.",
                    "fix": "Catch all unhandled exceptions globally and render generic, user-friendly error pages (RFC 7807). Disable DEBUG mode.",
                    "code_remediation": "# Python Django (settings.py):\nDEBUG = False\n\n# Node.js Express:\napp.use((err, req, res, next) => {\n  res.status(500).json({ error: 'Internal Server Error' });\n});",
                })
                break
    except Exception:
        pass

    return findings


def synthesize_attack_chains(findings: list) -> list:
    """Correlates discovered loop holes to identify chained multi-step hacker attack paths."""
    chains = []
    types_str = " ".join(f.get("type", "").lower() for f in findings)
    details_str = " ".join(f.get("detail", "").lower() for f in findings)

    has_csp_missing = "missing content security policy" in types_str
    has_tabnab = "reverse tabnabbing" in types_str
    has_cookie_insecure = "missing httponly" in types_str or "missing secure" in types_str
    has_cors_vuln = "cors" in types_str and ("wildcard" in types_str or "reflection" in types_str)
    has_git_or_env = ".git" in types_str or ".env" in types_str or "backup" in types_str
    has_admin_portal = "admin" in types_str or "wp-admin" in types_str or "phpmyadmin" in types_str
    has_hsts_missing = "strict transport security" in types_str or "insecure plain http" in types_str
    has_stack_trace = "stack trace" in types_str or "debug" in types_str
    has_secret_leak = "credentials" in types_str or "secret" in types_str

    # Chain 1: Missing CSP + Tabnabbing -> Phishing & Session Hijack
    if has_csp_missing and has_tabnab:
        chains.append({
            "title": "Chained Attack Path 1: Missing CSP + Reverse Tabnabbing (Phishing & Credential Theft)",
            "severity": "high",
            "impact": "Attackers can manipulate window.opener from external links to redirect victims to phishing clones without triggering CSP blocks.",
            "steps": "1. User clicks an external link on your site opening in a new tab.\n2. Malicious destination executes window.opener.location = 'https://fake-login-clone.com'.\n3. Victim returns to original tab believing their session timed out and enters credentials.",
            "remediation": "Add rel='noopener noreferrer' to all target='_blank' links and configure a strict Content-Security-Policy.",
        })

    # Chain 2: Missing HttpOnly + XSS Exposure / Missing CSP -> Session Hijack
    if has_cookie_insecure and has_csp_missing:
        chains.append({
            "title": "Chained Attack Path 2: Missing HttpOnly Cookie + Absent CSP (Account Takeover)",
            "severity": "critical",
            "impact": "Complete compromise of active user sessions via JavaScript document.cookie exfiltration.",
            "steps": "1. Attacker identifies any client-side injection point (or malicious third-party script dependency).\n2. Script reads document.cookie to harvest active authentication tokens.\n3. Harvested session cookies are exfiltrated to attacker server, enabling full account takeover.",
            "remediation": "Enforce HttpOnly and Secure flags on all session cookies, and deploy a strict Content-Security-Policy.",
        })

    # Chain 3: Exposed Git / .env + Secret Credentials -> Full Infrastructure Takeover
    if has_git_or_env or has_secret_leak:
        chains.append({
            "title": "Chained Attack Path 3: Exposed Repository / Environment File -> Cloud Infrastructure Breach",
            "severity": "critical",
            "impact": "Complete source code leak, database access, and cloud IAM compromise.",
            "steps": "1. Attacker fetches publicly accessible /.env or /.git/HEAD.\n2. Attacker downloads complete database connection strings or AWS IAM access keys.\n3. Keys are utilized to directly access production databases and cloud storage.",
            "remediation": "Block access to dotfiles (/.env, /.git) in web server config, rotate all exposed credentials immediately.",
        })

    # Chain 4: Permissive CORS + Sensitive Endpoints -> Cross-Origin Data Exfiltration
    if has_cors_vuln:
        chains.append({
            "title": "Chained Attack Path 4: Permissive CORS Reflection + Authenticated User Session",
            "severity": "high",
            "impact": "Unauthorized extraction of private user profiles and sensitive API responses.",
            "steps": "1. Logged-in victim visits attacker-controlled website.\n2. Malicious page sends background AJAX requests to target website.\n3. Permissive CORS headers allow attacker script to read victim's private response payload.",
            "remediation": "Enforce an explicit whitelist of authorized frontend origins in CORS headers.",
        })

    # Chain 5: Missing HSTS + Cleartext HTTP -> Man-in-the-Middle SSL Stripping
    if has_hsts_missing:
        chains.append({
            "title": "Chained Attack Path 5: Missing HSTS + Cleartext HTTP -> SSL-Stripping MitM Attack",
            "severity": "high",
            "impact": "Interception and manipulation of web traffic on public networks.",
            "steps": "1. Victim connects to public Wi-Fi or compromised network.\n2. Attacker runs sslstrip to intercept initial HTTP connection before HTTPS redirect.\n3. Victim communicates over plain HTTP while attacker proxies HTTPS to the real server, intercepting plain passwords.",
            "remediation": "Deploy HSTS with max-age=31536000 and submit the domain to the HSTS Preload list.",
        })

    return chains


def calculate_security_score_and_grade(findings: list) -> tuple:
    """Calculates overall security score (0-100) and letter grade (A+, A, B, C, D, F)."""
    counts = report._count(findings)
    deductions = {
        "critical": 25,
        "high": 12,
        "medium": 5,
        "low": 2,
        "info": 0,
    }

    total_penalty = sum(counts[sev] * deductions[sev] for sev in deductions)
    score = max(0, 100 - total_penalty)

    if counts["critical"] > 0:
        score = min(score, 55)

    if score >= 95 and counts["critical"] == 0 and counts["high"] == 0:
        grade = "A+"
        grade_desc = "Excellent — Hardened Security Posture"
    elif score >= 85 and counts["critical"] == 0 and counts["high"] == 0:
        grade = "A"
        grade_desc = "Strong — Robust Defenses with Minor Improvements"
    elif score >= 75 and counts["critical"] == 0:
        grade = "B"
        grade_desc = "Good — Moderate Hardening Required"
    elif score >= 60:
        grade = "C"
        grade_desc = "Fair — Several Significant Security Gaps"
    elif score >= 40:
        grade = "D"
        grade_desc = "Poor — High-Risk Vulnerabilities Detected"
    else:
        grade = "F"
        grade_desc = "Critical Risk — Immediate Breach Potential"

    return score, grade, grade_desc, counts


def analyse_url(url: str, deep: bool = True, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """
    Orchestrates the end-to-end professional website security assessment.
    Returns complete analysis results, attack surface, findings, chains, and score.
    """
    target_url = normalize_target_url(url)
    parsed = urlparse(target_url)
    hostname = parsed.hostname or ""

    # 1. DNS & Network Resolution
    network_info = resolve_target_host(hostname)

    # 2. TLS & Transport Audit
    tls_findings, tls_info = audit_tls_and_transport(target_url, timeout=timeout)

    # 3. Main Request & Response Header Analysis
    all_findings = list(tls_findings)
    raw_cookies = []
    response_headers = {}
    html_body = ""
    status_code = 0

    try:
        resp = requests.get(
            target_url,
            timeout=timeout,
            allow_redirects=True,
            verify=False,
            headers={"User-Agent": DEFAULT_USER_AGENT},
        )
        status_code = resp.status_code
        response_headers = dict(resp.headers)
        html_body = resp.text
        
        # Raw Set-Cookie headers
        if "set-cookie" in resp.headers:
            if hasattr(resp.raw, "headers"):
                raw_cookies = resp.raw.headers.getlist("Set-Cookie")
            if not raw_cookies:
                raw_cookies = [resp.headers["set-cookie"]]

    except requests.exceptions.RequestException as e:
        all_findings.append({
            "type": "[Connectivity] Target URL Connection Failed",
            "category": "Connectivity",
            "severity": "critical",
            "target": target_url,
            "cwe": "CWE-200",
            "owasp": "A05:2021-Security Misconfiguration",
            "cvss": 0.0,
            "evidence": str(e),
            "detail": f"Failed to connect to target '{target_url}': {str(e)}",
            "impact": "The website could not be reached for complete analysis.",
            "fix": "Verify that the URL is correct, DNS is resolving, and firewall security groups allow inbound HTTP/HTTPS traffic.",
        })

    # 4. Fingerprint WAF and Tech stack
    tech_info = detect_waf_and_technologies(response_headers, html_body)

    # 5. Audits
    if response_headers:
        all_findings.extend(audit_security_headers(response_headers, target_url))
        all_findings.extend(audit_cookie_security(raw_cookies, target_url))

    all_findings.extend(audit_cors_configuration(target_url, timeout=timeout))
    all_findings.extend(audit_http_methods(target_url, timeout=timeout))

    if deep:
        all_findings.extend(audit_sensitive_recon_paths(target_url, timeout=5))
        all_findings.extend(audit_robots_and_security_txt(target_url, timeout=timeout))
        all_findings.extend(audit_html_dom_security(html_body, target_url))
        all_findings.extend(audit_open_redirect(target_url, timeout=timeout))
        all_findings.extend(audit_error_stack_traces(target_url, timeout=timeout))

    # 6. Attack Chains Synthesis
    chains = synthesize_attack_chains(all_findings)

    # 7. Calculate Score & Letter Grade
    score, grade, grade_desc, counts = calculate_security_score_and_grade(all_findings)

    return {
        "target_url": target_url,
        "hostname": hostname,
        "status_code": status_code,
        "network_info": network_info,
        "tls_info": tls_info,
        "tech_info": tech_info,
        "security_score": score,
        "security_grade": grade,
        "grade_description": grade_desc,
        "severity_counts": counts,
        "findings": all_findings,
        "vulnerability_chains": chains,
        "scanned_at": datetime.datetime.now().isoformat(timespec="seconds"),
    }


def write_website_markdown_report(output_path: str, results: dict) -> str:
    """
    Generates a professional, comprehensive Hacker Security Audit & Loophole Fix Report in Markdown (.md).
    """
    url = results["target_url"]
    grade = results["security_grade"]
    score = results["security_score"]
    desc = results["grade_description"]
    counts = results["severity_counts"]
    findings = results["findings"]
    chains = results["vulnerability_chains"]
    net = results["network_info"]
    tls = results["tls_info"]
    tech = results["tech_info"]
    total = len(findings)

    grade_emojis = {"A+": "🏆", "A": "🛡️", "B": "🟢", "C": "🟡", "D": "🟠", "F": "🔴"}
    grade_icon = grade_emojis.get(grade, "🛡️")

    lines = []
    lines.append(f"# {grade_icon} Website Security Audit & Loophole Report — `{url}`")
    lines.append("")
    lines.append(f"> **Security Rating:** **Grade {grade}** ({score}/100) — *{desc}*  ")
    lines.append(f"> **Target:** `{url}` | **Audit Timestamp:** `{results['scanned_at']} UTC`  ")
    lines.append(f"> **Assessment Type:** Full-Spectrum Professional Ethical Web Penetration Audit  ")
    lines.append("")

    # Executive Summary Card
    lines.append("## 📊 Executive Summary & Security Posture")
    lines.append("")
    lines.append(f"Yemanode conducted an automated, professional ethical security audit against **{url}**. "
                 f"The audit analyzed TLS transport cryptography, HTTP browser security headers, cookie flags, "
                 f"CORS configurations, dangerous HTTP methods, sensitive file exposure, DOM/HTML loopholes, "
                 f"open redirects, and error handling.")
    lines.append("")
    lines.append(f"A total of **{total} loophole finding(s)** were identified, with **{counts['critical']} Critical** and **{counts['high']} High** priority vulnerabilities requiring immediate remediation.")
    lines.append("")

    # Metric Table
    lines.append("| Severity Level | Count | Action Required |")
    lines.append("|---|---:|---|")
    lines.append(f"| {report.SEVERITY_ICON['critical']} Critical | **{counts['critical']}** | 🚨 Fix Immediately (Within 24 Hours) |")
    lines.append(f"| {report.SEVERITY_ICON['high']} High | **{counts['high']}** | ⚠️ Fix within 7 Days |")
    lines.append(f"| {report.SEVERITY_ICON['medium']} Medium | **{counts['medium']}** | 🔧 Schedule for next sprint |")
    lines.append(f"| {report.SEVERITY_ICON['low']} Low | **{counts['low']}** | 📋 Apply defensive hardening |")
    lines.append(f"| {report.SEVERITY_ICON['info']} Info / Best Practice | **{counts['info']}** | 💡 Informational / RFC compliance |")
    lines.append("")

    # Discovered Attack Surface & Tech Stack
    lines.append("## 🔍 Discovered Attack Surface & Technology Stack")
    lines.append("")
    lines.append(f"- **Primary IPv4:** `{', '.join(net['ipv4']) if net['ipv4'] else 'Unresolved'}`")
    if net.get("ipv6"):
        lines.append(f"- **IPv6 Addresses:** `{', '.join(net['ipv6'])}`")
    lines.append(f"- **Web Application Firewall (WAF):** `{tech['waf'] or 'None Detected (Direct Origin Exposure)'}`")
    lines.append(f"- **Web Server:** `{tech['server'] or 'Not Disclosed'}`")
    lines.append(f"- **Backend Framework / Engine:** `{tech['powered_by'] or (', '.join(tech['frameworks']) if tech['frameworks'] else 'Not Disclosed')}`")
    lines.append(f"- **Negotiated TLS Protocol:** `{tls.get('tls_version') or 'N/A'}`")
    if tls.get("cert_issuer"):
        lines.append(f"- **SSL Certificate Issuer:** `{tls['cert_issuer']}` (Expires: `{tls.get('cert_expiry', 'Unknown')}`)")
    lines.append("")

    # Vulnerability Chaining
    if chains:
        lines.append("## ⛓️ Exploitable Vulnerability Chains & Hacker Attack Scenarios")
        lines.append("")
        lines.append("Individual loopholes can be chained by skilled adversaries to achieve deeper system compromise:")
        lines.append("")
        for ch in chains:
            lines.append(f"### 🔴 {ch['title']}")
            lines.append(f"- **Exploit Impact:** {ch['impact']}")
            lines.append(f"- **Hacker Attack Execution Steps:**\n```\n{ch['steps']}\n```")
            lines.append(f"- **Root Cause Remediation:** {ch['remediation']}")
            lines.append("")

    # Detailed Findings
    lines.append("## 🛠️ Detailed Loop Hole Findings & Action-Oriented Fix Plan")
    lines.append("")

    if not findings:
        lines.append("🎉 **No vulnerabilities were detected by automated static and dynamic checks.**")
        lines.append("Your web server and application demonstrate an excellent defensive baseline.")
    else:
        for idx, f in enumerate(report._sorted(findings), start=1):
            sev = f.get("severity", "info").lower()
            icon = report.SEVERITY_ICON.get(sev, "⚪")
            cwe = f.get("cwe", "CWE-200")
            owasp = f.get("owasp", "A05:2021-Security Misconfiguration")
            cvss = f.get("cvss", report.DEFAULT_CVSS_MAP.get(sev, 0.0))
            title = f.get("type", "Security Loophole")
            cat = f.get("category", "General")

            lines.append(f"### {idx}. {icon} [{sev.upper()}] {title}")
            lines.append("")
            lines.append(f"- **Category:** `{cat}` | **CVSS v3.1:** `{cvss}`")
            lines.append(f"- **Industry Standards:** `{cwe}` | `{owasp}`")
            lines.append(f"- **Affected Target:** `{f.get('target', url)}`")
            lines.append(f"- **Vulnerability Overview:** {f.get('detail', '')}")
            lines.append("")
            
            if f.get("evidence"):
                snip = str(f["evidence"])
                if "\n" in snip:
                    lines.append(f"**🔍 Discovered Evidence / Response Extract:**\n```\n{snip}\n```")
                else:
                    lines.append(f"**🔍 Discovered Evidence:** `{snip}`")
                lines.append("")

            if f.get("impact"):
                lines.append(f"**🎯 Hacker Exploit Scenario & Risk:**  \n{f['impact']}")
                lines.append("")

            if f.get("fix"):
                lines.append(f"**🔧 Step-by-Step Action to Fix:**  \n{f['fix']}")
                lines.append("")

            if f.get("code_remediation"):
                lines.append(f"**💻 Ready-to-Use Code & Config Fix:**\n```\n{f['code_remediation']}\n```")
                lines.append("")

            lines.append("---")
            lines.append("")

    # Prioritized Remediation Roadmap
    lines.append("## 📅 Prioritized 3-Phase Remediation Roadmap")
    lines.append("")
    lines.append("### 🚨 Phase 1: Immediate Critical Fixes (Within 24 Hours)")
    lines.append("1. **Block Exposed Sensitive Files:** Restrict access to `/.env`, `/.git`, database dumps, and backup archives in web server configs.")
    lines.append("2. **Secure High-Value Cookies:** Enforce `HttpOnly`, `Secure`, and `SameSite=Lax` on all authentication and session cookies.")
    lines.append("3. **Revoke Compromised Credentials:** Rotate any API keys or credentials discovered in client-side HTML or git commits.")
    lines.append("")
    lines.append("### ⚠️ Phase 2: High-Priority Hardening (Within 7 Days)")
    lines.append("1. **Deploy Essential Security Headers:** Add `Strict-Transport-Security` (HSTS), `X-Frame-Options`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy`.")
    lines.append("2. **Lock Down CORS Policies:** Disallow wildcard `*` with credentials and validate request `Origin` headers strictly.")
    lines.append("3. **Disable Dangerous HTTP Methods:** Turn off `TRACE`, `PUT`, `DELETE` at reverse proxy listeners.")
    lines.append("")
    lines.append("### 🛡️ Phase 3: Comprehensive Defense-in-Depth (Within 30 Days)")
    lines.append("1. **Implement Content-Security-Policy (CSP):** Start in Report-Only mode and incrementally tighten script and frame sources.")
    lines.append("2. **Fix Reverse Tabnabbing:** Append `rel=\"noopener noreferrer\"` to all external `<a target=\"_blank\">` links.")
    lines.append("3. **Adopt RFC 9116 security.txt:** Publish `/.well-known/security.txt` for coordinated vulnerability disclosure.")
    lines.append("")

    # Quick Server Hardening Templates
    lines.append("## 📋 Production Server Hardening Cheatsheet")
    lines.append("")
    lines.append("### Nginx Production Hardening Block")
    lines.append("```nginx")
    lines.append("# /etc/nginx/conf.d/security.conf")
    lines.append("server_tokens off;")
    lines.append("add_header X-Frame-Options 'DENY' always;")
    lines.append("add_header X-Content-Type-Options 'nosniff' always;")
    lines.append("add_header Referrer-Policy 'strict-origin-when-cross-origin' always;")
    lines.append("add_header Permissions-Policy 'camera=(), microphone=(), geolocation=(), payment=()' always;")
    lines.append("add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload' always;")
    lines.append("add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none';\" always;")
    lines.append("")
    lines.append("# Block sensitive dotfiles and git repos")
    lines.append("location ~ /\\.(?!well-known) {")
    lines.append("    deny all;")
    lines.append("    return 404;")
    lines.append("}")
    lines.append("```")
    lines.append("")
    lines.append("### Apache (.htaccess) Hardening Block")
    lines.append("```apache")
    lines.append("# .htaccess security rules")
    lines.append("Header always set X-Frame-Options 'DENY'")
    lines.append("Header always set X-Content-Type-Options 'nosniff'")
    lines.append("Header always set Referrer-Policy 'strict-origin-when-cross-origin'")
    lines.append("Header always set Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload'")
    lines.append("Header always set Permissions-Policy 'camera=(), microphone=(), geolocation=(), payment=()'")
    lines.append("ServerSignature Off")
    lines.append("```")
    lines.append("")
    lines.append("---")
    lines.append("_Generated by **Yemanode v2 — Multi-Target Ethical Security Scanner**._")
    lines.append("_Ethical security testing only. Always ensure authorization before auditing external targets._")

    return report._write(output_path, "\n".join(lines))
