"""
Hacker Pentest Engine for Yemanode.
Executes progressive offensive security methods (Levels 1 to 10) against targets
(source repositories, API URLs, OpenAPI specs, APKs, JWTs, or native binaries).
Includes Attack Surface Discovery, Safe/Aggressive execution modes, and Vulnerability Chaining.
"""
import datetime
import os

from . import api_security, apk_scanner, binary_scanner, dependencies, jwt_scanner, openapi, patterns, secrets
from .. import report

MAX_HACKER_LEVEL = 10

HACKER_METHODS = {
    1: {
        "name": "Method 1: Hardcoded Secrets & Git History Mining",
        "desc": "Scans for AWS/Azure/GCP keys, private PEM blocks, Slack/GitHub tokens, and commit history leaks.",
        "category": "Credentials & Secrets",
        "cwe": "CWE-798",
    },
    2: {
        "name": "Method 2: Code Injection & Remote Code Execution (RCE)",
        "desc": "Audits SQLi, NoSQLi, OS Command Injection, eval()/exec() usage, and SSTI.",
        "category": "Injection & RCE",
        "cwe": "CWE-89 / CWE-78",
    },
    3: {
        "name": "Method 3: Broken Access Control & Auth Enforcement",
        "desc": "Probes for missing authorization, unauthenticated state-changing HTTP verbs, and BOLA/IDOR risks.",
        "category": "Authentication & Authorization",
        "cwe": "CWE-284 / CWE-306",
    },
    4: {
        "name": "Method 4: SSRF & Internal Network Exposure Probe",
        "desc": "Probes for Server-Side Request Forgery, cloud metadata (169.254.169.254), and loopback resolution.",
        "category": "SSRF & Network Boundary",
        "cwe": "CWE-918",
    },
    5: {
        "name": "Method 5: Transport Layer Security & Header Hardening",
        "desc": "Validates TLS versions, SSL certificate trust, HSTS, CSP, CORS reflection, and security headers.",
        "category": "Transport & Cryptography",
        "cwe": "CWE-319 / CWE-942",
    },
    6: {
        "name": "Method 6: Deserialization, XXE & Path Traversal Probe",
        "desc": "Checks for pickle/unserialize/BinaryFormatter flaws, XML external entity, and path traversal (../).",
        "category": "Deserialization & Filesystem",
        "cwe": "CWE-502 / CWE-22",
    },
    7: {
        "name": "Method 7: Information Disclosure & Shadow API Discovery",
        "desc": "Probes for exposed /.env, /.git, /swagger.json, /actuator, shadow /v1 routes, and stack traces.",
        "category": "Information Disclosure",
        "cwe": "CWE-200",
    },
    8: {
        "name": "Method 8: Data Protection & Token Security Audit",
        "desc": "Audits JWT unsigned tokens (alg: none), weak HMAC keys, MD5/SHA1 hashing, and PII leakage.",
        "category": "Token & Cryptographic Controls",
        "cwe": "CWE-345 / CWE-327",
    },
    9: {
        "name": "Method 9: Infrastructure as Code & Container Hardening",
        "desc": "Audits Terraform 0.0.0.0/0 rules, Dockerfile root privileges, and Kubernetes hostPath/privileged pods.",
        "category": "IaC & Container Security",
        "cwe": "CWE-250 / CWE-732",
    },
    10: {
        "name": "Method 10: Supply Chain & Vulnerable Dependency Audit",
        "desc": "Wraps ecosystem audit tools (pip-audit, npm audit) to detect known CVEs in third-party dependencies.",
        "category": "Supply Chain & Dependencies",
        "cwe": "CWE-1395",
    },
}


def analyze_vulnerability_chains(findings):
    """
    Correlates individual findings to discover combined exploitable attack chains.
    """
    chains = []
    types_found = {f.get("type", "").lower() for f in findings}
    has_secret = any("secret" in t or "key" in t or "password" in t for t in types_found)
    has_git_secret = any("git history" in t for t in types_found)
    has_sqli = any("sql injection" in t for t in types_found)
    has_rce = any("command injection" in t or "eval" in t or "deserialization" in t for t in types_found)
    has_ssrf = any("ssrf" in t for t in types_found)
    has_cors = any("cors" in t and ("credential" in t or "wildcard" in t) for t in types_found)
    has_jwt_none = any("alg: none" in t or "unsigned token" in t for t in types_found)
    has_bola = any("bola" in t or "idor" in t or "without authentication" in t for t in types_found)
    has_debug = any("debug" in t or "stack trace" in t for t in types_found)

    if has_jwt_none and has_bola:
        chains.append({
            "title": "Chained Attack Path: Unsigned JWT (alg: none) + BOLA / IDOR Endpoint",
            "severity": "critical",
            "impact": "Complete unauthorized tenant account takeover and data exfiltration.",
            "steps": "1. Attacker crafts forged JWT with alg='none' and victim user identifier.\n2. Attacker sends forged token to unauthenticated BOLA endpoint to retrieve sensitive victim data.",
            "remediation": "Enforce strict asymmetric JWT signature verification and mandatory object-level authorization checks."
        })

    if has_ssrf and ("aws" in str(types_found) or has_secret):
        chains.append({
            "title": "Chained Attack Path: SSRF Probe + Cloud Metadata Credentials Access",
            "severity": "critical",
            "impact": "Cloud IAM instance profile compromise and infrastructure takeover.",
            "steps": "1. Attacker leverages SSRF vulnerability to request http://169.254.169.254/latest/meta-data/iam/security-credentials/.\n2. Temporary STS keys are exfiltrated to access cloud resources.",
            "remediation": "Block outbound requests to link-local IP 169.254.169.254 and enforce IMDSv2 with token hops limit 1."
        })

    if has_secret and has_git_secret:
        chains.append({
            "title": "Chained Attack Path: Committed Git History Secret + API Gateway Exposure",
            "severity": "critical",
            "impact": "Permanent credential compromise persisting despite code deletion in HEAD.",
            "steps": "1. Attacker clones public git repository and inspects commit logs (`git log -p`).\n2. Recovered API keys are utilized against live production services.",
            "remediation": "Immediately revoke and rotate all compromised keys and purge git history with git-filter-repo."
        })

    if has_debug and (has_sqli or has_rce):
        chains.append({
            "title": "Chained Attack Path: Debug Information Leakage + Injection Vector",
            "severity": "critical",
            "impact": "Precision injection exploitation guided by leaked database schema and stack traces.",
            "steps": "1. Attacker triggers error to inspect table/column names in leaked stack trace.\n2. Formulates targeted SQLi/Command payload to achieve RCE or data dump.",
            "remediation": "Disable DEBUG mode in production and sanitize all error responses."
        })

    if has_cors and (has_secret or has_bola):
        chains.append({
            "title": "Chained Attack Path: Wildcard/Permissive CORS + Sensitive Endpoint",
            "severity": "high",
            "impact": "Cross-Origin authenticated user data extraction from malicious websites.",
            "steps": "1. Victim visits attacker-controlled website while authenticated to the target API.\n2. Attacker script issues cross-origin AJAX requests reading victim responses via permissive CORS.",
            "remediation": "Enforce a strict whitelist of allowed Origins and disable Access-Control-Allow-Credentials for wildcard origins."
        })

    return chains


def run_hacker_test(target: str, level: int = 5, mode: str = "safe"):
    """
    Executes progressive security testing methods up to `level` (1 to MAX_HACKER_LEVEL)
    against the specified target. Returns structured results including attack surface,
    executed methods, findings, and vulnerability chains.
    """
    if level < 1:
        level = 1
    elif level > MAX_HACKER_LEVEL:
        level = MAX_HACKER_LEVEL

    executed_methods = []
    for lvl in range(1, level + 1):
        executed_methods.append({
            "level": lvl,
            **HACKER_METHODS[lvl]
        })

    all_findings = []
    target_type = "Unknown Target"
    attack_surface = []

    # 1. Target Auto-Detection & Surface Discovery
    if os.path.isdir(target):
        target_type = "Local Source Repository"
        repo_path = os.path.abspath(target)
        from ..detectors import language
        lang_counts, all_files, manifests = language.scan_repo(repo_path)
        attack_surface = [f"Source Files: {len(all_files)}", f"Manifests: {len(manifests)}", f"Languages: {', '.join(language.primary_languages(lang_counts))}"]

        # Level 1: Secrets & Git History
        if level >= 1:
            all_findings.extend(secrets.scan_files(all_files))
            all_findings.extend(secrets.scan_git_history(repo_path, max_commits=50))
        # Level 2, 6, 9: SAST patterns
        if level >= 2:
            all_findings.extend(patterns.scan_files(all_files))
        # Level 8: JWT Checks
        if level >= 8:
            for f in all_files:
                all_findings.extend(jwt_scanner.scan_file_for_jwts(f))
        # Level 10: Dependencies
        if level >= 10:
            all_findings.extend(dependencies.check_manifests(manifests))

    elif target.startswith(("http://", "https://")) or ("://" not in target and "." in target and not os.path.exists(target)):
        target_type = "Live API / Web Endpoint"
        url = target if target.startswith(("http://", "https://")) else "https://" + target
        attack_surface = [f"Base URL: {url}"]

        if level >= 3:
            all_findings.extend(api_security.check_auth_enforcement(url))
        if level >= 4:
            parsed = api_security.urlparse(url)
            if api_security._is_private_or_loopback_host(parsed.hostname):
                all_findings.append({
                    "type": "[Method 4] SSRF / Private Subnet Exposure",
                    "severity": "medium",
                    "target": url,
                    "cwe": "CWE-918",
                    "owasp": "API7:2023-Security Misconfiguration",
                    "cvss": 5.3,
                    "detail": f"Target host '{parsed.hostname}' resolves to loopback/private IP space.",
                    "fix": "Ensure internal endpoints are protected behind zero-trust proxies.",
                })
        if level >= 5:
            all_findings.extend(api_security.check_tls(url))
            all_findings.extend(api_security.check_security_headers(url))
            all_findings.extend(api_security.check_cors(url))
            all_findings.extend(api_security.check_http_methods(url))
        if level >= 7:
            all_findings.extend(api_security.check_information_disclosure(url))

    elif os.path.isfile(target):
        lower = target.lower()
        if lower.endswith((".apk", ".aab")):
            target_type = "Android APK Package"
            attack_surface = [f"APK Archive: {os.path.basename(target)}", f"Size: {os.path.getsize(target)} bytes"]
            all_findings.extend(apk_scanner.scan_apk(target))
        elif lower.endswith((".yaml", ".yml", ".json")) and openapi.parse_spec_file(target):
            target_type = "OpenAPI / Postman Spec"
            parsed = openapi.parse_spec_file(target)
            attack_surface = [f"Spec Type: {parsed.get('spec_type')}", f"Declared Endpoints: {len(parsed.get('endpoints', []))}"]
            if level >= 3:
                all_findings.extend(openapi.audit_spec_statically(parsed))
            if level >= 4 and parsed.get("base_url"):
                all_findings.extend(openapi.probe_spec_endpoints(parsed))
        elif lower.endswith((".txt", ".jwt")) or jwt_scanner.JWT_REGEX.search(target):
            target_type = "JWT Token / Credential File"
            attack_surface = ["JWT Token Container"]
            all_findings.extend(jwt_scanner.scan_file_for_jwts(target))
        else:
            target_type = "Desktop / Native Binary"
            attack_surface = [f"Binary File: {os.path.basename(target)}", f"Size: {os.path.getsize(target)} bytes"]
            all_findings.extend(binary_scanner.scan_binary(target))
    else:
        if jwt_scanner.JWT_REGEX.search(target):
            target_type = "Raw JWT Token String"
            attack_surface = ["Raw Base64 JWT"]
            all_findings.extend(jwt_scanner.analyze_jwt_token(target))

    # Vulnerability Chaining Analysis
    chains = analyze_vulnerability_chains(all_findings)

    return {
        "target": target,
        "target_type": target_type,
        "testing_mode": mode,
        "hacker_level": level,
        "max_level": MAX_HACKER_LEVEL,
        "attack_surface": attack_surface,
        "executed_methods": executed_methods,
        "findings": all_findings,
        "vulnerability_chains": chains,
    }


def write_hacker_report(output_path, test_results):
    """
    Generates an executive Hacker Mode Security Audit Report in Markdown.
    """
    target = test_results["target"]
    target_type = test_results["target_type"]
    level = test_results["hacker_level"]
    mode = test_results.get("testing_mode", "safe")
    executed = test_results["executed_methods"]
    findings = test_results["findings"]
    chains = test_results.get("vulnerability_chains", [])
    surface = test_results.get("attack_surface", [])

    counts = report._count(findings)
    lines = []
    lines.append(f"# 🥷 Hacker Pentest Report — Level {level}/{MAX_HACKER_LEVEL}")
    lines.append("")
    lines.append(f"**Generated:** {datetime.datetime.now().isoformat(timespec='seconds')}")
    lines.append(f"**Target:** `{target}` ({target_type})")
    lines.append(f"**Mode:** `{mode.upper()}` | **Hacker Level:** {level} of {MAX_HACKER_LEVEL}")
    lines.append("")
    
    if surface:
        lines.append("## 🔍 Discovered Attack Surface")
        for s in surface:
            lines.append(f"- {s}")
        lines.append("")

    lines.append("## Executive Pentest Summary")
    lines.append("")
    total = sum(counts.values())
    lines.append(f"Executed **{level} progressive pentest testing method(s)**. Identified **{total} vulnerability finding(s)** and **{len(chains)} chained attack path(s)**.")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|------:|")
    for sev in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {report.SEVERITY_ICON[sev]} {sev.title()} | {counts.get(sev, 0)} |")
    lines.append("")

    if chains:
        lines.append("## ⛓️ Vulnerability Chaining & Critical Attack Paths")
        lines.append("")
        for ch in chains:
            lines.append(f"### 🔴 {ch['title']}")
            lines.append(f"- **Exploit Impact:** {ch['impact']}")
            lines.append(f"- **Attack Steps:**\n```\n{ch['steps']}\n```")
            lines.append(f"- **Recommended Fix:** {ch['remediation']}")
            lines.append("")

    lines.append("## Executed Pentest Testing Methods")
    lines.append("")
    for m in executed:
        lines.append(f"### ⚔️ {m['name']}")
        lines.append(f"- **Category:** `{m['category']}` | **CWE:** `{m.get('cwe', '')}`")
        lines.append(f"- **Method Description:** {m['desc']}")
        lines.append("")

    lines.append("## Detailed Vulnerability Findings & Action Plan to Resolve")
    lines.append("")

    if not findings:
        lines.append("No automated findings were triggered for the executed methods.")
    else:
        for f in report._sorted(findings):
            sev = f.get("severity", "info")
            cwe = f.get("cwe", "CWE-200")
            owasp = f.get("owasp", "A05:2021-Security Misconfiguration")
            cvss = f.get("cvss", report.DEFAULT_CVSS_MAP.get(sev, 0.0))
            lines.append(f"### {report.SEVERITY_ICON[sev]} [{sev.upper()}] {f.get('type')}")
            lines.append("")
            lines.append(f"- **Standards:** `{cwe}` | `{owasp}` | **CVSS:** `{cvss}`")
            loc = f.get("file") or f.get("target") or target
            lines.append(f"- **Location / Endpoint:** `{loc}`" + (f" (line {f['line']})" if f.get("line") else ""))
            if f.get("snippet"):
                snip = str(f["snippet"]).replace("`", "\\`")
                if "\n" in snip:
                    lines.append(f"- **Evidence:**\n```\n{snip}\n```")
                else:
                    lines.append(f"- **Evidence:** `{snip}`")
            if f.get("fix"):
                lines.append(f"- **Action to Resolve:** {f['fix']}")
            lines.append("")

    lines.append("---")
    lines.append("_Generated by Yemanode Hacker Pentest Engine (Level 1-10) — Ethical security assessment only._")

    return report._write(output_path, "\n".join(lines))

