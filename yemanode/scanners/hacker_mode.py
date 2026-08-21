"""
Hacker Pentest Engine for Yemanode.
Executes progressive offensive security methods (Levels 1 to 10) against targets
(source repositories, API URLs, OpenAPI specs, APKs, JWTs, or native binaries).
"""
import os
import sys
import datetime

from . import secrets, patterns, dependencies, api_security, apk_scanner, binary_scanner, openapi, jwt_scanner
from .. import report

MAX_HACKER_LEVEL = 10

HACKER_METHODS = {
    1: {
        "name": "Method 1: Hardcoded Secrets & Credential Mining",
        "desc": "Scans for AWS/Azure/GCP keys, private PEM blocks, Slack/GitHub tokens, and connection strings.",
        "category": "Credentials & Secrets",
    },
    2: {
        "name": "Method 2: Code Injection & Remote Code Execution (RCE)",
        "desc": "Audits SQLi, NoSQLi, OS Command Injection, eval()/exec() usage, and SSTI.",
        "category": "Injection & RCE",
    },
    3: {
        "name": "Method 3: Broken Access Control & Auth Enforcement",
        "desc": "Probes for missing authorization, unauthenticated state-changing HTTP verbs, and IDOR risks.",
        "category": "Authentication & Authorization",
    },
    4: {
        "name": "Method 4: SSRF & Internal Network Exposure Probe",
        "desc": "Probes for Server-Side Request Forgery, cloud metadata (169.254.169.254), and loopback resolution.",
        "category": "SSRF & Network Boundary",
    },
    5: {
        "name": "Method 5: Transport Layer Security & Header Hardening",
        "desc": "Validates TLS versions, SSL certificate trust, HSTS, CSP, CORS reflection, and security headers.",
        "category": "Transport & Cryptography",
    },
    6: {
        "name": "Method 6: Insecure Deserialization & XXE Probe",
        "desc": "Checks for pickle/unserialize/BinaryFormatter flaws and XML external entity resolution.",
        "category": "Deserialization & XML",
    },
    7: {
        "name": "Method 7: Information Disclosure & Path Enumeration",
        "desc": "Probes for exposed /.env, /.git, /swagger.json, /actuator, and verbose error stack traces.",
        "category": "Information Disclosure",
    },
    8: {
        "name": "Method 8: Data Protection & Token Security Audit",
        "desc": "Audits JWT unsigned tokens (alg: none), weak HMAC keys, MD5/SHA1 hashing, and PII leakage.",
        "category": "Token & Cryptographic Controls",
    },
    9: {
        "name": "Method 9: Infrastructure as Code & Container Hardening",
        "desc": "Audits Terraform 0.0.0.0/0 rules, Dockerfile root privileges, and build ARG secrets.",
        "category": "IaC & Container Security",
    },
    10: {
        "name": "Method 10: Supply Chain & Vulnerable Dependency Audit",
        "desc": "Wraps ecosystem audit tools (pip-audit, npm audit) to detect known CVEs in dependencies.",
        "category": "Supply Chain & Dependencies",
    },
}


def run_hacker_test(target: str, level: int = 5):
    """
    Executes progressive security testing methods up to `level` (1 to MAX_HACKER_LEVEL)
    against the specified target. Returns structured results including executed methods and findings.
    """
    # Enforce maximum level limit
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

    # Target Auto-Detection & Testing Execution
    if os.path.isdir(target):
        target_type = "Local Source Repository"
        repo_path = os.path.abspath(target)
        lang_counts, all_files, manifests = patterns.os.walk, [], []
        from ..detectors import language
        lang_counts, all_files, manifests = language.scan_repo(repo_path)

        # Method 1: Secrets
        if level >= 1:
            all_findings.extend(secrets.scan_files(all_files))
        # Method 2, 6, 8, 9: Pattern checks
        if level >= 2:
            all_findings.extend(patterns.scan_files(all_files))
        # Method 8: JWT Checks
        if level >= 8:
            for f in all_files:
                all_findings.extend(jwt_scanner.scan_file_for_jwts(f))
        # Method 10: Dependencies
        if level >= 10:
            all_findings.extend(dependencies.check_manifests(manifests))

    elif target.startswith(("http://", "https://")) or ("://" not in target and "." in target and not os.path.exists(target)):
        target_type = "Live API / Web Endpoint"
        url = target if target.startswith(("http://", "https://")) else "https://" + target

        if level >= 3:
            all_findings.extend(api_security.check_auth_enforcement(url))
        if level >= 4:
            parsed = api_security.urlparse(url)
            if api_security._is_private_or_loopback_host(parsed.hostname):
                all_findings.append({
                    "type": "[Method 4] SSRF / Private Subnet Exposure",
                    "severity": "medium",
                    "target": url,
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
            all_findings.extend(apk_scanner.scan_apk(target))
        elif lower.endswith((".yaml", ".yml", ".json")) and openapi.parse_spec_file(target):
            target_type = "OpenAPI / Postman Spec"
            parsed = openapi.parse_spec_file(target)
            if level >= 3:
                all_findings.extend(openapi.audit_spec_statically(parsed))
            if level >= 4 and parsed.get("base_url"):
                all_findings.extend(openapi.probe_spec_endpoints(parsed))
        elif lower.endswith((".txt", ".jwt")) or jwt_scanner.JWT_REGEX.search(target):
            target_type = "JWT Token / Credential File"
            all_findings.extend(jwt_scanner.scan_file_for_jwts(target))
        else:
            target_type = "Desktop / Native Binary"
            all_findings.extend(binary_scanner.scan_binary(target))
    else:
        # String JWT token
        if jwt_scanner.JWT_REGEX.search(target):
            target_type = "Raw JWT Token String"
            all_findings.extend(jwt_scanner.analyze_jwt_token(target))

    # Filter findings based on hacker level
    # Higher levels unlock deeper severity findings
    return {
        "target": target,
        "target_type": target_type,
        "hacker_level": level,
        "max_level": MAX_HACKER_LEVEL,
        "executed_methods": executed_methods,
        "findings": all_findings,
    }


def write_hacker_report(output_path, test_results):
    """
    Generates an executive Hacker Mode Security Audit Report.
    """
    target = test_results["target"]
    target_type = test_results["target_type"]
    level = test_results["hacker_level"]
    executed = test_results["executed_methods"]
    findings = test_results["findings"]

    counts = report._count(findings)
    lines = []
    lines.append(f"# 🥷 Hacker Pentest Report — Level {level}/{MAX_HACKER_LEVEL}")
    lines.append("")
    lines.append(f"**Generated:** {datetime.datetime.now().isoformat(timespec='seconds')}")
    lines.append(f"**Target:** `{target}` ({target_type})")
    lines.append(f"**Hacker Attack Level:** {level} of {MAX_HACKER_LEVEL} max methods executed")
    lines.append("")
    lines.append("## Executive Pentest Summary")
    lines.append("")
    total = sum(counts.values())
    lines.append(f"Executed **{level} progressive pentest testing method(s)** against target. Identified **{total} vulnerability finding(s)**.")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|------:|")
    for sev in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {report.SEVERITY_ICON[sev]} {sev.title()} | {counts.get(sev, 0)} |")
    lines.append("")

    lines.append("## Executed Pentest Testing Methods")
    lines.append("")
    for m in executed:
        lines.append(f"### ⚔️ {m['name']}")
        lines.append(f"- **Category:** `{m['category']}`")
        lines.append(f"- **Method Description:** {m['desc']}")
        lines.append("")

    lines.append("## Detailed Vulnerability Findings & Action Plan to Resolve")
    lines.append("")

    if not findings:
        lines.append("No automated findings were triggered for the executed methods.")
    else:
        for f in report._sorted(findings):
            sev = f.get("severity", "info")
            lines.append(f"### {report.SEVERITY_ICON[sev]} [{sev.upper()}] {f.get('type')}")
            lines.append("")
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

    return report._write(output_path, lines)
