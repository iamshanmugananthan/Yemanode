"""
Professional Security Reporting Module for Yemanode.
Supports CVSS v3.1 estimation, CWE mapping, OWASP Top 10 mapping,
and multi-format export to Markdown (.md), JSON (.json), HTML (.html), and SARIF 2.1.0 (.sarif).
"""
import datetime
import html
import json
import os

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_ICON = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}
SEVERITY_COLOR = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#2563eb",
    "info": "#6b7280",
}
DEFAULT_CVSS_MAP = {
    "critical": 9.8,
    "high": 7.8,
    "medium": 5.5,
    "low": 3.5,
    "info": 0.0,
}


def _sorted(findings):
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 5))


def _count(findings):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _write(path, content):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


def write_json_report(output_path, title, target, findings, metadata=None):
    """Exports findings in standardized JSON schema."""
    counts = _count(findings)
    data = {
        "report_title": title,
        "scanner": "Yemanode v2",
        "timestamp": datetime.datetime.now(tz=datetime.timezone.utc).isoformat(),
        "target": target,
        "summary": {
            "total_findings": len(findings),
            "severity_counts": counts,
        },
        "metadata": metadata or {},
        "findings": [
            {
                "title": f.get("type"),
                "severity": f.get("severity", "info"),
                "cwe": f.get("cwe", "CWE-200"),
                "owasp": f.get("owasp", "A05:2021-Security Misconfiguration"),
                "cvss_score": f.get("cvss", DEFAULT_CVSS_MAP.get(f.get("severity", "info"), 0.0)),
                "location": {
                    "file": f.get("file") or f.get("target") or target,
                    "line": f.get("line", 0),
                },
                "evidence": f.get("snippet", ""),
                "detail": f.get("detail", ""),
                "remediation": f.get("fix", ""),
            }
            for f in _sorted(findings)
        ],
    }
    return _write(output_path, json.dumps(data, indent=2))


def write_sarif_report(output_path, title, target, findings):
    """Exports findings to OASIS SARIF v2.1.0 standard format for GitHub Code Scanning / IDEs."""
    sarif_rules = {}
    sarif_results = []

    for idx, f in enumerate(_sorted(findings)):
        rule_id = f.get("cwe") or f"YM-{(f.get('type') or 'RULE')[:20].replace(' ', '_').upper()}"
        rule_name = f.get("type", "Security Finding")
        sev = f.get("severity", "info").lower()
        
        # SARIF level mapping
        level_map = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note",
        }

        if rule_id not in sarif_rules:
            sarif_rules[rule_id] = {
                "id": rule_id,
                "name": rule_name,
                "shortDescription": {"text": rule_name},
                "help": {"text": f.get("fix", "Review finding and apply recommended security fix.")},
                "properties": {
                    "tags": ["security", sev, f.get("owasp", "")],
                    "precision": "high",
                }
            }

        file_path = f.get("file") or target
        line_no = max(1, f.get("line", 1))

        sarif_results.append({
            "ruleId": rule_id,
            "level": level_map.get(sev, "warning"),
            "message": {"text": f"{rule_name} — {f.get('fix', '')}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": file_path.replace(os.getcwd() + "/", "")},
                    "region": {
                        "startLine": line_no,
                        "startColumn": 1,
                        "snippet": {"text": f.get("snippet", "")}
                    }
                }
            }]
        })

    sarif_log = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Yemanode",
                    "version": "2.0.0",
                    "informationUri": "https://github.com/iamshanmugananthan/Yemanode",
                    "rules": list(sarif_rules.values()),
                }
            },
            "results": sarif_results,
        }]
    }

    return _write(output_path, json.dumps(sarif_log, indent=2))


def write_html_report(output_path, title, target, findings, metadata=None):
    """Generates a responsive executive HTML security report with interactive UI badges."""
    counts = _count(findings)
    total = len(findings)
    crit_high = counts["critical"] + counts["high"]

    cards_html = ""
    for sev in ("critical", "high", "medium", "low", "info"):
        color = SEVERITY_COLOR[sev]
        cards_html += f"""
        <div class="metric-card" style="border-top: 4px solid {color};">
            <div class="metric-title">{SEVERITY_ICON[sev]} {sev.upper()}</div>
            <div class="metric-value" style="color: {color};">{counts.get(sev, 0)}</div>
        </div>
        """

    findings_html = ""
    for idx, f in enumerate(_sorted(findings), start=1):
        sev = f.get("severity", "info").lower()
        color = SEVERITY_COLOR.get(sev, "#6b7280")
        loc = f.get("file") or f.get("target") or target
        line = f.get("line", 0)
        cwe = f.get("cwe", "CWE-200")
        owasp = f.get("owasp", "A05:2021-Security Misconfiguration")
        cvss = f.get("cvss", DEFAULT_CVSS_MAP.get(sev, 0.0))
        snip = html.escape(str(f.get("snippet", "")))
        fix = html.escape(str(f.get("fix", "")))
        detail = html.escape(str(f.get("detail", "")))

        findings_html += f"""
        <div class="finding-card">
            <div class="finding-header">
                <span class="badge" style="background-color: {color};">{sev.upper()}</span>
                <span class="finding-title">#{idx} {html.escape(f.get("type", "Security Finding"))}</span>
                <span class="meta-tag">CVSS {cvss}</span>
                <span class="meta-tag">{cwe}</span>
                <span class="meta-tag">{owasp}</span>
            </div>
            <div class="finding-body">
                <p><strong>📍 Target / Location:</strong> <code>{html.escape(loc)}</code> {f"(line {line})" if line else ""}</p>
                {f"<p><strong>📝 Detail:</strong> {detail}</p>" if detail else ""}
                {f"<div class='snippet-box'><strong>🔍 Evidence:</strong><pre><code>{snip}</code></pre></div>" if snip else ""}
                {f"<div class='fix-box'><strong>🔧 Recommended Fix:</strong> {fix}</div>" if fix else ""}
            </div>
        </div>
        """

    if not findings_html:
        findings_html = "<div class='finding-card'><p>🎉 No security vulnerabilities detected by automated static rules.</p></div>"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{html.escape(title)}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 24px; line-height: 1.6; }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        .header {{ background: #1e293b; padding: 24px; border-radius: 12px; margin-bottom: 24px; border: 1px solid #334155; }}
        h1 {{ margin: 0 0 8px 0; color: #38bdf8; font-size: 28px; }}
        .meta {{ color: #94a3b8; font-size: 14px; margin-bottom: 16px; }}
        .metrics-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }}
        .metric-card {{ background: #1e293b; padding: 16px; border-radius: 8px; text-align: center; border: 1px solid #334155; }}
        .metric-title {{ font-size: 13px; font-weight: 600; color: #94a3b8; margin-bottom: 4px; }}
        .metric-value {{ font-size: 32px; font-weight: bold; }}
        .finding-card {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; margin-bottom: 16px; overflow: hidden; }}
        .finding-header {{ background: #0f172a; padding: 12px 16px; border-bottom: 1px solid #334155; display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
        .badge {{ color: white; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; text-transform: uppercase; }}
        .meta-tag {{ background: #334155; color: #cbd5e1; padding: 2px 6px; border-radius: 4px; font-size: 11px; }}
        .finding-title {{ font-weight: bold; color: #f8fafc; font-size: 15px; flex-grow: 1; }}
        .finding-body {{ padding: 16px; }}
        .snippet-box {{ background: #020617; padding: 12px; border-radius: 6px; margin: 12px 0; border: 1px solid #1e293b; }}
        pre {{ margin: 6px 0 0 0; white-space: pre-wrap; word-break: break-all; color: #f43f5e; font-family: monospace; font-size: 13px; }}
        .fix-box {{ background: #064e3b; color: #a7f3d0; padding: 12px; border-radius: 6px; margin-top: 12px; border: 1px solid #047857; font-size: 14px; }}
        code {{ background: #334155; padding: 2px 6px; border-radius: 4px; font-size: 13px; color: #38bdf8; }}
        footer {{ text-align: center; color: #64748b; font-size: 12px; margin-top: 40px; padding: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ {html.escape(title)}</h1>
            <div class="meta">
                <span>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</span> • 
                <span>Target: <code>{html.escape(target)}</code></span>
            </div>
            <p>Automated security analysis identified <strong>{total} finding(s)</strong>, with <strong>{crit_high} Critical/High</strong> priority items requiring immediate remediation.</p>
        </div>

        <div class="metrics-grid">
            {cards_html}
        </div>

        <h2>Detailed Vulnerability Findings</h2>
        {findings_html}

        <footer>
            Generated by <strong>Yemanode v2 — Multi-Target Ethical Security Scanner</strong>
        </footer>
    </div>
</body>
</html>"""
    return _write(output_path, html_content)


def write_code_report(output_path, repo_path, languages, project_type,
                      secret_findings, pattern_findings, dep_findings):
    all_findings = secret_findings + pattern_findings + dep_findings
    counts = _count(all_findings)

    lines = []
    lines.append(f"# Security Audit Report — `{os.path.basename(repo_path.rstrip('/'))}`")
    lines.append("")
    lines.append(f"**Generated:** {datetime.datetime.now().isoformat(timespec='seconds')}")
    lines.append(f"**Target path:** `{repo_path}`")
    lines.append(f"**Project type:** {project_type}")
    lines.append(f"**Languages detected:** {', '.join(languages) if languages else 'none detected'}")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    total = sum(counts.values())
    crit_high = counts["critical"] + counts["high"]
    if total == 0:
        lines.append("No issues were flagged by the automated static checks.")
    else:
        lines.append(
            f"Automated analysis found **{total} finding(s)**, of which "
            f"**{crit_high}** are Critical or High severity. "
            "Address Critical/High items first."
        )
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|------:|")
    for sev in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {SEVERITY_ICON[sev]} {sev.title()} | {counts.get(sev, 0)} |")
    lines.append("")

    lines.append("## Recommended Priority Order")
    lines.append("")
    lines.append("1. **Rotate & remove any leaked secrets** (AWS keys, tokens, private keys, DB passwords).")
    lines.append("2. **Fix injection & RCE patterns** (SQL injection, command injection, insecure deserialization, eval).")
    lines.append("3. **Harden authentication / authorization** and remove debug flags.")
    lines.append("4. **Update vulnerable dependencies**.")
    lines.append("5. **Apply remaining medium/low hardening** (headers, CORS, crypto, etc.).")
    lines.append("")

    if not all_findings:
        lines.append("No automated findings. Pair with manual review, dependency updates, and penetration testing.")
    else:
        lines.append("## Detailed Findings")
        lines.append("")
        for f in _sorted(all_findings):
            sev = f.get("severity", "info")
            cwe = f.get("cwe", "CWE-200")
            owasp = f.get("owasp", "A05:2021-Security Misconfiguration")
            cvss = f.get("cvss", DEFAULT_CVSS_MAP.get(sev, 0.0))
            lines.append(f"### {SEVERITY_ICON[sev]} [{sev.upper()}] {f['type']}")
            lines.append("")
            lines.append(f"- **Standards Mapping:** `{cwe}` | `{owasp}` | **CVSS v3.1:** `{cvss}`")
            loc = f.get("file", "")
            line_no = f.get("line", 0)
            if loc:
                rel = loc
                try:
                    rel = os.path.relpath(loc, repo_path)
                except ValueError:
                    pass
                lines.append(f"- **Location:** `{rel}`" + (f" (line {line_no})" if line_no else ""))
            if f.get("snippet"):
                snip = str(f["snippet"]).replace("`", "\\`")
                if "\n" in snip:
                    lines.append(f"- **Evidence:**\n```\n{snip}\n```")
                else:
                    lines.append(f"- **Evidence:** `{snip}`")
            if f.get("fix"):
                lines.append(f"- **Recommended fix:** {f['fix']}")
            lines.append("")

    lines.append("---")
    lines.append("_Generated by Yemanode v2 — ethical, non-destructive security scanner._")

    return _write(output_path, "\n".join(lines))


def write_api_report(output_path, url, findings):
    counts = _count(findings)
    lines = []
    lines.append(f"# API Security Report — `{url}`")
    lines.append("")
    lines.append(f"**Generated:** {datetime.datetime.now().isoformat(timespec='seconds')}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|------:|")
    for sev in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {SEVERITY_ICON[sev]} {sev.title()} | {counts.get(sev, 0)} |")
    lines.append("")

    if not findings:
        lines.append("No issues found by the automated passive checks.")
    else:
        lines.append("## Findings")
        lines.append("")
        for f in _sorted(findings):
            sev = f.get("severity", "info")
            cwe = f.get("cwe", "CWE-200")
            owasp = f.get("owasp", "API7:2023-Security Misconfiguration")
            cvss = f.get("cvss", DEFAULT_CVSS_MAP.get(sev, 0.0))
            lines.append(f"### {SEVERITY_ICON[sev]} [{sev.upper()}] {f['type']}")
            lines.append("")
            lines.append(f"- **Standards:** `{cwe}` | `{owasp}` | **CVSS:** `{cvss}`")
            if f.get("detail"):
                lines.append(f"- **Detail:** {f['detail']}")
            if f.get("target") and f.get("target") != url:
                lines.append(f"- **Target:** `{f['target']}`")
            if f.get("fix"):
                lines.append(f"- **Recommended fix:** {f['fix']}")
            lines.append("")

    lines.append("---")
    lines.append("_Generated by Yemanode v2._")
    return _write(output_path, "\n".join(lines))


def write_generic_report(output_path, title, target_desc, findings, extra_notes=None):
    """Used for APK, binary, and JWT scans."""
    counts = _count(findings)
    lines = []
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"**Generated:** {datetime.datetime.now().isoformat(timespec='seconds')}")
    lines.append(f"**Target:** `{target_desc}`")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|------:|")
    for sev in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {SEVERITY_ICON[sev]} {sev.title()} | {counts.get(sev, 0)} |")
    lines.append("")

    if not findings:
        lines.append("No issues found by the automated static checks.")
    else:
        lines.append("## Findings")
        lines.append("")
        for f in _sorted(findings):
            sev = f.get("severity", "info")
            cwe = f.get("cwe", "CWE-200")
            owasp = f.get("owasp", "A05:2021-Security Misconfiguration")
            cvss = f.get("cvss", DEFAULT_CVSS_MAP.get(sev, 0.0))
            lines.append(f"### {SEVERITY_ICON[sev]} [{sev.upper()}] {f['type']}")
            lines.append("")
            lines.append(f"- **Standards:** `{cwe}` | `{owasp}` | **CVSS:** `{cvss}`")
            if f.get("file"):
                lines.append(f"- **Location:** `{f['file']}`" + (f" (line {f['line']})" if f.get("line") else ""))
            if f.get("snippet"):
                snip = str(f["snippet"]).replace("`", "\\`")
                if "\n" in snip:
                    lines.append(f"- **Evidence:**\n```\n{snip}\n```")
                else:
                    lines.append(f"- **Evidence:** `{snip}`")
            if f.get("fix"):
                lines.append(f"- **Recommended fix:** {f['fix']}")
            lines.append("")

    if extra_notes:
        lines.append("## Notes")
        lines.append("")
        for n in extra_notes:
            lines.append(f"- {n}")
        lines.append("")

    lines.append("---")
    lines.append("_Generated by Yemanode v2 — ethical, non-destructive security scanner._")
    return _write(output_path, "\n".join(lines))


def export_multi_format(base_output_path, title, target, findings, formats=("md", "json", "html", "sarif")):
    """Helper to export to multiple formats simultaneously if requested."""
    results = {}
    base_no_ext = os.path.splitext(base_output_path)[0]
    for fmt in formats:
        fmt = fmt.lower().strip()
        if fmt == "md" or fmt == "markdown":
            path = base_no_ext + ".md"
            write_generic_report(path, title, target, findings)
            results["md"] = path
        elif fmt == "json":
            path = base_no_ext + ".json"
            write_json_report(path, title, target, findings)
            results["json"] = path
        elif fmt == "html":
            path = base_no_ext + ".html"
            write_html_report(path, title, target, findings)
            results["html"] = path
        elif fmt == "sarif":
            path = base_no_ext + ".sarif"
            write_sarif_report(path, title, target, findings)
            results["sarif"] = path
    return results
