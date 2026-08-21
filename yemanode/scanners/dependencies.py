"""
Dependency vulnerability checking. Wraps pip-audit / npm audit when available.
Also notes other manifests for manual follow-up.
"""
import json
import os
import shutil
import subprocess


def _run(cmd, cwd):
    try:
        result = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, timeout=180
        )
        return result.stdout
    except Exception:
        return None


def check_python(manifest_path):
    findings = []
    if shutil.which("pip-audit") is None:
        findings.append({
            "type": "Tool Not Available (pip-audit)",
            "severity": "info",
            "file": manifest_path,
            "line": 0,
            "snippet": "pip-audit not installed",
            "fix": "Install with `pip install pip-audit` and re-run to check Python deps against OSV/PyPI advisories.",
        })
        return findings

    out = _run(["pip-audit", "-r", manifest_path, "-f", "json"], os.path.dirname(manifest_path) or ".")
    if not out:
        return findings
    try:
        data = json.loads(out)
    except Exception:
        return findings

    items = data.get("dependencies", data if isinstance(data, list) else [])
    for dep in items:
        vulns = dep.get("vulns", []) if isinstance(dep, dict) else []
        for v in vulns:
            findings.append({
                "type": f"Vulnerable dependency: {dep.get('name')} {dep.get('version')}",
                "severity": "high",
                "file": manifest_path,
                "line": 0,
                "snippet": v.get("id", "") or str(v)[:120],
                "fix": f"Upgrade {dep.get('name')} to a patched version (fix versions: "
                       f"{', '.join(v.get('fix_versions', []) or ['see advisory'])}).",
            })
    return findings


def check_npm(manifest_path):
    findings = []
    if shutil.which("npm") is None:
        findings.append({
            "type": "Tool Not Available (npm)",
            "severity": "info",
            "file": manifest_path,
            "line": 0,
            "snippet": "npm not installed",
            "fix": "Install Node.js/npm and run `npm audit` in the project directory.",
        })
        return findings

    out = _run(["npm", "audit", "--json"], os.path.dirname(manifest_path) or ".")
    if not out:
        return findings
    try:
        data = json.loads(out)
    except Exception:
        return findings

    vulns = data.get("vulnerabilities", {})
    for name, info in vulns.items():
        severity = info.get("severity", "medium")
        if severity not in ("critical", "high", "medium", "low", "info"):
            severity = "medium"
        findings.append({
            "type": f"Vulnerable dependency: {name}",
            "severity": severity,
            "file": manifest_path,
            "line": 0,
            "snippet": str(info.get("via", ""))[:160],
            "fix": f"Run `npm audit fix` or upgrade `{name}` manually according to the advisory.",
        })
    return findings


def check_manifests(manifest_files):
    findings = []
    seen = set()
    for m in manifest_files:
        base = os.path.basename(m).lower()
        if base in seen:
            continue
        seen.add(base)
        if base in ("requirements.txt",):
            findings.extend(check_python(m))
        elif base == "package.json":
            findings.extend(check_npm(m))
        elif base in ("pom.xml", "build.gradle", "build.gradle.kts", "go.mod",
                      "cargo.toml", "gemfile", "composer.json", "pubspec.yaml"):
            findings.append({
                "type": f"Manifest detected: {base} (manual check recommended)",
                "severity": "info",
                "file": m,
                "line": 0,
                "snippet": base,
                "fix": (f"Run the ecosystem-native audit tool for {base} "
                        "(e.g. `mvn dependency-check`, `./gradlew dependencyCheckAnalyze`, "
                        "`govulncheck`, `cargo audit`, `bundle audit`, `composer audit`)."),
            })
    return findings
