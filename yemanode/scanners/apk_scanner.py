"""
Basic static analysis for Android APK files.
Uses unzip + string/pattern matching (no external APK tooling required).
For deeper analysis install apktool / jadx / MobSF separately.
"""
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

from . import secrets, patterns

MAX_EXTRACT_SIZE = 80 * 1024 * 1024  # 80 MB safety


def _safe_extract(apk_path, dest):
    """Extract APK (zip) with size guard and Zip Slip / Path Traversal protection."""
    dest_path = Path(dest).resolve()
    with zipfile.ZipFile(apk_path, "r") as zf:
        total = sum(i.file_size for i in zf.infolist())
        if total > MAX_EXTRACT_SIZE:
            raise ValueError(f"APK contents too large ({total} bytes) – refusing to extract fully.")
        for member in zf.infolist():
            # Validate target path canonicalization to prevent Zip Slip
            target_path = (dest_path / member.filename).resolve()
            if not str(target_path).startswith(str(dest_path)) and not (str(target_path) + os.sep).startswith(str(dest_path) + os.sep):
                raise ValueError(f"Security Alert: Path traversal detected in ZIP entry '{member.filename}'")
            zf.extract(member, dest_path)


def _find_manifest(root):
    for dirpath, _, files in os.walk(root):
        for f in files:
            if f.lower() == "androidmanifest.xml":
                return os.path.join(dirpath, f)
    return None


def _strings_from_binary(path, min_len=6, max_bytes=50_000_000):
    """Extract printable strings in chunks to prevent memory exhaustion."""
    try:
        if os.path.getsize(path) > max_bytes:
            return []
        result = []
        current = []
        with open(path, "rb") as fh:
            while chunk := fh.read(65536):
                for b in chunk:
                    if 32 <= b < 127:
                        current.append(chr(b))
                    else:
                        if len(current) >= min_len:
                            result.append("".join(current))
                            if len(result) >= 20000:
                                return result
                        current = []
        if len(current) >= min_len:
            result.append("".join(current))
        return result
    except Exception:
        return []


def scan_apk(apk_path: str):
    """
    Returns list of finding dicts (same shape as other scanners).
    """
    findings = []
    apk_path = os.path.abspath(apk_path)
    if not os.path.isfile(apk_path):
        return [{
            "type": "APK file not found",
            "severity": "info",
            "file": apk_path,
            "line": 0,
            "snippet": "",
            "fix": "Provide a valid .apk path.",
        }]

    # 1. Quick strings pass on the APK itself (catches many hardcoded secrets)
    try:
        strs = _strings_from_binary(apk_path)
        # Write to temp file list so we can reuse secrets scanner logic lightly
        for s in strs:
            for name, pattern, severity in secrets.RULES:
                m = pattern.search(s)
                if m and not secrets._is_probably_placeholder(m.group(0)):
                    findings.append({
                        "type": f"[APK strings] {name}",
                        "severity": severity,
                        "file": apk_path,
                        "line": 0,
                        "snippet": s[:180],
                        "fix": secrets._default_fix(name),
                    })
                    break  # one hit per string is enough
    except Exception:
        pass

    # 2. Extract and scan manifest + resources
    tmp = tempfile.mkdtemp(prefix="yemanode_apk_")
    try:
        try:
            _safe_extract(apk_path, tmp)
        except Exception as e:
            findings.append({
                "type": "APK extraction failed",
                "severity": "info",
                "file": apk_path,
                "line": 0,
                "snippet": str(e),
                "fix": "File may be corrupt, encrypted, or not a standard APK.",
            })
            return findings

        # Manifest checks (binary XML is not human readable without aapt/apktool,
        # but we still look for cleartext markers and common bad strings)
        manifest = _find_manifest(tmp)
        if manifest:
            try:
                with open(manifest, "rb") as fh:
                    raw = fh.read()
                # Even binary XML often contains readable attribute values
                text = raw.decode("utf-8", errors="ignore")
                checks = [
                    (r'android:debuggable\s*=\s*["\']?true', "high",
                     "android:debuggable=true", "Never release with debuggable=true."),
                    (r'android:allowBackup\s*=\s*["\']?true', "low",
                     "android:allowBackup=true", "Set allowBackup=false unless required and tested."),
                    (r'usesCleartextTraffic\s*=\s*["\']?true|cleartextTrafficPermitted\s*=\s*["\']?true', "high",
                     "cleartext traffic permitted", "Disable cleartext HTTP; force HTTPS."),
                    (r'android:exported\s*=\s*["\']?true', "medium",
                     "exported=true component", "Review every exported component; require permissions or set exported=false."),
                ]
                for pat, sev, label, fix in checks:
                    if re.search(pat, text, re.I):
                        findings.append({
                            "type": f"[AndroidManifest] {label}",
                            "severity": sev,
                            "file": manifest,
                            "line": 0,
                            "snippet": label,
                            "fix": fix,
                        })
            except Exception:
                pass

        # Scan all extracted text-ish files with secrets + patterns
        text_files = []
        for root, _, files in os.walk(tmp):
            for f in files:
                full = os.path.join(root, f)
                ext = os.path.splitext(f)[1].lower()
                if ext in {".xml", ".json", ".txt", ".properties", ".js", ".html", ".smali", ".java", ".kt"}:
                    text_files.append(full)
                elif f.lower() in ("androidmanifest.xml", "network_security_config.xml"):
                    text_files.append(full)

        findings.extend(secrets.scan_files(text_files))
        findings.extend(patterns.scan_files(text_files))

        # Look for world-readable / insecure shared prefs patterns etc. in smali/resources
        for root, _, files in os.walk(tmp):
            for f in files:
                if f.endswith((".xml", ".smali")):
                    full = os.path.join(root, f)
                    try:
                        with open(full, "r", errors="ignore") as fh:
                            content = fh.read(50_000)
                        if re.search(r"MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE|0x00000001", content):
                            findings.append({
                                "type": "[Android] Insecure file mode (WORLD_READABLE/WRITEABLE)",
                                "severity": "high",
                                "file": full,
                                "line": 0,
                                "snippet": "MODE_WORLD_* detected",
                                "fix": "Use MODE_PRIVATE for SharedPreferences and internal files.",
                            })
                        if re.search(r"http://[^\s\"']+", content) and "localhost" not in content.lower():
                            # only flag if looks like a real endpoint
                            urls = re.findall(r"http://[^\s\"']{10,80}", content)
                            for u in urls[:3]:
                                findings.append({
                                    "type": "[Android] Cleartext HTTP URL found",
                                    "severity": "medium",
                                    "file": full,
                                    "line": 0,
                                    "snippet": u[:120],
                                    "fix": "Use HTTPS only. Configure network security config to block cleartext.",
                                })
                    except Exception:
                        pass

    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # Deduplicate roughly by type+snippet
    seen = set()
    unique = []
    for f in findings:
        key = (f.get("type"), f.get("file"), f.get("snippet", "")[:80])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
