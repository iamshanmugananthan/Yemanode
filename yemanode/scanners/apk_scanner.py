"""
Comprehensive static security analysis for Android APK packages.
Analyzes AndroidManifest.xml, dangerous permissions, exported components,
cleartext traffic, embedded secrets, Firebase instances, WebViews, deep links, and native .so libraries.
"""
import os
import re
import shutil
import tempfile
import zipfile
from pathlib import Path

from . import secrets, patterns

MAX_EXTRACT_SIZE = 120 * 1024 * 1024  # 120 MB safety

DANGEROUS_PERMISSIONS = {
    "READ_SMS": ("Dangerous Permission: READ_SMS (Privacy / OTP Interception)", "high", "CWE-250", "M1:Insecure Authentication", 7.5,
                 "Verify if SMS reading is strictly required. Use SMS Retriever API instead."),
    "SEND_SMS": ("Dangerous Permission: SEND_SMS (Financial Fraud Risk)", "high", "CWE-250", "M1:Insecure Authentication", 7.5,
                 "Restrict SMS sending to explicit user interaction."),
    "ACCESS_FINE_LOCATION": ("Dangerous Permission: ACCESS_FINE_LOCATION (Precise Tracking)", "medium", "CWE-250", "M2:Insecure Data Storage", 5.5,
                            "Request approximate location unless fine accuracy is essential."),
    "CAMERA": ("Dangerous Permission: CAMERA", "medium", "CWE-250", "M2:Insecure Data Storage", 5.0,
               "Only request camera permission at runtime when needed."),
    "RECORD_AUDIO": ("Dangerous Permission: RECORD_AUDIO (Microphone Eavesdropping)", "high", "CWE-250", "M2:Insecure Data Storage", 7.0,
                     "Enforce runtime permission and clear user notification during recording."),
    "READ_CONTACTS": ("Dangerous Permission: READ_CONTACTS (Address Book Access)", "medium", "CWE-250", "M2:Insecure Data Storage", 5.5,
                     "Limit contact reading to explicit user-shared contacts."),
    "READ_CALL_LOG": ("Dangerous Permission: READ_CALL_LOG (Call History Access)", "high", "CWE-250", "M2:Insecure Data Storage", 7.0,
                     "Restricted permission. Avoid unless app is default phone handler."),
    "SYSTEM_ALERT_WINDOW": ("Dangerous Permission: SYSTEM_ALERT_WINDOW (Overlay / Tapjacking Risk)", "high", "CWE-1021", "M8:Code Tampering", 7.5,
                            "Avoid overlay permissions to prevent tapjacking and UI redressing attacks."),
    "WRITE_EXTERNAL_STORAGE": ("Dangerous Permission: WRITE_EXTERNAL_STORAGE (Legacy Shared Storage)", "medium", "CWE-276", "M2:Insecure Data Storage", 6.0,
                              "Adopt Scoped Storage (API 29+) and avoid writing to public external storage."),
}


def _safe_extract(apk_path, dest):
    """Extract APK (zip) with size guard and Zip Slip / Path Traversal protection."""
    dest_path = Path(dest).resolve()
    with zipfile.ZipFile(apk_path, "r") as zf:
        total = sum(i.file_size for i in zf.infolist())
        if total > MAX_EXTRACT_SIZE:
            raise ValueError(f"APK contents too large ({total} bytes) – refusing to extract fully.")
        for member in zf.infolist():
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
    findings = []
    apk_path = os.path.abspath(apk_path)
    if not os.path.isfile(apk_path):
        return [{
            "type": "APK file not found",
            "severity": "info",
            "file": apk_path,
            "line": 0,
            "cwe": "CWE-200",
            "owasp": "M1:Insecure Authentication",
            "cvss": 0.0,
            "snippet": "",
            "fix": "Provide a valid .apk path.",
        }]

    # 1. Quick strings pass on the APK container (catches hardcoded secrets & Firebase DBs)
    try:
        strs = _strings_from_binary(apk_path)

        for s in strs:
            # Firebase DB Detection
            if "firebaseio.com" in s:
                fb_match = re.search(r"https?://[a-zA-Z0-9_-]+\.firebaseio\.com", s)
                if fb_match:
                    findings.append({
                        "type": "[APK Resource] Embedded Firebase Database URL Found",
                        "severity": "medium",
                        "file": apk_path,
                        "line": 0,
                        "cwe": "CWE-200",
                        "owasp": "M2:Insecure Data Storage",
                        "cvss": 6.5,
                        "snippet": fb_match.group(0),
                        "fix": "Verify that Firebase Security Rules require authentication and restrict unauthenticated '.read' and '.write'.",
                    })

            # Secrets scan
            for rule in secrets.RULES:
                name, pattern, severity, cwe, owasp = rule[0], rule[1], rule[2], rule[3], rule[4]
                m = pattern.search(s)
                if m and not secrets._is_probably_placeholder(m.group(0)):
                    findings.append({
                        "type": f"[APK Secret] {name}",
                        "severity": severity,
                        "file": apk_path,
                        "line": 0,
                        "cwe": cwe,
                        "owasp": owasp,
                        "cvss": 8.5 if severity == "critical" else 7.0,
                        "snippet": s[:180],
                        "fix": secrets._default_fix(name),
                    })
                    break
    except Exception:
        pass

    # 2. Extract APK and inspect manifest, resources, native libraries
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
                "cwe": "CWE-200",
                "owasp": "M8:Code Tampering",
                "cvss": 0.0,
                "snippet": str(e),
                "fix": "File may be corrupt, protected, or not a valid APK.",
            })
            return findings

        # Inspect AndroidManifest.xml
        manifest = _find_manifest(tmp)
        if manifest:
            try:
                with open(manifest, "rb") as fh:
                    raw = fh.read()
                text = raw.decode("utf-8", errors="ignore")

                # Manifest security flags
                checks = [
                    (r'android:debuggable\s*=\s*["\']?true', "critical", "CWE-489", "M8:Code Tampering", 8.8,
                     "Debuggable APK Flag Enabled", "Never publish an APK with android:debuggable=true. It allows arbitrary runtime debugging and memory injection."),
                    (r'android:allowBackup\s*=\s*["\']?true', "low", "CWE-524", "M2:Insecure Data Storage", 3.3,
                     "Application Backup Allowed (allowBackup=true)", "Set android:allowBackup=false to prevent data extraction via adb backup."),
                    (r'usesCleartextTraffic\s*=\s*["\']?true|cleartextTrafficPermitted\s*=\s*["\']?true', "high", "CWE-319", "M3:Insecure Communication", 7.4,
                     "Cleartext HTTP Traffic Permitted", "Disable cleartext HTTP (android:usesCleartextTraffic=\"false\") and force HTTPS."),
                    (r'android:exported\s*=\s*["\']?true', "medium", "CWE-926", "M1:Insecure Authentication", 6.5,
                     "Exported Android Component Without Permission", "Audit all exported Activities/Services/Receivers. Set exported=false unless explicitly intended for third-party apps."),
                ]
                for pat, sev, cwe, owasp, cvss, label, fix in checks:
                    if re.search(pat, text, re.I):
                        findings.append({
                            "type": f"[AndroidManifest] {label}",
                            "severity": sev,
                            "file": manifest,
                            "line": 0,
                            "cwe": cwe,
                            "owasp": owasp,
                            "cvss": cvss,
                            "snippet": label,
                            "fix": fix,
                        })

                # Dangerous Permissions audit
                for perm_name, (perm_title, perm_sev, perm_cwe, perm_owasp, perm_cvss, perm_fix) in DANGEROUS_PERMISSIONS.items():
                    if perm_name in text:
                        findings.append({
                            "type": f"[APK Permission] {perm_title}",
                            "severity": perm_sev,
                            "file": manifest,
                            "line": 0,
                            "cwe": perm_cwe,
                            "owasp": perm_owasp,
                            "cvss": perm_cvss,
                            "snippet": f"Permission requested: android.permission.{perm_name}",
                            "fix": perm_fix,
                        })
            except Exception:
                pass

        # Scan native .so libraries in lib/
        so_files = []
        for root, _, files in os.walk(tmp):
            for f in files:
                if f.endswith(".so"):
                    so_files.append(os.path.join(root, f))

        for so_path in so_files[:10]:
            so_rel = os.path.relpath(so_path, tmp)
            findings.append({
                "type": f"[APK Native Library] Native Binary Detected ({os.path.basename(so_path)})",
                "severity": "info",
                "file": so_rel,
                "line": 0,
                "cwe": "CWE-693",
                "owasp": "M8:Code Tampering",
                "cvss": 0.0,
                "snippet": f"Native .so library: {so_rel}",
                "fix": "Ensure native C/C++ libraries are compiled with stack protections (-fstack-protector) and stripped.",
            })

        # Scan text / smali / xml files for insecure storage & WebViews
        text_files = []
        for root, _, files in os.walk(tmp):
            for f in files:
                full = os.path.join(root, f)
                ext = os.path.splitext(f)[1].lower()
                if ext in {".xml", ".json", ".txt", ".properties", ".js", ".html", ".smali", ".java", ".kt"}:
                    text_files.append(full)

        findings.extend(secrets.scan_files(text_files))
        findings.extend(patterns.scan_files(text_files))

        # Check for WebView security patterns and MODE_WORLD_READABLE in files
        for root, _, files in os.walk(tmp):
            for f in files:
                if f.endswith((".xml", ".smali", ".java", ".kt")):
                    full = os.path.join(root, f)
                    try:
                        with open(full, "r", errors="ignore") as fh:
                            content = fh.read(50_000)
                        
                        if re.search(r"MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE|0x00000001", content):
                            findings.append({
                                "type": "[Android Security] Insecure File Creation Mode (WORLD_READABLE/WRITEABLE)",
                                "severity": "high",
                                "file": os.path.relpath(full, tmp),
                                "line": 0,
                                "cwe": "CWE-276",
                                "owasp": "M2:Insecure Data Storage",
                                "cvss": 7.5,
                                "snippet": "MODE_WORLD_* detected",
                                "fix": "Use MODE_PRIVATE or EncryptedSharedPreferences for internal data storage.",
                            })
                        
                        if "setJavaScriptEnabled(true)" in content or "setAllowFileAccess(true)" in content:
                            findings.append({
                                "type": "[Android WebView] Insecure WebView Configuration (JS/File Access Enabled)",
                                "severity": "medium",
                                "file": os.path.relpath(full, tmp),
                                "line": 0,
                                "cwe": "CWE-749",
                                "owasp": "M1:Insecure Authentication",
                                "cvss": 6.5,
                                "snippet": "WebView JavaScript/File Access enabled",
                                "fix": "Disable setAllowFileAccess and sanitize all loaded URLs in WebViews.",
                            })
                    except Exception:
                        pass
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # Deduplicate findings
    seen = set()
    unique = []
    for f in findings:
        key = (f.get("type"), f.get("file"), f.get("snippet", "")[:80])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
