"""
Lightweight static analysis for desktop / native binaries (ELF, PE, Mach-O, generic).
Extracts strings and runs secret + basic pattern rules. Not a full reverse-engineering suite.
"""
import os
import re
import subprocess
import shutil

from . import secrets

# Common interesting patterns in binaries
BINARY_PATTERNS = [
    ("Hardcoded private key / PEM in binary",
     re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
     "critical",
     "Private keys must not be embedded in binaries. Use OS key stores or retrieve at runtime."),
    ("Possible AWS key in binary",
     re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
     "critical",
     "Rotate the key immediately and remove it from the binary."),
    ("Hardcoded password-like string",
     re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?[A-Za-z0-9!@#$%^&*]{6,}"),
     "high",
     "Avoid embedding credentials; use secure storage or user-provided secrets."),
    ("Insecure function indicators (gets, strcpy, etc.)",
     re.compile(r"\b(gets|strcpy|sprintf|scanf)\b"),
     "medium",
     "These C functions are historically associated with buffer overflows. Prefer safer alternatives (fgets, strncpy, snprintf) and enable stack protections."),
    ("Debug / verbose logging strings",
     re.compile(r"(?i)(debug|verbose|trace)\s*(mode|level|enabled)|printf\s*\(\s*\"%s\""),
     "low",
     "Ensure production builds strip excessive debug logging that could leak internals."),
    ("Possible SQL built by concatenation",
     re.compile(r"(?i)(SELECT|INSERT|UPDATE|DELETE).{0,40}(\+| \|\| |format)"),
     "medium",
     "Prefer parameterized queries even in native code."),
]


def _extract_strings(path, min_len=5, max_bytes=80 * 1024 * 1024):
    """Prefer system `strings` if available, else pure Python chunked scanner to prevent OOM."""
    try:
        size = os.path.getsize(path)
        if size > max_bytes:
            return []
    except Exception:
        return []

    if shutil.which("strings"):
        try:
            out = subprocess.check_output(
                ["strings", "-n", str(min_len), path],
                stderr=subprocess.DEVNULL, timeout=60
            )
            return out.decode("utf-8", errors="ignore").splitlines()
        except Exception:
            pass
    # Fallback chunked reader
    try:
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
                            if len(result) >= 30000:
                                return result
                        current = []
        if len(current) >= min_len:
            result.append("".join(current))
        return result
    except Exception:
        return []


def _detect_binary_type(path):
    try:
        with open(path, "rb") as fh:
            magic = fh.read(8)
        if magic[:4] == b"\x7fELF":
            return "ELF (Linux/Unix)"
        if magic[:2] == b"MZ":
            return "PE (Windows)"
        if magic[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe",
                          b"\xcf\xfa\xed\xfe"):
            return "Mach-O (macOS)"
        return "Unknown / raw binary"
    except Exception:
        return "Unknown"


def scan_binary(path: str):
    findings = []
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        return [{
            "type": "Binary not found",
            "severity": "info",
            "file": path,
            "line": 0,
            "snippet": "",
            "fix": "Provide a valid executable / library path.",
        }]

    btype = _detect_binary_type(path)
    findings.append({
        "type": f"Binary type detected: {btype}",
        "severity": "info",
        "file": path,
        "line": 0,
        "snippet": btype,
        "fix": "Informational only.",
    })

    size = os.path.getsize(path)
    if size > 80 * 1024 * 1024:
        findings.append({
            "type": "Binary very large – limited string scan",
            "severity": "info",
            "file": path,
            "line": 0,
            "snippet": f"{size} bytes",
            "fix": "Only a portion of strings may be examined for performance.",
        })

    strings = _extract_strings(path)
    # Cap to keep runtime reasonable
    strings = strings[:15000]

    for s in strings:
        # Secrets
        for name, pattern, severity in secrets.RULES:
            m = pattern.search(s)
            if m and not secrets._is_probably_placeholder(m.group(0)):
                findings.append({
                    "type": f"[Binary strings] {name}",
                    "severity": severity,
                    "file": path,
                    "line": 0,
                    "snippet": s[:180],
                    "fix": secrets._default_fix(name),
                })
                break
        # Binary-specific patterns
        for name, pattern, severity, fix in BINARY_PATTERNS:
            if pattern.search(s):
                findings.append({
                    "type": f"[Binary] {name}",
                    "severity": severity,
                    "file": path,
                    "line": 0,
                    "snippet": s[:180],
                    "fix": fix,
                })

    # Dedup
    seen = set()
    unique = []
    for f in findings:
        key = (f.get("type"), f.get("file"), f.get("snippet", "")[:60])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
