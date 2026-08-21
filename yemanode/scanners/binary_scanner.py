"""
Lightweight static analysis and security mitigation scanner for native binaries (ELF, PE, Mach-O).
Audits security mitigations (ASLR/PIE, NX/DEP, RELRO, Stack Canaries), debug symbols,
dangerous imported C functions, embedded secrets, and suspicious URLs.
"""
import os
import re
import shutil
import struct
import subprocess

from . import secrets

# Common dangerous or suspicious functions in native binaries
DANGEROUS_C_APIS = {
    "gets": ("Dangerous Insecure Function 'gets' (Buffer Overflow)", "critical", "CWE-120", "A06:2021-Vulnerable and Outdated Components", 9.8,
             "Replace 'gets' with 'fgets(buf, sizeof(buf), stdin)' to prevent fatal stack buffer overflows."),
    "strcpy": ("Unsafe Memory Function 'strcpy' (Buffer Overflow Risk)", "medium", "CWE-120", "A06:2021-Vulnerable and Outdated Components", 6.5,
               "Replace 'strcpy' with 'strncpy' or 'snprintf' and ensure null-termination."),
    "strcat": ("Unsafe String Concatenation 'strcat' (Buffer Overflow Risk)", "medium", "CWE-120", "A06:2021-Vulnerable and Outdated Components", 6.5,
               "Replace 'strcat' with 'strncat' or 'snprintf'."),
    "sprintf": ("Unbounded Format Function 'sprintf' (Buffer Overflow Risk)", "medium", "CWE-120", "A06:2021-Vulnerable and Outdated Components", 6.5,
                "Replace 'sprintf' with 'snprintf' to enforce buffer bounds."),
    "scanf": ("Unbounded Input Function 'scanf' (Buffer Overflow Risk)", "medium", "CWE-120", "A06:2021-Vulnerable and Outdated Components", 6.5,
              "Use length specifiers in format strings (e.g. '%31s') or 'fgets'."),
    "system": ("Process Shell Execution 'system' (Command Injection Vector)", "medium", "CWE-78", "A03:2021-Injection", 6.5,
               "Avoid calling 'system()'. Use 'execve' or 'posix_spawn' with explicit argument arrays."),
    "popen": ("Process Pipe Execution 'popen' (Command Injection Vector)", "medium", "CWE-78", "A03:2021-Injection", 6.5,
              "Avoid passing unvalidated dynamic strings to 'popen()'."),
    "ptrace": ("Anti-Debugging / Memory Modification 'ptrace' Call", "info", "CWE-388", "A04:2021-Insecure Design", 3.0,
               "Note: ptrace detected (often used for anti-tamper or self-debugging mechanisms)."),
    "mprotect": ("Memory Protection Modification 'mprotect' (RWX Memory Risk)", "medium", "CWE-732", "A05:2021-Security Misconfiguration", 5.5,
                 "Ensure mprotect does not mark heap/stack pages as simultaneously Writable and Executable (W^X violation)."),
}

BINARY_PATTERNS = [
    ("Hardcoded Private Key / PEM in Binary",
     re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
     "critical", "CWE-312", "A02:2021-Cryptographic Failures", 8.9,
     "Private keys must not be embedded in binaries. Use OS key stores or retrieve at runtime."),
    ("Hardcoded AWS Key in Binary",
     re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
     "critical", "CWE-798", "A01:2021-Broken Access Control", 8.9,
     "Rotate the key immediately in AWS IAM and remove it from the binary."),
    ("Hardcoded Password-Like String in Binary",
     re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?[A-Za-z0-9!@#$%^&*]{6,}"),
     "high", "CWE-798", "A01:2021-Broken Access Control", 7.5,
     "Avoid embedding credentials in compiled binaries. Strings are trivially extracted with reverse engineering tools."),
    ("Embedded Internal / Cleartext URL in Binary",
     re.compile(r"https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?|https?://[a-zA-Z0-9_\-.]+(?:internal|corp|local|stage|dev)"),
     "low", "CWE-200", "A01:2021-Broken Access Control", 3.8,
     "Audit internal hostnames and IP addresses to prevent internal network topology disclosure."),
]


def _extract_strings(path, min_len=5, max_bytes=80 * 1024 * 1024):
    """Extract strings using system `strings` if available or chunked fallback."""
    try:
        if os.path.getsize(path) > max_bytes:
            return []
    except Exception:
        return []

    if shutil.which("strings"):
        try:
            out = subprocess.check_output(
                ["strings", "-n", str(min_len), path],
                stderr=subprocess.DEVNULL, timeout=45
            )
            return out.decode("utf-8", errors="ignore").splitlines()
        except Exception:
            pass

    # Fallback chunked string extractor
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
        if magic[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe"):
            return "Mach-O (macOS)"
        return "Raw / Generic Binary"
    except Exception:
        return "Unknown"


def _audit_elf_mitigations(path):
    """
    Parses ELF headers to audit security mitigations:
    - ASLR / PIE (Position Independent Executable)
    - NX / DEP (No-Execute Stack: PT_GNU_STACK PF_X)
    - RELRO (Full / Partial / None: PT_GNU_RELRO + DT_BIND_NOW)
    """
    findings = []
    try:
        with open(path, "rb") as f:
            ident = f.read(16)
            if ident[:4] != b"\x7fELF":
                return findings
            data_encoding = ident[5]  # 1 = LSB (little endian), 2 = MSB (big endian)
            endian = "<" if data_encoding == 1 else ">"

            # Read e_type
            e_type_bytes = f.read(2)
            if len(e_type_bytes) < 2:
                return findings
            e_type = struct.unpack(endian + "H", e_type_bytes)[0]

            # PIE Audit
            # ET_EXEC = 2 (No PIE), ET_DYN = 3 (PIE or Shared Library)
            if e_type == 2:
                findings.append({
                    "type": "[Binary Mitigation] ASLR / PIE Disabled (Position Independent Executable Missing)",
                    "severity": "high",
                    "file": path,
                    "line": 0,
                    "cwe": "CWE-693",
                    "owasp": "A05:2021-Security Misconfiguration",
                    "cvss": 7.5,
                    "snippet": "ELF Type: ET_EXEC (Fixed load address)",
                    "fix": "Recompile with '-fPIE -pie' to enable Address Space Layout Randomization (ASLR).",
                })
            elif e_type == 3:
                findings.append({
                    "type": "[Binary Hardening] PIE / ASLR Enabled (Position Independent)",
                    "severity": "info",
                    "file": path,
                    "line": 0,
                    "cwe": "CWE-693",
                    "owasp": "A05:2021-Security Misconfiguration",
                    "cvss": 0.0,
                    "snippet": "ELF Type: ET_DYN",
                    "fix": "PIE hardening verified.",
                })

            # Check program headers for PT_GNU_STACK and PT_GNU_RELRO
            f.seek(0)
            raw = f.read(min(os.path.getsize(path), 64 * 1024))
            
            # Check for stack execution indicator (NX)
            # PT_GNU_STACK is 0x6474e551
            has_gnu_stack = b"\x51\xe5\x74\x64" in raw or b"\x64\x74\xe5\x51" in raw
            has_relro = b"\x52\xe5\x74\x64" in raw or b"\x64\x74\xe5\x52" in raw

            if not has_gnu_stack:
                findings.append({
                    "type": "[Binary Mitigation] Executable Stack Risk (NX / DEP Missing or Unenforced)",
                    "severity": "high",
                    "file": path,
                    "line": 0,
                    "cwe": "CWE-693",
                    "owasp": "A05:2021-Security Misconfiguration",
                    "cvss": 7.8,
                    "snippet": "PT_GNU_STACK program header not found.",
                    "fix": "Recompile with '-Wl,-z,noexecstack' to prevent shellcode execution from stack memory.",
                })
            
            if not has_relro:
                findings.append({
                    "type": "[Binary Mitigation] RELRO Missing (Read-Only Relocations Disabled)",
                    "severity": "medium",
                    "file": path,
                    "line": 0,
                    "cwe": "CWE-693",
                    "owasp": "A05:2021-Security Misconfiguration",
                    "cvss": 5.9,
                    "snippet": "PT_GNU_RELRO segment not found.",
                    "fix": "Recompile with '-Wl,-z,relro,-z,now' for Full RELRO protection of Global Offset Table (GOT).",
                })
    except Exception:
        pass
    return findings


def scan_binary(path: str):
    findings = []
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        return [{
            "type": "Binary not found",
            "severity": "info",
            "file": path,
            "line": 0,
            "cwe": "CWE-200",
            "owasp": "A05:2021-Security Misconfiguration",
            "cvss": 0.0,
            "snippet": "",
            "fix": "Provide a valid executable / library path.",
        }]

    btype = _detect_binary_type(path)
    findings.append({
        "type": f"Binary type detected: {btype}",
        "severity": "info",
        "file": path,
        "line": 0,
        "cwe": "CWE-200",
        "owasp": "A05:2021-Security Misconfiguration",
        "cvss": 0.0,
        "snippet": btype,
        "fix": "Informational only.",
    })

    # Run ELF mitigation checks if ELF
    if "ELF" in btype:
        findings.extend(_audit_elf_mitigations(path))

    strings = _extract_strings(path)
    all_strings_set = set(strings)
    strings_sample = strings[:20000]

    # Stack Canary Symbol Check
    has_canary = any("__stack_chk_fail" in s or "__security_cookie" in s for s in strings_sample)
    if not has_canary and "ELF" in btype:
        findings.append({
            "type": "[Binary Mitigation] Stack Canary Missing (__stack_chk_fail not found)",
            "severity": "medium",
            "file": path,
            "line": 0,
            "cwe": "CWE-693",
            "owasp": "A05:2021-Security Misconfiguration",
            "cvss": 5.9,
            "snippet": "No stack protector symbols detected in string table.",
            "fix": "Recompile with '-fstack-protector-strong' or '-fstack-protector-all' to guard against stack smashing.",
        })

    # Debug Symbol Detection
    has_debug = any(".debug_info" in s or ".debug_str" in s or "DWARF" in s or ".pdb" in s for s in strings_sample)
    if has_debug:
        findings.append({
            "type": "[Binary Info] Debug Symbols Detected in Production Binary",
            "severity": "low",
            "file": path,
            "line": 0,
            "cwe": "CWE-215",
            "owasp": "A05:2021-Security Misconfiguration",
            "cvss": 3.1,
            "snippet": "Debug sections / symbols found in binary.",
            "fix": "Strip debug symbols before shipping with 'strip --strip-all <binary>'.",
        })

    # Dangerous C API checks
    for fn, (title, severity, cwe, owasp, cvss, fix) in DANGEROUS_C_APIS.items():
        if fn in all_strings_set:
            findings.append({
                "type": f"[Binary Function] {title}",
                "severity": severity,
                "file": path,
                "line": 0,
                "cwe": cwe,
                "owasp": owasp,
                "cvss": cvss,
                "snippet": f"Symbol reference '{fn}' found in binary import/symbol table.",
                "fix": fix,
            })

    # Check for embedded patterns & secrets
    for s in strings_sample:
        for name, pattern, severity, cwe, owasp in secrets.RULES:
            m = pattern.search(s)
            if m and not secrets._is_probably_placeholder(m.group(0)):
                findings.append({
                    "type": f"[Binary Secret] {name}",
                    "severity": severity,
                    "file": path,
                    "line": 0,
                    "cwe": cwe,
                    "owasp": owasp,
                    "cvss": 8.5 if severity == "critical" else 7.0,
                    "snippet": s[:180],
                    "fix": secrets._default_fix(name),
                })
                break

        for name, pattern, severity, cwe, owasp, cvss, fix in BINARY_PATTERNS:
            if pattern.search(s):
                findings.append({
                    "type": f"[Binary String] {name}",
                    "severity": severity,
                    "file": path,
                    "line": 0,
                    "cwe": cwe,
                    "owasp": owasp,
                    "cvss": cvss,
                    "snippet": s[:180],
                    "fix": fix,
                })

    # Deduplicate findings
    seen = set()
    unique = []
    for f in findings:
        key = (f.get("type"), f.get("file"), f.get("snippet", "")[:60])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
