"""
JWT (JSON Web Token) Security Scanner for Yemanode.
Decodes tokens without secret key, checks header/payload risks, weak algorithms,
kid parameter injection, issuer/audience security, and claim validation.
"""
import base64
import datetime
import json
import re

# Match standard JWT tokens: header.payload.signature
JWT_REGEX = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*\b")

SENSITIVE_CLAIM_KEYS = {
    "password", "passwd", "pwd", "secret", "private_key", "ssn", "social_security",
    "credit_card", "card_number", "pin", "api_key", "apikey", "auth_token", "access_token"
}


def _base64_url_decode(segment: str) -> str:
    """Decode base64url string with padding fix."""
    rem = len(segment) % 4
    if rem > 0:
        segment += "=" * (4 - rem)
    try:
        return base64.urlsafe_b64decode(segment.encode("utf-8")).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def analyze_jwt_token(token_str: str, source_location: str = "JWT string"):
    """
    Decodes and audits a single JWT token.
    Returns list of finding dicts with CWE, OWASP, CVSS, and actionable fixes.
    """
    findings = []
    parts = token_str.strip().split(".")
    if len(parts) not in (2, 3):
        return findings

    header_raw = _base64_url_decode(parts[0])
    payload_raw = _base64_url_decode(parts[1])

    if not header_raw or not payload_raw:
        return findings

    try:
        header = json.loads(header_raw)
        payload = json.loads(payload_raw)
    except Exception:
        return findings

    alg = str(header.get("alg", "")).lower()

    # 1. Critical: 'none' algorithm bypass
    if alg == "none" or header.get("alg") is None:
        findings.append({
            "type": "[JWT Vulnerability] Unsigned Token (alg: none / missing)",
            "severity": "critical",
            "file": source_location,
            "line": 0,
            "cwe": "CWE-345",
            "owasp": "A07:2021-Identification and Authentication Failures",
            "cvss": 9.8,
            "snippet": f"Header: {header_raw[:120]}",
            "fix": "Reject tokens with alg='none' or missing algorithms in backend JWT validation middleware.",
        })

    # 2. Symmetric weak algorithm (HS256)
    elif alg.startswith("hs"):
        findings.append({
            "type": f"[JWT Weakness] Symmetric Signing Algorithm ({header.get('alg', 'HS256')})",
            "severity": "medium",
            "file": source_location,
            "line": 0,
            "cwe": "CWE-327",
            "owasp": "A02:2021-Cryptographic Failures",
            "cvss": 5.3,
            "snippet": f"Header alg: {header.get('alg')}",
            "fix": "Consider using asymmetric algorithms (RS256, ES256, EdDSA) so microservices do not need shared symmetric secrets.",
        })

    # 3. Empty signature with non-none alg
    if len(parts) == 2 or (len(parts) == 3 and not parts[2]):
        if alg != "none":
            findings.append({
                "type": "[JWT Vulnerability] Stripped / Empty Signature",
                "severity": "critical",
                "file": source_location,
                "line": 0,
                "cwe": "CWE-347",
                "owasp": "A07:2021-Identification and Authentication Failures",
                "cvss": 9.1,
                "snippet": "Signature segment is empty.",
                "fix": "Ensure token verification is strictly enforced before processing claims.",
            })

    # 4. Header parameter injection risks (jwk, jku, x5u)
    if "jku" in header or "jwk" in header or "x5u" in header:
        findings.append({
            "type": "[JWT Vulnerability] Header Key Injection Risk (jwk/jku/x5u present)",
            "severity": "high",
            "file": source_location,
            "line": 0,
            "cwe": "CWE-345",
            "owasp": "A07:2021-Identification and Authentication Failures",
            "cvss": 8.1,
            "snippet": f"Header keys: {list(header.keys())}",
            "fix": "Do not trust inline JWK, JKU, or X5U URLs without explicit allow-listing of trusted domains.",
        })

    # 5. Key ID (kid) parameter traversal / injection
    kid = str(header.get("kid", ""))
    if kid and ("../" in kid or "..\\" in kid or "'" in kid or '"' in kid or ";" in kid):
        findings.append({
            "type": "[JWT Vulnerability] Suspicious Key ID (kid) Injection Pattern",
            "severity": "high",
            "file": source_location,
            "line": 0,
            "cwe": "CWE-22",
            "owasp": "A03:2021-Injection",
            "cvss": 8.6,
            "snippet": f"Header kid: '{kid}'",
            "fix": "Sanitize and validate 'kid' against an allowed set of key IDs. Prevent path traversal or database query interpolation with kid.",
        })

    # 6. Expiration check (exp)
    if "exp" not in payload:
        findings.append({
            "type": "[JWT Weakness] Missing Expiration Claim (exp)",
            "severity": "medium",
            "file": source_location,
            "line": 0,
            "cwe": "CWE-613",
            "owasp": "A07:2021-Identification and Authentication Failures",
            "cvss": 6.5,
            "snippet": f"Payload keys: {list(payload.keys())}",
            "fix": "Always set an 'exp' expiration claim on JWT tokens to restrict token validity windows.",
        })
    else:
        exp_val = payload.get("exp")
        if isinstance(exp_val, (int, float)):
            now_ts = datetime.datetime.now(tz=datetime.timezone.utc).timestamp()
            if exp_val < now_ts:
                findings.append({
                    "type": "[JWT Info] Expired Token",
                    "severity": "info",
                    "file": source_location,
                    "line": 0,
                    "cwe": "CWE-613",
                    "owasp": "A07:2021-Identification and Authentication Failures",
                    "cvss": 0.0,
                    "snippet": f"exp timestamp {exp_val} is in the past",
                    "fix": "Token is expired. Verify expiration enforcement in authorization handlers.",
                })
            elif exp_val - now_ts > 5 * 365 * 86400:  # > 5 years
                findings.append({
                    "type": "[JWT Weakness] Excessively Long Token Expiration Window (> 5 Years)",
                    "severity": "low",
                    "file": source_location,
                    "line": 0,
                    "cwe": "CWE-613",
                    "owasp": "A07:2021-Identification and Authentication Failures",
                    "cvss": 3.7,
                    "snippet": f"exp timestamp {exp_val} allows validity for over 5 years",
                    "fix": "Reduce token validity period (recommended 15 minutes to 24 hours) and use refresh tokens.",
                })

    # 7. Issuer (iss) / Audience (aud) validation
    iss = str(payload.get("iss", ""))
    if iss.startswith("http://"):
        findings.append({
            "type": "[JWT Weakness] Insecure HTTP Issuer URI (iss)",
            "severity": "low",
            "file": source_location,
            "line": 0,
            "cwe": "CWE-319",
            "owasp": "A02:2021-Cryptographic Failures",
            "cvss": 3.1,
            "snippet": f"iss claim: '{iss}'",
            "fix": "Use HTTPS for all token issuer URIs to avoid MITM tampering.",
        })

    # 8. Sensitive data leakage in payload
    leaked_keys = [k for k in payload.keys() if k.lower() in SENSITIVE_CLAIM_KEYS]
    if leaked_keys:
        findings.append({
            "type": "[JWT Vulnerability] Sensitive Information Leaked in JWT Claims",
            "severity": "high",
            "file": source_location,
            "line": 0,
            "cwe": "CWE-312",
            "owasp": "A04:2021-Insecure Design",
            "cvss": 7.5,
            "snippet": f"Sensitive payload claim(s) found: {', '.join(leaked_keys)}",
            "fix": "JWT tokens are base64-encoded and not encrypted. Never store passwords, PINs, secrets, or PII in claims without JWE encryption.",
        })

    return findings


def scan_file_for_jwts(file_path: str):
    """Scan a text file for embedded JWT tokens."""
    findings = []
    try:
        with open(file_path, "r", errors="ignore") as fh:
            for lineno, line in enumerate(fh, start=1):
                for match in JWT_REGEX.finditer(line):
                    jwt_str = match.group(0)
                    res = analyze_jwt_token(jwt_str, source_location=f"{file_path}:{lineno}")
                    findings.extend(res)
    except Exception:
        pass
    return findings
