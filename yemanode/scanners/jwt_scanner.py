"""
JWT (JSON Web Token) Security Scanner for Yemanode.
Decodes tokens without secret key, checks header/payload risks, weak algorithms, and expiration.
"""
import base64
import json
import re
import datetime

# Match standard JWT tokens: header.payload.signature
JWT_REGEX = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")

SENSITIVE_CLAIM_KEYS = {
    "password", "passwd", "secret", "private_key", "ssn", "social_security",
    "credit_card", "card_number", "pin", "api_key"
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
    Returns list of finding dicts.
    """
    findings = []
    parts = token_str.strip().split(".")
    if len(parts) != 3:
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

    # 1. Algorithm check: 'none' algorithm
    if alg == "none":
        findings.append({
            "type": "[JWT Vulnerability] Unsigned Token (alg: none)",
            "severity": "critical",
            "file": source_location,
            "line": 0,
            "snippet": f"Header: {header_raw[:120]}",
            "fix": "Reject tokens with alg='none' in JWT validation middleware.",
        })

    # 2. Symmetric weak secret or deprecated algorithm
    elif alg in ("hs256", "none"):
        findings.append({
            "type": "[JWT Risk] Symmetric Signing Algorithm (HS256)",
            "severity": "medium",
            "file": source_location,
            "line": 0,
            "snippet": f"Header alg: {header.get('alg')}",
            "fix": "Consider asymmetric algorithms (RS256/ES256) for public-facing microservices.",
        })

    # 3. Header parameter injection risks (jwk, jku)
    if "jku" in header or "jwk" in header:
        findings.append({
            "type": "[JWT Vulnerability] Header Key Injection Risk (jwk/jku present)",
            "severity": "high",
            "file": source_location,
            "line": 0,
            "snippet": f"Header contains: jku={header.get('jku')} jwk={header.get('jwk')}",
            "fix": "Do not trust inline JWK or JKU headers without explicit server-side allow-listing.",
        })

    # 4. Expiration check
    if "exp" not in payload:
        findings.append({
            "type": "[JWT Risk] Missing Expiration Claim (exp)",
            "severity": "medium",
            "file": source_location,
            "line": 0,
            "snippet": f"Payload keys: {list(payload.keys())}",
            "fix": "Always set an 'exp' claim on JWT tokens to limit token lifespan.",
        })
    else:
        exp_val = payload.get("exp")
        if isinstance(exp_val, (int, float)):
            exp_dt = datetime.datetime.fromtimestamp(exp_val, tz=datetime.timezone.utc)
            now_dt = datetime.datetime.now(tz=datetime.timezone.utc)
            if exp_dt < now_dt:
                findings.append({
                    "type": "[JWT Info] Expired Token",
                    "severity": "info",
                    "file": source_location,
                    "line": 0,
                    "snippet": f"Expired at: {exp_dt.isoformat()}",
                    "fix": "Ensure token refresh mechanisms work properly.",
                })

    # 5. Sensitive data leakage in payload
    leaked_keys = []
    for k in payload.keys():
        if k.lower() in SENSITIVE_CLAIM_KEYS:
            leaked_keys.append(k)

    if leaked_keys:
        findings.append({
            "type": "[JWT Vulnerability] Sensitive Claims Leaked in Unencrypted Payload",
            "severity": "high",
            "file": source_location,
            "line": 0,
            "snippet": f"Sensitive payload claim(s) found: {', '.join(leaked_keys)}",
            "fix": "Never store sensitive data (passwords, PII, secret keys) in JWT payloads.",
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
