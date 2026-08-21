"""Regex-based secret / hardcoded credential scanner – expanded rule set."""
import os
import re

MAX_FILE_SIZE = 3_000_000  # skip huge files
BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".tar", ".gz", ".bz2",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".exe", ".dll", ".so", ".dylib",
    ".class", ".jar", ".pyc", ".o", ".a", ".lib", ".apk", ".aab", ".ipa", ".dex",
    ".bin", ".dat", ".wasm",
}

RULES = [
    # Cloud providers
    ("AWS Access Key ID", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "critical"),
    ("AWS Secret Access Key", re.compile(r"(?i)(aws_secret_access_key|aws_secret_key)\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]"), "critical"),
    ("AWS Session Token", re.compile(r"(?i)aws_session_token\s*[:=]\s*['\"][A-Za-z0-9/+=]{100,}['\"]"), "critical"),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "high"),
    ("Google OAuth Client Secret", re.compile(r"(?i)client_secret\s*[:=]\s*['\"][A-Za-z0-9\-_]{24,}['\"]"), "high"),
    ("Azure Storage Key", re.compile(r"(?i)(accountkey|sharedaccesssignature)\s*[:=]\s*['\"][A-Za-z0-9+/=]{40,}['\"]"), "critical"),
    ("Azure Client Secret", re.compile(r"(?i)(client_secret|azure_client_secret)\s*[:=]\s*['\"][A-Za-z0-9~\-._]{20,}['\"]"), "critical"),

    # Generic secrets
    ("Generic API Key", re.compile(r"(?i)(api[_-]?key|apikey|api_secret)\s*[:=]\s*['\"][A-Za-z0-9\-_]{16,}['\"]"), "high"),
    ("Generic Secret / Token", re.compile(r"(?i)(secret|token|auth_token|access_token|refresh_token)\s*[:=]\s*['\"][A-Za-z0-9\-_/+=]{16,}['\"]"), "high"),
    ("Hardcoded Password", re.compile(r"(?i)(password|passwd|pwd|passphrase)\s*[:=]\s*['\"](?!.*\$\{)(?!.*%\()[^'\"]{4,}['\"]"), "high"),
    ("Private Key Block", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "critical"),
    ("SSH Private Key (inline)", re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"), "critical"),

    # Service tokens
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"), "high"),
    ("Slack Webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"), "medium"),
    ("GitHub Token (classic/PAT)", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"), "critical"),
    ("GitHub Fine-grained Token", re.compile(r"github_pat_[A-Za-z0-9_]{80,}"), "critical"),
    ("GitLab Token", re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"), "critical"),
    ("Stripe Secret Key", re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), "critical"),
    ("Stripe Publishable Key (live)", re.compile(r"pk_live_[0-9a-zA-Z]{24,}"), "medium"),
    ("Twilio Account SID / Auth", re.compile(r"(?i)(twilio|account_sid|auth_token)\s*[:=]\s*['\"][A-Za-z0-9]{20,}['\"]"), "high"),
    ("SendGrid API Key", re.compile(r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"), "high"),
    ("Mailgun API Key", re.compile(r"key-[0-9a-zA-Z]{32}"), "high"),
    ("JWT Token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "medium"),
    ("Firebase / Google Service Account", re.compile(r"(?i)\"type\"\s*:\s*\"service_account\""), "high"),

    # Databases & connection strings
    ("Database Connection String", re.compile(
        r"(?i)(mongodb(\+srv)?|postgres(ql)?|mysql|mariadb|redis|mssql|sqlserver|oracle)://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+"
    ), "critical"),
    ("Generic DB Password in URL", re.compile(r"(?i)[a-z]+://[^:]+:[^@\s'\"]{4,}@"), "high"),

    # Mobile / other
    ("Android Hardcoded Key", re.compile(r"(?i)(api_key|apikey|secret_key)\s*=\s*[\"'][A-Za-z0-9\-_]{16,}[\"']"), "high"),
    ("iOS / plist secret-ish", re.compile(r"(?i)<key>(api[_-]?key|secret|token|password)</key>\s*<string>[^<]{8,}</string>"), "high"),
]

ALLOWLIST_HINTS = (
    "example", "sample", "test_", "dummy", "changeme", "your_", "xxxx", "placeholder",
    "todo", "fixme", "insert_", "replace_", "xxx", "yyy", "zzz", "abcdef",
    "12345", "password123", "secret123", "not_a_real",
)


def _is_probably_placeholder(match_text: str) -> bool:
    low = match_text.lower()
    return any(h in low for h in ALLOWLIST_HINTS)


def scan_files(file_list):
    findings = []
    for path in file_list:
        ext = os.path.splitext(path)[1].lower()
        if ext in BINARY_EXT:
            continue
        try:
            if os.path.getsize(path) > MAX_FILE_SIZE:
                continue
        except OSError:
            continue
        try:
            with open(path, "r", errors="ignore") as fh:
                lines = fh.readlines()
        except Exception:
            continue

        for lineno, line in enumerate(lines, start=1):
            if "re.compile(" in line or "RULES = [" in line:
                continue
            for name, pattern, severity in RULES:
                m = pattern.search(line)
                if m and not _is_probably_placeholder(m.group(0)):
                    findings.append({
                        "type": name,
                        "severity": severity,
                        "file": path,
                        "line": lineno,
                        "snippet": line.strip()[:200],
                        "fix": _default_fix(name),
                    })
    return findings


def _default_fix(name: str) -> str:
    if "AWS" in name or "Azure" in name or "Google" in name:
        return ("Remove the hardcoded credential immediately. Rotate the key/secret in the "
                "cloud console, store it in a secrets manager (AWS Secrets Manager, SSM, "
                "Azure Key Vault, GCP Secret Manager, or HashiCorp Vault), and load it at "
                "runtime via environment variables or the SDK.")
    if "Private Key" in name or "SSH" in name:
        return ("Remove the private key from the repository. Revoke/rotate the key pair, "
                "add the file to .gitignore, and use a proper secrets management solution.")
    if "Password" in name or "Connection String" in name or "DB" in name:
        return ("Never hardcode credentials. Move them to environment variables or a secrets "
                "manager. Prefer connection-string builders that pull host/user/password separately.")
    if "JWT" in name:
        return ("JWTs in source are usually either test tokens or leaked session material. "
                "Ensure signing secrets live in env vars / secrets manager and never commit real tokens.")
    return ("Remove the secret from source control, rotate it if it was real, and load it "
            "from environment variables or a secrets manager at runtime.")
