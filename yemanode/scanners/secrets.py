"""
Advanced Regex-based secret, token, and hardcoded credential scanner.
Supports source file scanning, sensitive config discovery, and Git commit history secret mining.
"""
import os
import re
import subprocess

MAX_FILE_SIZE = 5_000_000  # 5 MB
BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".tar", ".gz", ".bz2",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".exe", ".dll", ".so", ".dylib",
    ".class", ".jar", ".pyc", ".o", ".a", ".lib", ".apk", ".aab", ".ipa", ".dex",
    ".bin", ".dat", ".wasm",
}

# Sensitive file basenames that should never be committed to git
SENSITIVE_FILENAMES = {
    ".env": ("Committed .env Environment File", "critical", "CWE-798", "A01:2021-Broken Access Control"),
    ".env.local": ("Committed .env.local File", "critical", "CWE-798", "A01:2021-Broken Access Control"),
    ".env.production": ("Committed .env.production File", "critical", "CWE-798", "A01:2021-Broken Access Control"),
    ".env.staging": ("Committed .env.staging File", "critical", "CWE-798", "A01:2021-Broken Access Control"),
    "id_rsa": ("Committed SSH RSA Private Key File", "critical", "CWE-312", "A02:2021-Cryptographic Failures"),
    "id_ed25519": ("Committed SSH Ed25519 Private Key File", "critical", "CWE-312", "A02:2021-Cryptographic Failures"),
    "id_ecdsa": ("Committed SSH ECDSA Private Key File", "critical", "CWE-312", "A02:2021-Cryptographic Failures"),
    "credentials.json": ("Committed Google/AWS Credentials JSON", "critical", "CWE-798", "A01:2021-Broken Access Control"),
    "service-account.json": ("Committed Cloud Service Account JSON", "critical", "CWE-798", "A01:2021-Broken Access Control"),
    "firebase-adminsdk.json": ("Committed Firebase Admin SDK Secret", "critical", "CWE-798", "A01:2021-Broken Access Control"),
    ".npmrc": ("Committed .npmrc with Auth Tokens", "high", "CWE-312", "A02:2021-Cryptographic Failures"),
    ".dockercfg": ("Committed Docker Auth Config", "critical", "CWE-312", "A02:2021-Cryptographic Failures"),
    "wp-config.php": ("Committed WordPress Configuration File", "high", "CWE-312", "A02:2021-Cryptographic Failures"),
}

RULES = [
    # Cloud providers
    ("AWS Access Key ID", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "critical", "CWE-798", "A01:2021-Broken Access Control"),
    ("AWS Secret Access Key", re.compile(r"(?i)(aws_secret_access_key|aws_secret_key)\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]"), "critical", "CWE-798", "A01:2021-Broken Access Control"),
    ("AWS Session Token", re.compile(r"(?i)aws_session_token\s*[:=]\s*['\"][A-Za-z0-9/+=]{100,}['\"]"), "critical", "CWE-798", "A01:2021-Broken Access Control"),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "high", "CWE-798", "A01:2021-Broken Access Control"),
    ("Google OAuth Client Secret", re.compile(r"(?i)client_secret\s*[:=]\s*['\"][A-Za-z0-9\-_]{24,}['\"]"), "high", "CWE-798", "A01:2021-Broken Access Control"),
    ("Azure Storage / SharedAccess Key", re.compile(r"(?i)(accountkey|sharedaccesssignature)\s*[:=]\s*['\"][A-Za-z0-9+/=]{40,}['\"]"), "critical", "CWE-798", "A01:2021-Broken Access Control"),
    ("Azure Client Secret", re.compile(r"(?i)(client_secret|azure_client_secret)\s*[:=]\s*['\"][A-Za-z0-9~\-._]{20,}['\"]"), "critical", "CWE-798", "A01:2021-Broken Access Control"),
    ("GCP Service Account Private Key", re.compile(r'"private_key":\s*"-----BEGIN PRIVATE KEY-----\\n'), "critical", "CWE-798", "A01:2021-Broken Access Control"),

    # AI / LLM Keys
    ("OpenAI API Key", re.compile(r"\bsk-(proj-|live-)?[A-Za-z0-9]{20,T3BlbkFJ[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{48}\b"), "critical", "CWE-798", "A01:2021-Broken Access Control"),
    ("Anthropic API Key", re.compile(r"\bsk-ant-api03-[A-Za-z0-9\-_]{80,}\b"), "critical", "CWE-798", "A01:2021-Broken Access Control"),
    ("Hugging Face Access Token", re.compile(r"\bhf_[A-Za-z0-9]{34,}\b"), "high", "CWE-798", "A01:2021-Broken Access Control"),
    ("Cohere API Key", re.compile(r"(?i)cohere_api_key\s*[:=]\s*['\"][A-Za-z0-9]{40}['\"]"), "high", "CWE-798", "A01:2021-Broken Access Control"),

    # Generic secrets
    ("Generic API Key", re.compile(r"(?i)(api[_-]?key|apikey|api_secret)\s*[:=]\s*['\"][A-Za-z0-9\-_]{16,}['\"]"), "high", "CWE-798", "A01:2021-Broken Access Control"),
    ("Generic Secret / Token", re.compile(r"(?i)(secret|token|auth_token|access_token|refresh_token)\s*[:=]\s*['\"][A-Za-z0-9\-_/+=]{16,}['\"]"), "high", "CWE-798", "A01:2021-Broken Access Control"),
    ("Hardcoded Password", re.compile(r"(?i)(password|passwd|pwd|passphrase)\s*[:=]\s*['\"](?!.*\$\{)(?!.*%\()[^'\"]{4,}['\"]"), "high", "CWE-798", "A01:2021-Broken Access Control"),
    ("Private Key Block (RSA/EC/DSA/OPENSSH)", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----"), "critical", "CWE-312", "A02:2021-Cryptographic Failures"),
    ("SSH Private Key (inline)", re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"), "critical", "CWE-312", "A02:2021-Cryptographic Failures"),

    # Service tokens
    ("Slack Token (Bot/User)", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "high", "CWE-798", "A01:2021-Broken Access Control"),
    ("Slack Webhook URL", re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z_]+"), "medium", "CWE-798", "A01:2021-Broken Access Control"),
    ("GitHub Token (Classic/PAT)", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "critical", "CWE-798", "A01:2021-Broken Access Control"),
    ("GitHub Fine-grained PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{80,}\b"), "critical", "CWE-798", "A01:2021-Broken Access Control"),
    ("GitLab Personal Access Token", re.compile(r"\bglpat-[A-Za-z0-9\-_]{20,}\b"), "critical", "CWE-798", "A01:2021-Broken Access Control"),
    ("Stripe Secret Key", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"), "critical", "CWE-798", "A01:2021-Broken Access Control"),
    ("Stripe Publishable Key (live)", re.compile(r"\bpk_live_[0-9a-zA-Z]{24,}\b"), "medium", "CWE-798", "A01:2021-Broken Access Control"),
    ("Twilio Account SID / Auth Token", re.compile(r"(?i)(twilio|account_sid|auth_token)\s*[:=]\s*['\"][A-Za-z0-9]{20,}['\"]"), "high", "CWE-798", "A01:2021-Broken Access Control"),
    ("SendGrid API Key", re.compile(r"\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b"), "high", "CWE-798", "A01:2021-Broken Access Control"),
    ("Mailgun API Key", re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"), "high", "CWE-798", "A01:2021-Broken Access Control"),
    ("Discord Bot Token", re.compile(r"\b[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}\b"), "high", "CWE-798", "A01:2021-Broken Access Control"),
    ("Supabase Service Role Key", re.compile(r"(?i)(supabase_service_role_key|service_role_key)\s*[:=]\s*['\"][A-Za-z0-9\-_/+=]{30,}['\"]"), "critical", "CWE-798", "A01:2021-Broken Access Control"),
    ("JWT Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "medium", "CWE-798", "A01:2021-Broken Access Control"),

    # Databases & connection strings
    ("Database Connection String with Credentials", re.compile(
        r"(?i)(mongodb(\+srv)?|postgres(ql)?|mysql|mariadb|redis|mssql|sqlserver|oracle)://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+"
    ), "critical", "CWE-798", "A01:2021-Broken Access Control"),
    ("Generic DB Password in URI", re.compile(r"(?i)[a-z]+://[^:]+:[^@\s'\"]{4,}@"), "high", "CWE-798", "A01:2021-Broken Access Control"),

    # Mobile / other
    ("Android Embedded Key", re.compile(r"(?i)(api_key|apikey|secret_key)\s*=\s*[\"'][A-Za-z0-9\-_]{16,}[\"']"), "high", "CWE-798", "A01:2021-Broken Access Control"),
    ("iOS Plist Key Exposure", re.compile(r"(?i)<key>(api[_-]?key|secret|token|password)</key>\s*<string>[^<]{8,}</string>"), "high", "CWE-798", "A01:2021-Broken Access Control"),
]

ALLOWLIST_HINTS = (
    "example", "sample", "test_", "dummy", "changeme", "your_", "xxxx", "placeholder",
    "todo", "fixme", "insert_", "replace_", "xxx", "yyy", "zzz", "abcdef",
    "12345", "password123", "secret123", "not_a_real", "<your-key>", "my-secret-key",
)


def _is_probably_placeholder(match_text: str) -> bool:
    low = match_text.lower()
    return any(h in low for h in ALLOWLIST_HINTS)


def scan_files(file_list):
    """Scans list of source files for secrets and sensitive config file basenames."""
    findings = []
    
    for path in file_list:
        base_name = os.path.basename(path).lower()

        # Check for committed sensitive configuration files
        if base_name in SENSITIVE_FILENAMES:
            title, severity, cwe, owasp = SENSITIVE_FILENAMES[base_name]
            findings.append({
                "type": f"[Sensitive File] {title}",
                "severity": severity,
                "file": path,
                "line": 1,
                "cwe": cwe,
                "owasp": owasp,
                "snippet": f"Sensitive file '{base_name}' detected directly in repository tree.",
                "fix": f"Add '{base_name}' to .gitignore immediately, remove from git history, and rotate any secrets it contained.",
            })

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
            for rule in RULES:
                name, pattern, severity, cwe, owasp = rule[0], rule[1], rule[2], rule[3], rule[4]
                m = pattern.search(line)
                if m and not _is_probably_placeholder(m.group(0)):
                    findings.append({
                        "type": f"[Hardcoded Secret] {name}",
                        "severity": severity,
                        "file": path,
                        "line": lineno,
                        "cwe": cwe,
                        "owasp": owasp,
                        "snippet": line.strip()[:200],
                        "fix": _default_fix(name),
                    })
    return findings


def scan_git_history(repo_path: str, max_commits: int = 50):
    """
    Analyzes git commit history (`git log -p`) to detect secrets that were committed
    and might have been removed from current HEAD but remain exposed in Git logs.
    """
    findings = []
    if not os.path.isdir(os.path.join(repo_path, ".git")):
        return findings

    try:
        cmd = ["git", "log", "-p", f"-n{max_commits}", "--no-merges", "-U0"]
        res = subprocess.run(
            cmd, cwd=repo_path, capture_output=True, text=True, errors="ignore", timeout=30
        )
        if res.returncode != 0:
            return findings

        current_commit = "unknown"
        current_file = "git commit log"

        for line in res.stdout.splitlines():
            if line.startswith("commit "):
                current_commit = line.split()[1][:10]
            elif line.startswith("+++ b/"):
                current_file = line[6:]
            elif line.startswith("+") and not line.startswith("+++"):
                added_content = line[1:]
                for rule in RULES:
                    name, pattern, severity, cwe, owasp = rule[0], rule[1], rule[2], rule[3], rule[4]
                    m = pattern.search(added_content)
                    if m and not _is_probably_placeholder(m.group(0)):
                        findings.append({
                            "type": f"[Git History Secret] {name}",
                            "severity": severity,
                            "file": f"{current_file} (commit {current_commit})",
                            "line": 0,
                            "cwe": cwe,
                            "owasp": owasp,
                            "snippet": added_content.strip()[:180],
                            "fix": f"Secret was introduced in Git commit {current_commit}. Rotate this secret immediately and consider using 'git-filter-repo' or BFG Repo-Cleaner to rewrite history.",
                        })
    except Exception:
        pass

    return findings


def _default_fix(name: str) -> str:
    if "AWS" in name or "Azure" in name or "Google" in name or "GCP" in name:
        return ("Remove the hardcoded credential immediately. Rotate the key/secret in the "
                "cloud provider console, store it in a secrets manager (AWS Secrets Manager, SSM, "
                "Azure Key Vault, or GCP Secret Manager), and load it at runtime via IAM roles or environment variables.")
    if "OpenAI" in name or "Anthropic" in name or "Hugging Face" in name:
        return ("Revoke and regenerate the AI API token in your developer dashboard. Load via os.getenv('API_KEY').")
    if "Private Key" in name or "SSH" in name:
        return ("Remove the private key from the repository. Revoke/rotate the key pair, "
                "add key files to .gitignore, and use an OS keychain or HashiCorp Vault.")
    if "Password" in name or "Connection String" in name or "DB" in name:
        return ("Never hardcode database credentials. Inject them securely via environment variables or container secrets.")
    return "Remove the secret from source control, rotate it immediately if it was ever active, and load it from environment variables at runtime."
