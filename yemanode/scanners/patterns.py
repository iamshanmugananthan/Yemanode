"""
Expanded pattern-based static analysis for common vulnerability classes.
Covers injection, XSS, insecure crypto, misconfigurations, Android/iOS patterns, IaC, etc.
"""
import os
import re

MAX_FILE_SIZE = 3_000_000

# Language / extension specific rules: (name, pattern, severity, fix)
RULES = {
    ".py": [
        ("SQL Injection (string formatting / concat into query)",
         re.compile(r"(execute|executemany|raw)\s*\(\s*(f['\"]|['\"].*%|['\"].*\+|\.format\()"),
         "high",
         "Use parameterized queries: cursor.execute(sql, (param,)) or an ORM. Never build SQL with f-strings, %, or +."),
        ("Use of eval / exec",
         re.compile(r"\b(eval|exec)\s*\("),
         "high",
         "Avoid eval()/exec() on untrusted input. Prefer ast.literal_eval or a proper parser."),
        ("Insecure Deserialization (pickle / yaml.load)",
         re.compile(r"\bpickle\.(load|loads)\s*\(|yaml\.load\s*\((?!.*Loader=yaml\.SafeLoader)"),
         "high",
         "Never unpickle untrusted data. Use yaml.safe_load() or JSON."),
        ("Command Injection (os.system / shell=True)",
         re.compile(r"os\.system\s*\(|subprocess\.[A-Za-z]+\([^)]*shell\s*=\s*True"),
         "high",
         "Use subprocess with a list of arguments and shell=False. Never pass user input to a shell."),
        ("Debug mode enabled",
         re.compile(r"(?i)(DEBUG|debug)\s*=\s*True"),
         "medium",
         "Ensure DEBUG / Flask debug / Django DEBUG is False in production to avoid stack-trace & secret leakage."),
        ("Weak hash for security (MD5 / SHA1)",
         re.compile(r"\bhashlib\.(md5|sha1)\s*\("),
         "medium",
         "Use SHA-256+ for integrity; for passwords use bcrypt / scrypt / argon2."),
        ("Hardcoded SECRET_KEY / Flask secret",
         re.compile(r"(?i)(SECRET_KEY|secret_key)\s*=\s*['\"][^'\"]{8,}['\"]"),
         "critical",
         "Load SECRET_KEY from environment or a secrets manager. Rotate if it was committed."),
        ("Insecure random for security",
         re.compile(r"\brandom\.(random|randint|choice)\s*\("),
         "low",
         "For security-sensitive values (tokens, keys) use secrets module, not random."),
        ("assert used for security checks",
         re.compile(r"\bassert\s+.*(auth|permission|admin|role)"),
         "medium",
         "assert statements are stripped with -O. Use explicit if/raise for authorization checks."),
        ("SSRF Risk (user-supplied URL in HTTP request)",
         re.compile(r"requests\.(get|post|put|delete|request)\s*\(\s*(?!['\"]https?://)[A-Za-z0-9_.]+\b"),
         "high",
         "Validate and sanitize user-supplied URLs against an allow-list of domains before making HTTP requests (SSRF prevention)."),
        ("SSTI (Server-Side Template Injection)",
         re.compile(r"render_template_string\s*\(|jinja2\.Template\s*\([^)]*f['\"]"),
         "high",
         "Avoid passing dynamic string templates or f-strings to render_template_string(). Use static template files."),
        ("XXE (XML External Entity Risk)",
         re.compile(r"etree\.parse\s*\(|xml\.dom\.minidom\.parse"),
         "medium",
         "Ensure XML parsers disable external entity resolution (resolve_entities=False / defusedxml)."),
    ],
    ".js": [
        ("SQL Injection (template literal / concat into query)",
         re.compile(r"\.query\s*\(\s*`[^`]*\$\{|\.query\s*\(\s*['\"].*\+"),
         "high",
         "Use parameterized queries (?, $1) or an ORM. Never interpolate variables into SQL."),
        ("Use of eval",
         re.compile(r"\beval\s*\("),
         "high",
         "Avoid eval(). It enables arbitrary code execution."),
        ("innerHTML / dangerouslySetInnerHTML (XSS)",
         re.compile(r"\.innerHTML\s*=|dangerouslySetInnerHTML"),
         "medium",
         "Prefer textContent or a sanitizer (DOMPurify). Avoid raw HTML assignment of untrusted data."),
        ("Hardcoded JWT / session secret",
         re.compile(r"(?i)(jwt\.sign|secret|sessionSecret)\s*[=:(][^,)]*['\"][^'\"]{6,}['\"]"),
         "high",
         "Load signing secrets from environment variables or a secrets manager."),
        ("Disabled TLS verification",
         re.compile(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"),
         "critical",
         "Never disable TLS certificate verification in production."),
        ("Command Injection (child_process.exec)",
         re.compile(r"child_process\.(exec|execSync)\s*\("),
         "high",
         "Prefer execFile / spawn with argument arrays over shell-interpreting exec."),
        ("document.write (XSS)",
         re.compile(r"document\.write\s*\("),
         "medium",
         "Avoid document.write with dynamic content; use safe DOM APIs."),
        ("localStorage for sensitive data",
         re.compile(r"localStorage\.(setItem|getItem)\s*\(\s*['\"][^'\"]*(token|password|secret|key|auth)"),
         "medium",
         "Avoid storing tokens/passwords in localStorage (XSS-accessible). Prefer httpOnly cookies or memory."),
        ("SSRF Risk (dynamic URL in fetch/axios)",
         re.compile(r"(fetch|axios\.(get|post|put|delete))\s*\(\s*(?!['\"]https?://)[A-Za-z0-9_.]+\b"),
         "high",
         "Validate target URLs against a domain allow-list server-side before fetching."),
    ],
    ".ts": None,
    ".jsx": None,
    ".tsx": None,
    ".java": [
        ("SQL built via string concatenation / Statement",
         re.compile(r"createStatement\s*\(|executeQuery\s*\(\s*\".*\"\s*\+|executeUpdate\s*\(\s*\".*\"\s*\+"),
         "high",
         "Use PreparedStatement with bound parameters."),
        ("XML External Entity (XXE) risk",
         re.compile(r"DocumentBuilderFactory\.newInstance\s*\(|SAXParserFactory\.newInstance\s*\("),
         "medium",
         "Disable external entities: setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true) and disallow-doctype-decl."),
        ("Insecure Deserialization",
         re.compile(r"ObjectInputStream\s*\(|readObject\s*\("),
         "high",
         "Avoid Java deserialization of untrusted data (RCE risk). Prefer JSON + schema validation."),
        ("Hardcoded credentials",
         re.compile(r"(?i)(password|secret|apikey)\s*=\s*\"[^\"]{4,}\""),
         "high",
         "Load secrets from environment, JNDI, or a secrets manager."),
        ("Weak crypto (DES / MD5 / SHA1)",
         re.compile(r"Cipher\.getInstance\s*\(\s*\"(DES|RC4)|MessageDigest\.getInstance\s*\(\s*\"(MD5|SHA-1|SHA1)\""),
         "medium",
         "Use AES-GCM and SHA-256+ / modern password hashing (bcrypt/scrypt/argon2)."),
    ],
    ".kt": [  # Kotlin shares many Java patterns
        ("SQL string interpolation / concatenation",
         re.compile(r"rawQuery\s*\(\s*\".*\$|\.query\s*\(\s*\".*\+"),
         "high",
         "Use parameterized queries or Room / SQLDelight."),
        ("Hardcoded secret",
         re.compile(r"(?i)(api_key|secret|password|token)\s*=\s*\"[^\"]{8,}\""),
         "high",
         "Store secrets in encrypted storage or retrieve from a backend; never hardcode."),
    ],
    ".php": [
        ("SQL Injection (concatenated query)",
         re.compile(r"(mysqli_query|mysql_query|->query)\s*\([^)]*\.\s*\$"),
         "high",
         "Use prepared statements (mysqli/PDO) with bound parameters."),
        ("Use of eval",
         re.compile(r"\beval\s*\("),
         "high",
         "Remove eval(); it is a common RCE vector."),
        ("Command Injection",
         re.compile(r"\b(system|exec|shell_exec|passthru|popen)\s*\(\s*\$"),
         "high",
         "Never pass user input to shell functions. Use escapeshellarg or avoid shelling out."),
        ("File Inclusion (LFI/RFI)",
         re.compile(r"(include|require|include_once|require_once)\s*\(\s*\$"),
         "high",
         "Never include files based on user-controlled paths without strict allow-listing."),
        ("Unserialized user input",
         re.compile(r"unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)"),
         "critical",
         "Never unserialize untrusted data (PHP object injection / RCE)."),
    ],
    ".go": [
        ("SQL built via fmt.Sprintf / concatenation",
         re.compile(r"db\.(Query|Exec|QueryRow)\(fmt\.Sprintf|db\.(Query|Exec)\([^)]*\+"),
         "high",
         "Use parameterized queries with $1, $2 placeholders."),
        ("Disabled TLS verification",
         re.compile(r"InsecureSkipVerify\s*:\s*true"),
         "critical",
         "Never set InsecureSkipVerify: true in production."),
        ("Command execution with shell",
         re.compile(r"exec\.Command\s*\(\s*[\"']?(sh|bash|cmd)"),
         "medium",
         "Prefer direct binary execution with argument slices; avoid shell when possible."),
    ],
    ".rb": [
        ("SQL Injection (string interpolation)",
         re.compile(r"\.(execute|where|find_by_sql)\s*\(.*#\{"),
         "high",
         "Use parameterized queries or ActiveRecord safe methods."),
        ("Command Injection (system / exec / `)",
         re.compile(r"\b(system|exec|`)\s*\(.*#\{"),
         "high",
         "Avoid interpolating user input into shell commands."),
    ],
    ".cs": [
        ("SQL Injection (string concat)",
         re.compile(r"(SqlCommand|ExecuteReader|ExecuteNonQuery).*\+|string\.Format\s*\(.*SELECT"),
         "high",
         "Use parameterized SqlCommand with Parameters.Add."),
        ("Insecure Deserialization (BinaryFormatter)",
         re.compile(r"BinaryFormatter|LosFormatter|NetDataContractSerializer"),
         "critical",
         "BinaryFormatter is dangerous; prefer System.Text.Json or DataContractSerializer with known types."),
        ("Hardcoded connection string / password",
         re.compile(r"(?i)(Password|Pwd)\s*=\s*[^;\"']{4,}"),
         "high",
         "Store connection strings in configuration / Key Vault, not source."),
    ],
    ".xml": [
        ("Android exported component without permission",
         re.compile(r'android:exported\s*=\s*"true"'),
         "medium",
         "Review every exported Activity/Service/Receiver/Provider. Require permissions or set exported=false if not needed."),
        ("Android allowBackup true",
         re.compile(r'android:allowBackup\s*=\s*"true"'),
         "low",
         "Set android:allowBackup=\"false\" unless you explicitly need backup and have tested it."),
        ("Android debuggable true",
         re.compile(r'android:debuggable\s*=\s*"true"'),
         "high",
         "Never ship with android:debuggable=\"true\". It allows runtime inspection and code injection."),
        ("Cleartext traffic permitted",
         re.compile(r'android:usesCleartextTraffic\s*=\s*"true"|cleartextTrafficPermitted\s*=\s*"true"'),
         "high",
         "Disable cleartext HTTP. Force HTTPS and use network security config."),
    ],
    ".gradle": [
        ("Hardcoded signing password / keystore",
         re.compile(r"(?i)(storePassword|keyPassword|password)\s*[=\s]['\"][^'\"]+['\"]"),
         "critical",
         "Never commit keystore passwords. Use environment variables or CI secrets."),
    ],
    ".tf": [
        ("Hardcoded secret in Terraform",
         re.compile(r"(?i)(password|secret|api_key|access_key)\s*=\s*\"[^\"]{6,}\""),
         "critical",
         "Use variables marked sensitive, or pull from a secrets backend (Vault, SSM, Secrets Manager)."),
        ("Public S3 / open security group risk indicators",
         re.compile(r'cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]|0\.0\.0\.0/0'),
         "high",
         "Avoid 0.0.0.0/0 unless absolutely required and reviewed. Prefer least-privilege CIDRs / security groups."),
    ],
    ".yml": [
        ("Hardcoded secret in YAML config",
         re.compile(r"(?i)(password|secret|api[_-]?key|token):\s*[\"']?[A-Za-z0-9\-_/+=]{12,}"),
         "high",
         "Move secrets to environment variables or a secrets manager; never commit them."),
    ],
    ".yaml": None,
    ".json": [
        ("Possible committed service account / key JSON",
         re.compile(r"(?i)\"private_key\"\s*:|\"type\"\s*:\s*\"service_account\""),
         "critical",
         "Service-account JSON keys must never be committed. Use workload identity or short-lived tokens."),
    ],
    ".html": [
        ("Inline script with possible XSS sink",
         re.compile(r"<script[^>]*>[^<]*document\.(write|location)"),
         "medium",
         "Avoid document.write and location assignment with untrusted data."),
    ],
    ".sh": [
        ("Unquoted variable expansion (injection risk)",
         re.compile(r"\b(eval|source|\.)\s+\$\{?\w+"),
         "medium",
         "Quote variables and avoid eval/source of untrusted input."),
        ("Hardcoded credentials in shell",
         re.compile(r"(?i)(password|passwd|secret|token|apikey)=['\"][^'\"]{4,}['\"]"),
         "high",
         "Use environment variables or a secrets manager; never hardcode credentials in scripts."),
    ],
}

RULES[".ts"] = RULES[".js"]
RULES[".jsx"] = RULES[".js"]
RULES[".tsx"] = RULES[".js"]
RULES[".yaml"] = RULES[".yml"]
RULES[".kts"] = RULES[".kt"]
RULES[".properties"] = [
    ("Hardcoded password / secret in properties",
     re.compile(r"(?i)(password|secret|api\.key|token)\s*=\s*\S{4,}"),
     "high",
     "Externalize secrets; do not commit real values."),
]


def scan_files(file_list):
    findings = []
    for path in file_list:
        ext = os.path.splitext(path)[1].lower()
        basename = os.path.basename(path).lower()
        
        # Restrict Android manifest rules strictly to AndroidManifest.xml
        rules = RULES.get(ext)
        if ext == ".xml":
            if basename == "androidmanifest.xml":
                rules = RULES.get(".xml", [])
            else:
                rules = None

        if basename.startswith("dockerfile"):
            rules = [
                ("Dockerfile runs as root / missing USER",
                 re.compile(r"^FROM\s+", re.I),
                 "low",
                 "Add a non-root USER instruction after installing packages to reduce container breakout impact."),
                ("Secrets passed as build ARG / ENV",
                 re.compile(r"(?i)(ARG|ENV)\s+.*(PASSWORD|SECRET|TOKEN|KEY|API)"),
                 "high",
                 "Do not bake secrets into image layers via ARG/ENV. Use runtime secrets or multi-stage carefully."),
            ]

        if not rules:
            continue
        try:
            if os.path.getsize(path) > MAX_FILE_SIZE:
                continue
            with open(path, "r", errors="ignore") as fh:
                content = fh.readlines()
        except Exception:
            continue

        for lineno, line in enumerate(content, start=1):
            for name, pattern, severity, fix in rules:
                if pattern.search(line):
                    findings.append({
                        "type": name,
                        "severity": severity,
                        "file": path,
                        "line": lineno,
                        "snippet": line.strip()[:200],
                        "fix": fix,
                    })
    return findings

