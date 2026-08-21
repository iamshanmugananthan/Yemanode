"""
Expanded pattern-based static analysis for common vulnerability classes.
Covers SQLi/NoSQLi, Command Injection, SSRF, XSS, Path Traversal, Deserialization,
Auth flaws, Insecure Crypto, Docker, Kubernetes, and Terraform misconfigurations.
"""
import os
import re

MAX_FILE_SIZE = 5_000_000

# Language / extension specific rules: (name, pattern, severity, cwe, owasp, cvss, fix)
RULES = {
    ".py": [
        ("SQL Injection (string formatting / concat into query)",
         re.compile(r"(execute|executemany|raw)\s*\(\s*(f['\"]|['\"].*%|['\"].*\+|\.format\()"),
         "high", "CWE-89", "A03:2021-Injection", 8.8,
         "Use parameterized queries: cursor.execute(sql, (param,)) or an ORM. Never build SQL with f-strings, %, or +."),
        ("NoSQL Injection (dynamic query construction)",
         re.compile(r"(find|find_one|update|delete)\s*\(\s*\{[^}]*\$where\s*:"),
         "high", "CWE-943", "A03:2021-Injection", 8.5,
         "Avoid using $where or building MongoDB queries with unvalidated user input strings."),
        ("Use of eval / exec (RCE Risk)",
         re.compile(r"\b(eval|exec)\s*\("),
         "critical", "CWE-95", "A03:2021-Injection", 9.8,
         "Avoid eval()/exec() on untrusted input. Prefer ast.literal_eval or a proper data parser."),
        ("Insecure Deserialization (pickle / yaml.load)",
         re.compile(r"\bpickle\.(load|loads)\s*\(|yaml\.load\s*\((?!.*Loader=yaml\.SafeLoader)"),
         "critical", "CWE-502", "A08:2021-Software and Data Integrity Failures", 9.8,
         "Never unpickle untrusted data. Use yaml.safe_load() or JSON for data serialization."),
        ("Command Injection (os.system / shell=True)",
         re.compile(r"os\.system\s*\(|subprocess\.[A-Za-z]+\([^)]*shell\s*=\s*True"),
         "critical", "CWE-78", "A03:2021-Injection", 9.8,
         "Use subprocess with a list of arguments and shell=False. Never pass raw user input to a shell."),
        ("Path Traversal (unvalidated file path)",
         re.compile(r"(open|send_file|send_from_directory)\s*\(\s*(f['\"]|['\"].*\+|request\.(args|form|values|json))"),
         "high", "CWE-22", "A01:2021-Broken Access Control", 8.6,
         "Sanitize and validate paths using os.path.abspath and verify they reside within the intended base directory (werkzeug.utils.secure_filename)."),
        ("Server-Side Request Forgery (SSRF Risk)",
         re.compile(r"requests\.(get|post|put|delete|request|head)\s*\(\s*(?!['\"]https?://)[A-Za-z0-9_.]+\b"),
         "high", "CWE-918", "A10:2021-Server-Side Request Forgery", 8.6,
         "Validate and sanitize user-supplied URLs against an allow-list of domains before making HTTP requests. Block cloud metadata IPs (169.254.169.254)."),
        ("Server-Side Template Injection (SSTI)",
         re.compile(r"render_template_string\s*\(|jinja2\.Template\s*\([^)]*f['\"]"),
         "high", "CWE-1336", "A03:2021-Injection", 8.8,
         "Avoid passing dynamic string templates or f-strings to render_template_string(). Use static template files."),
        ("XML External Entity (XXE Risk)",
         re.compile(r"etree\.parse\s*\(|xml\.dom\.minidom\.parse|xml\.sax\.make_parser"),
         "high", "CWE-611", "A05:2021-Security Misconfiguration", 7.5,
         "Ensure XML parsers disable external entity resolution (defusedxml or resolve_entities=False)."),
        ("Debug Mode Enabled in Production",
         re.compile(r"(?i)(DEBUG|debug)\s*=\s*True|app\.run\([^)]*debug\s*=\s*True"),
         "medium", "CWE-489", "A05:2021-Security Misconfiguration", 6.5,
         "Ensure DEBUG is False in production environments to avoid leaking interactive debuggers, stack traces, and internal secrets."),
        ("Weak Hash Algorithm (MD5 / SHA1)",
         re.compile(r"\bhashlib\.(md5|sha1)\s*\("),
         "medium", "CWE-328", "A02:2021-Cryptographic Failures", 5.9,
         "Use SHA-256+ for checksums/integrity. For passwords, use bcrypt, scrypt, or argon2."),
        ("Hardcoded Application Secret Key",
         re.compile(r"(?i)(SECRET_KEY|secret_key|JWT_SECRET)\s*=\s*['\"][^'\"]{8,}['\"]"),
         "critical", "CWE-798", "A01:2021-Broken Access Control", 8.9,
         "Load SECRET_KEY from environment variables or a secrets manager. Rotate immediately if committed."),
        ("Insecure Random for Cryptographic Operations",
         re.compile(r"\brandom\.(random|randint|choice|randrange)\s*\("),
         "low", "CWE-330", "A02:2021-Cryptographic Failures", 3.7,
         "For security-sensitive tokens, passwords, and nonce generation, use the 'secrets' module instead of 'random'."),
        ("Assert Statement Used for Authorization",
         re.compile(r"\bassert\s+.*(auth|permission|admin|role|is_valid|user)"),
         "medium", "CWE-617", "A01:2021-Broken Access Control", 6.5,
         "Assert statements are stripped when Python runs with optimization (-O). Use explicit if/raise checks for security enforcement."),
        ("Open Redirect Risk",
         re.compile(r"redirect\s*\(\s*request\.(args|form|values)"),
         "medium", "CWE-601", "A01:2021-Broken Access Control", 6.1,
         "Validate redirect targets against a strict allow-list of local URLs or trusted domains."),
    ],
    ".js": [
        ("SQL Injection (template literal / concat in query)",
         re.compile(r"\.query\s*\(\s*`[^`]*\$\{|\.query\s*\(\s*['\"].*\+"),
         "high", "CWE-89", "A03:2021-Injection", 8.8,
         "Use parameterized queries (?, $1) or an ORM. Never concatenate variables into SQL query strings."),
        ("NoSQL Injection (direct query parameter passing)",
         re.compile(r"(find|findOne|update|remove)\s*\(\s*(req\.(body|query|params)|req\.(body|query|params)\.[a-zA-Z0-9_]+)\s*\)"),
         "high", "CWE-943", "A03:2021-Injection", 8.5,
         "Sanitize input and enforce types to prevent Mongo operator injection (e.g. { $gt: '' })."),
        ("Cross-Site Scripting (innerHTML / dangerouslySetInnerHTML)",
         re.compile(r"\.innerHTML\s*=|dangerouslySetInnerHTML\s*=\s*\{"),
         "medium", "CWE-79", "A03:2021-Injection", 6.1,
         "Prefer textContent or sanitize HTML with DOMPurify before rendering untrusted markup."),
        ("Use of eval / Function constructor",
         re.compile(r"\beval\s*\(|new\s+Function\s*\("),
         "critical", "CWE-95", "A03:2021-Injection", 9.8,
         "Avoid eval() and dynamic Function execution. Parse JSON with JSON.parse()."),
        ("Command Injection (child_process.exec)",
         re.compile(r"child_process\.(exec|execSync)\s*\("),
         "critical", "CWE-78", "A03:2021-Injection", 9.8,
         "Prefer child_process.execFile or spawn with argument arrays without shell interpolation."),
        ("Path Traversal (fs file reading with user input)",
         re.compile(r"fs\.(readFile|readFileSync|createReadStream)\s*\([^)]*req\.(params|query|body)"),
         "high", "CWE-22", "A01:2021-Broken Access Control", 8.6,
         "Validate file paths with path.resolve() and verify they remain within a safe root directory."),
        ("Disabled TLS Certificate Verification",
         re.compile(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"),
         "critical", "CWE-295", "A02:2021-Cryptographic Failures", 9.1,
         "Never disable TLS verification in production. It makes applications vulnerable to Man-in-the-Middle attacks."),
        ("SSRF Risk (dynamic fetch / axios URL)",
         re.compile(r"(fetch|axios\.(get|post|put|delete))\s*\(\s*(?!['\"]https?://)[A-Za-z0-9_.]+\b"),
         "high", "CWE-918", "A10:2021-Server-Side Request Forgery", 8.6,
         "Validate target URLs against an allowed domain list server-side before fetching."),
        ("Sensitive Data Stored in LocalStorage",
         re.compile(r"localStorage\.(setItem|getItem)\s*\(\s*['\"][^'\"]*(token|password|secret|key|auth)"),
         "medium", "CWE-312", "A04:2021-Insecure Design", 5.3,
         "Avoid storing tokens and credentials in localStorage (accessible via XSS). Prefer HttpOnly, Secure cookies."),
    ],
    ".ts": None,
    ".jsx": None,
    ".tsx": None,
    ".java": [
        ("SQL Injection (concatenated Statement)",
         re.compile(r"createStatement\s*\(|executeQuery\s*\(\s*\".*\"\s*\+|executeUpdate\s*\(\s*\".*\"\s*\+"),
         "high", "CWE-89", "A03:2021-Injection", 8.8,
         "Use PreparedStatement with parameterized query binding (?, :param)."),
        ("Command Injection (Runtime.exec / ProcessBuilder)",
         re.compile(r"Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+|new\s+ProcessBuilder\s*\([^)]*\+"),
         "critical", "CWE-78", "A03:2021-Injection", 9.8,
         "Pass command arguments as separate array elements and never interpolate untrusted strings."),
        ("Path Traversal (File / FileInputStream with dynamic path)",
         re.compile(r"new\s+(File|FileInputStream|FileOutputStream)\s*\([^)]*(request\.getParameter|req\.getParameter)"),
         "high", "CWE-22", "A01:2021-Broken Access Control", 8.6,
         "Use Path.normalize() and verify getPath() starts with the canonical root directory."),
        ("XML External Entity (XXE Risk)",
         re.compile(r"DocumentBuilderFactory\.newInstance\s*\(|SAXParserFactory\.newInstance\s*\("),
         "high", "CWE-611", "A05:2021-Security Misconfiguration", 7.5,
         "Disable external entity parsing: setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)."),
        ("Insecure Deserialization (ObjectInputStream)",
         re.compile(r"ObjectInputStream\s*\(|readObject\s*\("),
         "critical", "CWE-502", "A08:2021-Software and Data Integrity Failures", 9.8,
         "Avoid Java native serialization on untrusted data. Prefer JSON/Protobuf with strict schema validation."),
        ("Weak Cryptography (DES / MD5 / SHA-1)",
         re.compile(r"Cipher\.getInstance\s*\(\s*\"(DES|RC4)|MessageDigest\.getInstance\s*\(\s*\"(MD5|SHA-1|SHA1)\""),
         "medium", "CWE-327", "A02:2021-Cryptographic Failures", 5.9,
         "Use AES/GCM/NoPadding for encryption and SHA-256+ / Argon2 for hashing."),
    ],
    ".kt": [
        ("SQL Injection (rawQuery string interpolation)",
         re.compile(r"rawQuery\s*\(\s*\".*\$|\.query\s*\(\s*\".*\+"),
         "high", "CWE-89", "A03:2021-Injection", 8.8,
         "Use Room ORM, SQLDelight, or parameterized queries with selectionArgs."),
        ("Insecure WebView Settings (JavaScript / File Access)",
         re.compile(r"setJavaScriptEnabled\s*\(\s*true\s*\)|setAllowFileAccess\s*\(\s*true\s*\)"),
         "medium", "CWE-749", "A01:2021-Broken Access Control", 6.5,
         "Disable file access and limit JavaScript interfaces to trusted origins in WebViews."),
    ],
    ".php": [
        ("SQL Injection (concatenated query parameter)",
         re.compile(r"(mysqli_query|mysql_query|->query|->exec)\s*\([^)]*\.\s*\$"),
         "high", "CWE-89", "A03:2021-Injection", 8.8,
         "Use PDO prepared statements with bound parameters."),
        ("Use of eval (RCE Vector)",
         re.compile(r"\beval\s*\("),
         "critical", "CWE-95", "A03:2021-Injection", 9.8,
         "Remove eval(); execute pre-defined logic instead."),
        ("Command Injection (system / exec / shell_exec)",
         re.compile(r"\b(system|exec|shell_exec|passthru|popen)\s*\(\s*\$"),
         "critical", "CWE-78", "A03:2021-Injection", 9.8,
         "Avoid shelling out. If necessary, use escapeshellcmd() and escapeshellarg()."),
        ("File Inclusion / Path Traversal (LFI/RFI)",
         re.compile(r"(include|require|include_once|require_once)\s*\(\s*\$_(GET|POST|REQUEST)"),
         "critical", "CWE-98", "A03:2021-Injection", 9.8,
         "Never include files using user-controlled parameters. Use a strict whitelist."),
        ("Insecure Deserialization (unserialize)",
         re.compile(r"unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)"),
         "critical", "CWE-502", "A08:2021-Software and Data Integrity Failures", 9.8,
         "Never pass untrusted user data to unserialize(). Prefer json_decode()."),
        ("Cross-Site Scripting (echo unescaped input)",
         re.compile(r"echo\s+\$_(GET|POST|REQUEST)"),
         "medium", "CWE-79", "A03:2021-Injection", 6.1,
         "Escape output with htmlspecialchars($val, ENT_QUOTES, 'UTF-8')."),
    ],
    ".go": [
        ("SQL Injection (fmt.Sprintf / concat into query)",
         re.compile(r"db\.(Query|Exec|QueryRow)\(fmt\.Sprintf|db\.(Query|Exec)\([^)]*\+"),
         "high", "CWE-89", "A03:2021-Injection", 8.8,
         "Use parameterized queries with $1, $2 or ? placeholders."),
        ("Disabled TLS Verification (InsecureSkipVerify)",
         re.compile(r"InsecureSkipVerify\s*:\s*true"),
         "critical", "CWE-295", "A02:2021-Cryptographic Failures", 9.1,
         "Never set InsecureSkipVerify: true in production code."),
        ("Command Injection (exec.Command with shell)",
         re.compile(r"exec\.Command\s*\(\s*[\"']?(sh|bash|cmd)"),
         "medium", "CWE-78", "A03:2021-Injection", 6.5,
         "Execute the target binary directly with argument slices rather than invoking a shell."),
        ("Path Traversal (os.Open with user input)",
         re.compile(r"os\.(Open|ReadFile|Create)\s*\([^)]*r\.(URL\.Query|FormValue)"),
         "high", "CWE-22", "A01:2021-Broken Access Control", 8.6,
         "Use filepath.Clean and verify strings.HasPrefix(targetPath, baseDir)."),
    ],
    ".rb": [
        ("SQL Injection (string interpolation in query)",
         re.compile(r"\.(execute|where|find_by_sql)\s*\(.*#\{"),
         "high", "CWE-89", "A03:2021-Injection", 8.8,
         "Use ActiveRecord hash syntax or parameterized queries: where('name = ?', name)."),
        ("Command Injection (system / exec / backticks)",
         re.compile(r"\b(system|exec|`)\s*\(?.*#\{"),
         "critical", "CWE-78", "A03:2021-Injection", 9.8,
         "Pass command arguments as separate array elements: system('ls', '-l', dir)."),
        ("Insecure Deserialization (Marshal.load)",
         re.compile(r"Marshal\.load\s*\("),
         "critical", "CWE-502", "A08:2021-Software and Data Integrity Failures", 9.8,
         "Avoid Marshal.load on untrusted data. Prefer JSON.parse."),
    ],
    ".cs": [
        ("SQL Injection (string formatting / concatenation)",
         re.compile(r"(SqlCommand|ExecuteReader|ExecuteNonQuery).*\+|string\.Format\s*\(.*(SELECT|INSERT|UPDATE|DELETE)"),
         "high", "CWE-89", "A03:2021-Injection", 8.8,
         "Use parameterized SqlCommand with SqlParameter objects."),
        ("Insecure Deserialization (BinaryFormatter)",
         re.compile(r"BinaryFormatter|LosFormatter|NetDataContractSerializer"),
         "critical", "CWE-502", "A08:2021-Software and Data Integrity Failures", 9.8,
         "BinaryFormatter is insecure and obsolete. Use System.Text.Json or Newtonsoft.Json with TypeNameHandling.None."),
    ],
    ".rs": [
        ("Unsafe Code Block Detected",
         re.compile(r"\bunsafe\s*\{"),
         "low", "CWE-242", "A06:2021-Vulnerable and Outdated Components", 3.0,
         "Review unsafe blocks to verify pointer safety, memory alignment, and absence of data races."),
        ("Command Injection (std::process::Command with sh)",
         re.compile(r"Command::new\s*\(\s*\"(sh|bash|cmd)\""),
         "medium", "CWE-78", "A03:2021-Injection", 6.5,
         "Call the executable directly and pass arguments using .arg() instead of invoking a shell."),
    ],
    ".xml": [
        ("Android Exported Component Without Permission",
         re.compile(r'android:exported\s*=\s*"true"'),
         "medium", "CWE-926", "A01:2021-Broken Access Control", 6.5,
         "Review exported Activities/Services/Receivers. Add android:permission or set android:exported=\"false\"."),
        ("Android Backup Enabled (allowBackup)",
         re.compile(r'android:allowBackup\s*=\s*"true"'),
         "low", "CWE-524", "A04:2021-Insecure Design", 3.3,
         "Set android:allowBackup=\"false\" to prevent unauthorized data extraction via adb backup."),
        ("Android Debuggable Build Flag",
         re.compile(r'android:debuggable\s*=\s*"true"'),
         "critical", "CWE-489", "A05:2021-Security Misconfiguration", 8.8,
         "Never ship production apps with android:debuggable=\"true\". It allows runtime code injection."),
        ("Cleartext HTTP Traffic Permitted",
         re.compile(r'android:usesCleartextTraffic\s*=\s*"true"|cleartextTrafficPermitted\s*=\s*"true"'),
         "high", "CWE-319", "A02:2021-Cryptographic Failures", 7.4,
         "Enforce HTTPS by setting android:usesCleartextTraffic=\"false\" and configuring networkSecurityConfig."),
    ],
    ".tf": [
        ("Public Ingress / Open CIDR (0.0.0.0/0)",
         re.compile(r'cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]|0\.0\.0\.0/0'),
         "high", "CWE-284", "A05:2021-Security Misconfiguration", 7.5,
         "Restrict security group ingress to specific trusted CIDRs or security groups. Avoid open 0.0.0.0/0 rules."),
        ("Unencrypted S3 Bucket / Volume",
         re.compile(r'server_side_encryption_configuration\s*\{\s*rule\s*\{\s*apply_server_side_encryption_by_default\s*\{\s*sse_algorithm\s*=\s*"AES256"'),
         "low", "CWE-311", "A02:2021-Cryptographic Failures", 4.3,
         "Ensure server-side encryption is enabled using KMS or AES256 for all storage resources."),
    ],
    ".yml": [
        ("Kubernetes Privileged Container",
         re.compile(r'privileged\s*:\s*true'),
         "critical", "CWE-250", "A05:2021-Security Misconfiguration", 8.8,
         "Avoid running containers in privileged mode. Use granular Linux capabilities instead."),
        ("Kubernetes HostPath Mount",
         re.compile(r'hostPath\s*:'),
         "high", "CWE-22", "A01:2021-Broken Access Control", 7.5,
         "Avoid hostPath volume mounts as they allow container escapes to the underlying node filesystem."),
        ("Kubernetes Privilege Escalation Allowed",
         re.compile(r'allowPrivilegeEscalation\s*:\s*true'),
         "high", "CWE-250", "A05:2021-Security Misconfiguration", 7.5,
         "Set securityContext.allowPrivilegeEscalation: false to prevent child processes from gaining more privileges."),
        ("Hardcoded Secret in YAML Configuration",
         re.compile(r"(?i)(password|secret|api[_-]?key|token):\s*[\"']?[A-Za-z0-9\-_/+=]{16,}"),
         "high", "CWE-798", "A01:2021-Broken Access Control", 7.9,
         "Move secrets to environment variables or a secrets manager (Kubernetes Secrets, Vault)."),
    ],
    ".yaml": None,
    ".sh": [
        ("Unquoted Variable Expansion (Command Injection)",
         re.compile(r"\b(eval|source|\.)\s+\$\{?\w+"),
         "high", "CWE-78", "A03:2021-Injection", 8.2,
         "Always quote variable expansions \"$VAR\" and avoid eval or source on dynamic variables."),
    ],
    ".html": [
        ("DOM XSS Sink (document.write / location.href)",
         re.compile(r"document\.write\s*\(|location\.href\s*=\s*location\."),
         "medium", "CWE-79", "A03:2021-Injection", 6.1,
         "Avoid writing unvalidated URL parameters directly into the DOM."),
    ],
}

RULES[".ts"] = RULES[".js"]
RULES[".jsx"] = RULES[".js"]
RULES[".tsx"] = RULES[".js"]
RULES[".yaml"] = RULES[".yml"]
RULES[".kts"] = RULES[".kt"]


def scan_files(file_list):
    """Performs deep pattern-based static security analysis across source files."""
    findings = []
    
    for path in file_list:
        ext = os.path.splitext(path)[1].lower()
        basename = os.path.basename(path).lower()

        # Handle Dockerfile rules
        rules = RULES.get(ext)
        if basename == "dockerfile" or basename.startswith("dockerfile."):
            rules = [
                ("Dockerfile Runs as Root / Missing Non-Root USER",
                 re.compile(r"^FROM\s+", re.I),
                 "low", "CWE-250", "A05:2021-Security Misconfiguration", 3.8,
                 "Add a non-root 'USER appuser' instruction after installing system packages to reduce breakout risk."),
                ("Secrets Passed as Build ARG / ENV",
                 re.compile(r"(?i)(ARG|ENV)\s+.*(PASSWORD|SECRET|TOKEN|API_KEY|KEY)"),
                 "high", "CWE-798", "A01:2021-Broken Access Control", 7.5,
                 "Do not bake credentials into Docker image layers. Use buildkit secrets (--mount=type=secret) or runtime env vars."),
            ]
        elif ext == ".xml":
            if basename != "androidmanifest.xml":
                rules = None

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
            if "re.compile(" in line or "RULES = {" in line:
                continue
            for rule in rules:
                name, pattern, severity, cwe, owasp, cvss, fix = rule[0], rule[1], rule[2], rule[3], rule[4], rule[5], rule[6]
                if pattern.search(line):
                    findings.append({
                        "type": f"[SAST Vulnerability] {name}",
                        "severity": severity,
                        "file": path,
                        "line": lineno,
                        "cwe": cwe,
                        "owasp": owasp,
                        "cvss": cvss,
                        "snippet": line.strip()[:200],
                        "fix": fix,
                    })
    return findings

