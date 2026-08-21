# 🛡️ Yemanode v2

**Yemanode** is a powerful, multi-target **ethical security scanner** designed for developers, DevOps engineers, and security auditors.

With a single unified CLI, Yemanode performs static security analysis and passive vulnerability checks against **source repositories**, **OpenAPI/Swagger specs & Postman collections**, **live REST APIs**, **JWT tokens**, **Android APK packages**, and **native desktop binaries**.

---

## 🚀 Key Features

| Feature | Target Type | Command | Description |
|---|---|---|---|
| 🌐 **Website URL Loophole Auditor** | Live Website / Web App URL | `yemanode analyse-url` | Conducts full-spectrum hacker-grade loophole audit (TLS, Security Headers, Cookies, CORS, HTTP Verbs, Recon Paths, DOM/Secrets, Redirects, Error Leaks) and generates an executive `.md` fix report with copy-paste configs. |
| 🥷 **Hacker Pentest Engine** | Any Target (Repo/API/APK/Binary/JWT) | `yemanode hacker-test` | Executes progressive pentest attack methods (Levels 1 to 10 max) against any target and generates an action-oriented fix report. |
| 📂 **Source Tree Auditor** | Source Code & IaC | `yemanode scan-repo` | Scans source folders for hardcoded secrets, OWASP Top 10 injection flaws, unsafe patterns, and vulnerable dependencies. Supports `--diff` PR scoping. |
| 🌐 **Live API & Contract Scanner** | REST / OpenAPI / Postman | `yemanode scan-api` | Conducts passive HTTP probes for TLS, security headers, CORS, and audits OpenAPI / Postman specifications for missing auth and security risks. |
| 🔑 **JWT Security Analyzer** | JWT Tokens / Files | `yemanode scan-jwt` | Decodes JWT header/payload to detect unsigned tokens (`alg: none`), weak HMAC algorithms, expired tokens, and leaked PII claims. |
| 📱 **Android APK Analyzer** | Android Packages (`.apk`) | `yemanode scan-apk` | Analyzes Manifest security flags, cleartext traffic, embedded secrets, and insecure file modes. |
| 💻 **Native Binary Scanner** | Executables (`ELF`/`PE`/`Mach-O`) | `yemanode scan-binary` | Extracts strings from native binaries to detect leaked private keys, credentials, and dangerous C functions. |
| ⚡ **API Load & Rate-Limit Tester** | Live API / Gateway URL | `yemanode load-test` | Performs controlled concurrent load testing to audit rate limiting, throughput (RPS), status distribution, and latency percentiles (P50/P95/P99). |


---

## 🔍 Feature Deep Dive

### 1. 🌐 Website URL Loophole & Security Auditor (`analyse-url`)
Full-spectrum offensive & defensive security audit of live websites and web applications with a hacker-grade loophole analysis engine.
- **TLS & Transport Cryptography:** Checks plain HTTP enforcement, HTTP-to-HTTPS 301 redirection, deprecated TLS versions (TLS 1.0/1.1), and SSL certificate expiration & trust.
- **Security Headers & Modern Defenses:** Audits `Strict-Transport-Security` (HSTS), `Content-Security-Policy` (CSP quality, `unsafe-inline`, `unsafe-eval`, `frame-ancestors`), `X-Frame-Options` (Clickjacking), `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`, and `Cross-Origin-Opener-Policy` (COOP).
- **Cookie Security Audit:** Audits all `Set-Cookie` headers for missing `HttpOnly`, missing `Secure`, missing/weak `SameSite` (`Lax`/`Strict`), and prefix conventions (`__Host-`, `__Secure-`).
- **CORS Misconfiguration Probing:** Detects wildcard origins (`*`) with credentials, unvalidated Origin header reflection, and null origin permissions.
- **Dangerous HTTP Methods & Verb Tampering:** Tests for enabled `TRACE` (Cross-Site Tracing / XST) and unauthenticated state-changing `PUT`/`DELETE` verbs.
- **Reconnaissance & Exposed Sensitive Files:** Concurrent probe for exposed `/.env`, `/.git/HEAD`, `/.htaccess`, `/.htpasswd`, `/backup.zip`, `/database.sql`, `/phpinfo.php`, Spring `/actuator/env`, `/metrics`, `/_debugbar`, and admin panels (`/admin`, `/wp-admin/`, `/phpmyadmin/`).
- **robots.txt & security.txt Audit:** Parses `robots.txt` for leaked internal paths and verifies RFC 9116 `/.well-known/security.txt` vulnerability disclosure policies.
- **DOM & Client-Side HTML Security:** Detects reverse tabnabbing (`target="_blank"` without `rel="noopener noreferrer"`), insecure forms submitting over HTTP, missing anti-CSRF tokens in POST forms, mixed content assets, leaked developer comments, and hardcoded secrets/API keys (AWS, Google, Stripe, JWTs) in client scripts.
- **Open Redirect Parameter Audit:** Tests query parameters (`?redirect=`, `?return=`, `?next=`) for unvalidated domain redirection vulnerabilities.
- **Error Stack Trace Leakage:** Probes 404/malformed routes for verbose framework stack traces (Django, Flask, Spring, Express, Rails, ASP.NET, SQL errors).
- **Vulnerability Chaining & Attack Scenarios:** Correlates weaknesses to illustrate realistic hacker attack paths.
- **Executive Score & Action Plan (.md):** Calculates a 0-100 Security Score, Letter Grade (A+ to F), and generates a comprehensive Markdown report with copy-paste Nginx, Apache, and Express remediation snippets.

### 2. 🥷 Hacker Pentest Mode (`hacker-test` / `-H 1..10`)
Progressive offensive security pentesting framework executing up to **10 progressive attack methods** against any target.
- **Max Level Limit:** Level `1` (light scan) to Level `10` (maximum deep attack methods).
- **Progressive Method Levels:**
  - **Level 1:** Hardcoded Secrets & Credential Mining (AWS, GCP, Azure, Slack, GitHub, Private Keys, DB URLs).
  - **Level 2:** Code Injection & RCE Audit (SQLi, NoSQLi, OS Command Injection, `eval`/`exec`, SSTI).
  - **Level 3:** Broken Access Control & Auth Probe (Missing auth headers, basic auth exposure, unauthenticated state-changing verbs).
  - **Level 4:** SSRF & Network Boundary Probe (Localhost/Subnet resolution, internal endpoints, Cloud Metadata `169.254.169.254`).
  - **Level 5:** Transport & Security Header Audit (TLS versions, SSL cert trust, HSTS, CSP, CORS reflection).
  - **Level 6:** Deserialization & XXE Security Probe (`pickle`, `ObjectInputStream`, `unserialize`, XML DTD parsing).
  - **Level 7:** Information Disclosure & Path Enumeration (`/.env`, `/.git`, `/actuator`, `/swagger.json`, `/metrics`, stack traces).
  - **Level 8:** Data Protection & Token Security Audit (JWT `alg: none`, weak HMAC keys, MD5/SHA1 hashing, PII leakage).
  - **Level 9:** Infrastructure as Code & Container Hardening (Terraform `0.0.0.0/0`, Dockerfile root user, ENV secrets).
  - **Level 10:** Supply Chain & Vulnerable Dependency Audit (`pip-audit`, `npm audit`, vulnerable manifest versions).

### 2. Source Repository & Codebase Scanner (`scan-repo`)
Deep static analysis across multi-language source trees.
- **Language Detection:** Automatically identifies Python, JavaScript/TypeScript, Java, Kotlin, Go, PHP, Ruby, Rust, C/C++, C#, Shell, HTML, Dockerfile, Terraform, and configuration files.
- **Git PR Diff Scoping (`--diff`):** Restricts security scans strictly to files modified relative to a base branch (e.g., `--diff-base origin/main`) for fast CI/CD pull-request checks.
- **Hardcoded Secret Detection:** Scans source code for AWS/GCP/Azure keys, GitHub PATs, Slack/Stripe/Twilio tokens, PEM blocks, and DB strings.
- **OWASP Top 10 Insecure Code Pattern Auditing:** SQL Injection, Command Injection, SSRF, SSTI, XXE, Insecure Deserialization, `eval()`/`exec()`, Weak Crypto (MD5/SHA1), IaC Terraform/Dockerfile secrets.
- **Dependency Vulnerability Scanning:** Executes `pip-audit` for Python or `npm audit` for Node.js projects.

### 3. Live API Endpoint & Specification Scanner (`scan-api`)
Passive, non-destructive security probes designed for REST APIs, AWS API Gateway endpoints, OpenAPI/Swagger specifications, and Postman collections.
- **OpenAPI & Postman Contract Auditing (`-s / --spec`):** Parses OpenAPI v2/v3 (`.json` / `.yaml`) and Postman Collections. Flags endpoints missing auth declarations, unauthenticated `PUT`/`DELETE` verbs, and `http` schemes.
- **TLS & Certificate Validation:** Enforces HTTPS, checks outdated TLS versions, and validates SSL certificate trust.
- **Security Headers Audit:** Detects missing standard security headers (`HSTS`, `X-Content-Type-Options`, `CSP`, `X-Frame-Options`, `Referrer-Policy`).
- **CORS & Verb Probing:** Detects wildcard origin (`*`), credential reflection, and risky HTTP methods (`PUT`, `DELETE`, `PATCH`, `TRACE`).
- **Information Disclosure & SSRF:** Probes exposed paths (`/.env`, `/.git`, `/actuator`, `/swagger.json`) and alerts on private/loopback resolution.

### 4. JWT Security Analyzer (`scan-jwt`)
Structural JWT token decoder and claim security auditor (no secret key required).
- **Unsigned Tokens:** Flags critical `alg: "none"` bypass attempts.
- **Weak Algorithms & Injection:** Alerts on symmetric `HS256` usage and inline key injection headers (`jwk` / `jku`).
- **Expiration & Claim Leaks:** Audits missing `exp` claims and leaks of sensitive user data (`password`, `ssn`, `api_key`).

### 5. Android APK Security Scanner (`scan-apk`)
Static analysis of compiled Android APK files without requiring heavy external reverse-engineering setups.
- **Manifest Auditing:** Checks `AndroidManifest.xml` for `debuggable="true"`, `allowBackup="true"`, `usesCleartextTraffic="true"`, and exported components.
- **Secret & Mode Mining:** Extracts embedded API keys and detects deprecated `MODE_WORLD_READABLE`/`WRITEABLE` flags.

### 6. Desktop & Native Binary Scanner (`scan-binary`)
Lightweight static string and pattern analysis for compiled binaries (`ELF`, `PE`, `Mach-O`).
- Identifies dangerous buffer-overflow prone functions (`gets`, `strcpy`, `sprintf`, `scanf`) and mines embedded secrets.

---

## 📥 Installation

### Automated Installer (Recommended)
Clone or extract the repository and run `install.sh`:
```bash
./install.sh
```

### Manual Installation
```bash
pipx install . --force
# or
pip3 install --user .
```

---

## 💡 How to Use Yemanode

### Mode A: Interactive Menu (Recommended for Beginners)
Simply run `yemanode` with no arguments:
```bash
yemanode
```
**Interactive Prompt Example:**
```text
  __   _____ __  __    _    _   _  ___  ____  _____
  \ \ / / _ \  \/  |  / \  | \ | |/ _ \|  _ \| ____|
   \ V /  __/ |\/| | / _ \ |  \| | |_| | |_) |  _|  
    |_| \___|_|  |_/_/   \_\_| \_|\___/|____/|_____|

  Multi-target ethical security scanner  v2.0.0
  Targets: source folder · Website URLs · API / OpenAPI · JWT · APK · binary · Hacker Mode (L1-10) · Load Testing

What would you like to scan?

  [1] Local source / project folder
  [2] Live API URL or OpenAPI / Postman spec
  [3] 🌐 Website URL Loophole & Security Auditor (analyse-url)
  [4] Android APK file
  [5] Desktop / native binary (ELF, PE, Mach-O, etc.)
  [6] JWT Token / payload analyzer
  [7] 🥷 Hacker Pentest Mode (Progressive Attack Levels 1 to 10)
  [8] ⚡ API Load Test & Rate-Limit Audit

Choice [1]: 3
```

---

### Mode B: Direct Command Line Interface (CLI)

#### 1. 🌐 Website URL Loophole & Security Auditor (`analyse-url`)
Conduct full-spectrum loophole analysis against any website or web application and generate an executive Markdown fix report:
```bash
# Analyze a live website URL and generate a comprehensive .md loophole report:
yemanode analyse-url https://mywebsite.com

# Custom output report path:
yemanode analyse-url https://mywebsite.com -o ./WEBSITE_AUDIT_REPORT.md

# Export in multiple formats simultaneously (Markdown, JSON, HTML, SARIF):
yemanode analyse-url https://mywebsite.com -f all

# Fast scan without deep path enumeration:
yemanode analyse-url https://mywebsite.com --no-deep
```

#### 2. 🥷 Running Hacker Pentest Mode (`hacker-test`)
Execute progressive attack testing methods (Levels 1 to 10 max) against any target:
```bash
# Run Level 5 Pentest against a repository:
yemanode hacker-test ./my-project -H 5


# Run Maximum Level 10 Pentest against an API endpoint:
yemanode hacker-test https://api.example.com -H 10

# Run Level 7 Pentest against an OpenAPI spec file:
yemanode hacker-test ./openapi.yaml -H 7
```

#### 3. Scanning a Source Code Folder (`scan-repo`)
Point Yemanode to any local project folder:
```bash
yemanode scan-repo /path/to/your/project
```
**Git PR Diff Scoped Scanning:**
```bash
yemanode scan-repo ./src --diff --diff-base origin/main
```

#### 4. Scanning a Live API or OpenAPI Contract (`scan-api`)
Test a live REST API or OpenAPI contract:
```bash
yemanode scan-api https://api.example.com/prod
yemanode scan-api -s ./openapi.yaml
```

#### 5. Auditing JWT Tokens (`scan-jwt`)
Analyze a raw JWT string or token file:
```bash
yemanode scan-jwt "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicGFzc3dvcmQiOiJzZWNyZXQxMjMifQ."
```

#### 6. Scanning an Android APK (`scan-apk`)
Analyze an `.apk` file:
```bash
yemanode scan-apk ./myapp.apk
```

#### 7. Scanning a Native Desktop Binary (`scan-binary`)
Analyze a Linux ELF, Windows EXE/DLL, or macOS binary:
```bash
yemanode scan-binary /usr/local/bin/custom_tool
```

#### 8. API Load & Rate-Limit Testing (`load-test`)
Audit API performance, rate limiting, and latency under concurrent load:
```bash
yemanode load-test https://api.example.com/items -n 100 -c 10
```


---

## 📊 Markdown Report & Severity System

Every scan produces a detailed, structured Markdown security report with explicit action steps to resolve findings.

### Severity Hierarchy
- 🔴 **CRITICAL:** High-impact flaws (Leaked Private Keys, Hardcoded AWS Secrets, Zip Slip, `alg: none` JWTs, Disabling TLS Verification).
- 🟠 **HIGH:** Exploitable vulnerabilities (SQL Injection, Command Injection, SSRF, SSTI, Unauthenticated Sensitive APIs, Debuggable APKs).
- 🟡 **MEDIUM:** Misconfigurations (Missing HSTS Header, Stack Trace Leakage, XXE Risk, Missing `exp` Claim, Dangerous Functions).
- 🔵 **LOW:** Hardening recommendations (Missing `X-Content-Type-Options`, Verbose `Server` headers, `allowBackup=true`).
- ⚪ **INFO:** Information disclosure and scan environment details.

---

## 🗑️ Uninstallation

```bash
./uninstall.sh
```

---

## ⚖️ Scope & Ethical Use Directive

- **Passive & Static Analysis Only:** Yemanode performs static code analysis and non-destructive passive HTTP probes. It deliberately does **not** send exploit payloads, perform dynamic instrumentation, or attempt brute-force authentication bypasses.
- **Authorization Required:** Only scan systems, applications, and APIs that you own or have explicit, written permission to test. Unauthorized security testing against third-party systems is illegal.
