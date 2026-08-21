# 🛡️ Yemanode v2

**Yemanode** is a powerful, multi-target **ethical security scanner** designed for developers, DevOps engineers, and security auditors.

With a single unified CLI, Yemanode performs static security analysis and passive vulnerability checks against **source repositories**, **live REST APIs**, **Android APK packages**, and **native desktop binaries**.

---

## 🚀 Key Features

| Feature | Target Type | Command | Description |
|---|---|---|---|
| 📂 **Source Tree Auditor** | Source Code & IaC | `yemanode scan-repo` | Scans source folders for hardcoded secrets, injection flaws, unsafe patterns, and vulnerable dependencies. |
| 🌐 **Live API Scanner** | REST / AWS API Gateway | `yemanode scan-api` | Conducts passive HTTP probes for TLS configuration, missing headers, CORS flaws, and path disclosure. |
| 📱 **Android APK Analyzer** | Android Packages (`.apk`) | `yemanode scan-apk` | Analyzes Manifest security flags, cleartext traffic, embedded secrets, and insecure file modes. |
| 💻 **Native Binary Scanner** | Executables (`ELF`/`PE`/`Mach-O`) | `yemanode scan-binary` | Extracts strings from native binaries to detect leaked private keys, credentials, and dangerous C functions. |

---

## 🔍 Feature Deep Dive

### 1. Source Repository & Codebase Scanner (`scan-repo`)
Deep static analysis across multi-language source trees.
- **Language Detection:** Automatically identifies Python, JavaScript/TypeScript, Java, Kotlin, Go, PHP, Ruby, Rust, C/C++, C#, Shell, HTML, Dockerfile, Terraform, and configuration files.
- **Hardcoded Secret Detection:** Scans source code for:
  - AWS Access Keys & Secret Keys
  - Google Cloud API Keys & OAuth Client Secrets
  - Azure Storage Keys & Client Secrets
  - GitHub PATs & Fine-Grained Tokens
  - Slack Tokens & Webhooks, Stripe Live Keys, Twilio SID, SendGrid Keys
  - JWT Tokens, Private Key Blocks (`PEM`, `OPENSSH`, `RSA`)
  - Database Connection Strings (`PostgreSQL`, `MySQL`, `MongoDB`, `Redis`)
- **Insecure Code Pattern Auditing:**
  - **SQL Injection:** String concatenation/formatting into query functions.
  - **Command Injection:** `os.system`, `subprocess(shell=True)`, `child_process.exec`, `system()`, `passthru()`.
  - **Insecure Deserialization:** Python `pickle`/`yaml.load`, Java `ObjectInputStream`, PHP `unserialize`, .NET `BinaryFormatter`.
  - **Dangerous Execution:** `eval()`, `exec()`, `document.write()`.
  - **Crypto & Secrets:** Weak hashing (`MD5`, `SHA1`), insecure random generators, hardcoded `SECRET_KEY`.
  - **Infrastructure as Code (IaC):** Open Terraform Security Groups (`0.0.0.0/0`), Dockerfile secrets passed in `ARG`/`ENV`.
- **Dependency Vulnerability Scanning:** Automatically executes `pip-audit` for Python manifests or `npm audit` for Node.js projects when available.

### 2. Live API Endpoint Security Prober (`scan-api`)
Passive, non-destructive security probes designed for REST APIs and AWS API Gateway endpoints.
- **TLS & Certificate Validation:** Enforces HTTPS, checks for outdated TLS versions (TLS 1.0 / 1.1), and validates SSL certificate trust.
- **Security Headers Audit:** Detects missing standard security headers:
  - `Strict-Transport-Security` (HSTS)
  - `X-Content-Type-Options: nosniff`
  - `Content-Security-Policy` (CSP)
  - `X-Frame-Options: DENY`
  - `Referrer-Policy` & `Permissions-Policy`
  - `Cache-Control` for sensitive data
- **Authentication Enforcement:** Checks if the endpoint returns sensitive payload data without credentials.
- **Stack Trace & Error Leakage:** Identifies unhandled exceptions leaking internal framework details (e.g., Python `Traceback`, Java `NullPointerException`, SQL errors).
- **CORS Misconfiguration:** Detects wildcard origin (`*`), unsafe credentials combination (`Access-Control-Allow-Credentials: true`), and arbitrary origin reflection.
- **Unnecessary HTTP Verbs:** Probes for enabled risky HTTP methods (`PUT`, `DELETE`, `PATCH`, `TRACE`, `CONNECT`).
- **Information Disclosure:** Probes for exposed administrative and configuration endpoints (`/.env`, `/.git/HEAD`, `/swagger.json`, `/openapi.json`, `/actuator`, `/debug`, `/metrics`).
- **SSRF Warning System:** Alerts when target endpoints resolve to loopback or private subnet addresses.

### 3. Android APK Security Scanner (`scan-apk`)
Static analysis of compiled Android APK files without requiring heavy external reverse-engineering setups.
- **Manifest Security Flag Auditing:** Checks `AndroidManifest.xml` for dangerous flags:
  - `android:debuggable="true"`
  - `android:allowBackup="true"`
  - `usesCleartextTraffic="true"`
  - Unprotected `exported="true"` activities, services, and receivers
- **Secret & Credential Extraction:** Extracts embedded printable strings to detect hardcoded API keys, private keys, and OAuth secrets.
- **Insecure Storage Modes:** Detects deprecated `MODE_WORLD_READABLE` and `MODE_WORLD_WRITEABLE` storage flags in smali and XML resources.
- **Built-in Zip Slip Protection:** Safeguards the scanning system against path traversal exploits embedded in malicious APK zip headers.

### 4. Desktop & Native Binary Scanner (`scan-binary`)
Lightweight static string and pattern analysis for compiled binaries.
- **Architecture Identification:** Detects `ELF` (Linux), `PE` (Windows), `Mach-O` (macOS), or raw binaries.
- **Dangerous C Functions:** Identifies buffer-overflow prone legacy functions (`gets`, `strcpy`, `sprintf`, `scanf`).
- **Embedded Credential Mining:** Extracts printable strings and scans for embedded PEM private keys, cloud tokens, and password strings.
- **Memory Guard:** Uses chunked streaming to safely process large binary files without memory exhaustion (OOM).

---

## 📥 Installation

### Automated Installer (Recommended)
Clone or extract the repository and run `install.sh`:
```bash
./install.sh
```
*`install.sh` automatically purges legacy `codesentinel` binaries and registers the `yemanode` CLI globally via `pipx` or `pip3`.*

### Manual Installation
```bash
pipx install . --force
# or
pip3 install --user .
```

---

## 💡 How to Use Yemanode

### Mode A: Interactive Menu (Recommended for Beginners)
Simply run `yemanode` with no arguments to launch the interactive prompt:
```bash
yemanode
```
**Interactive Prompt Example:**
```text
  __   _____ __  __    _    _   _  ___  ____  _____
  \ \ / / _ \  \/  |  / \  | \ | |/ _ \|  _ \| ____|
   \ V /  __/ |\/| | / _ \ |  \| | |_| | |_) |  _|  
    |_| \___|_|  |_/_/   \_\_| \_|\___/|____/|_____|

  Multi-target ethical security scanner v2.0.0
  Targets: source folder · API URL · APK · desktop binary

What would you like to scan?

  [1] Local source / project folder
  [2] Live API URL (AWS API Gateway, REST, etc.)
  [3] Android APK file
  [4] Desktop / native binary (ELF, PE, Mach-O, etc.)

Choice [1]: 
```

---

### Mode B: Direct Command Line Interface (CLI)

#### 1. Scanning a Source Code Folder (`scan-repo`)
Point Yemanode to any local project folder:
```bash
yemanode scan-repo /path/to/your/project
```
**Custom Report Output Path:**
```bash
yemanode scan-repo ./src -o ./reports/my_audit_report.md
```

#### 2. Scanning a Live API URL (`scan-api`)
Test a live REST API or AWS API Gateway endpoint:
```bash
yemanode scan-api https://lljy7gjuqf.execute-api.ap-south-1.amazonaws.com
```
**Custom Report Output Path:**
```bash
yemanode scan-api https://api.example.com/prod -o ./api_report.md
```

#### 3. Scanning an Android APK (`scan-apk`)
Analyze an `.apk` file:
```bash
yemanode scan-apk ./myapp.apk
```
**Custom Report Output Path:**
```bash
yemanode scan-apk ./build/outputs/app-release.apk -o ./apk_audit.md
```

#### 4. Scanning a Native Desktop Binary (`scan-binary`)
Analyze a Linux ELF, Windows EXE/DLL, or macOS binary:
```bash
yemanode scan-binary /usr/local/bin/custom_tool
```
**Custom Report Output Path:**
```bash
yemanode scan-binary ./bin/server -o ./binary_audit.md
```

---

## 📊 Markdown Report & Severity System

Every scan produces a detailed, structured Markdown security report.

### Severity Hierarchy
- 🔴 **CRITICAL:** High-impact flaws (Leaked Private Keys, Hardcoded AWS Secrets, Zip Slip, Disabling TLS Verification).
- 🟠 **HIGH:** Exploitable vulnerabilities (SQL Injection, Command Execution, Unauthenticated Sensitive APIs, Debuggable APKs).
- 🟡 **MEDIUM:** Misconfigurations (Missing HSTS Header, Stack Trace Leakage, Dangerous Functions, assertion security checks).
- 🔵 **LOW:** Hardening recommendations (Missing `X-Content-Type-Options`, Verbose `Server` headers, `allowBackup=true`).
- ⚪ **INFO:** Information disclosure and scan environment details.

---

## 🗑️ Uninstallation

To completely uninstall Yemanode and clean up binary links:

```bash
./uninstall.sh
```

Or manually via package managers:
```bash
pipx uninstall yemanode
# or
pip3 uninstall yemanode
```

---

## ⚖️ Scope & Ethical Use Directive

- **Passive & Static Analysis Only:** Yemanode performs static code analysis and non-destructive passive HTTP probes. It deliberately does **not** send exploit payloads, perform dynamic instrumentation, or attempt brute-force authentication bypasses.
- **Authorization Required:** Only scan systems, applications, and APIs that you own or have explicit, written permission to test. Unauthorized security testing against third-party systems is illegal.
