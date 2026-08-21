#!/usr/bin/env python3
"""
Yemanode v2 – multi-target ethical security scanner.
Supports: source folders, API URLs / OpenAPI specs, JWT tokens, APK files, desktop binaries,
and Advanced Hacker Pentest Engine (Levels 1 to 10) with multi-format reports (MD, JSON, HTML, SARIF).
"""
import datetime
import os
import re
import subprocess

import click

from . import __version__, report
from .detectors import language
from .scanners import (
    api_security,
    apk_scanner,
    binary_scanner,
    dependencies,
    hacker_mode,
    jwt_scanner,
    load_test,
    openapi,
    patterns,
    secrets,
    url_analyzer,
)



def _banner():
    click.secho(r"""
__   _____ __  __    _    _   _  ___  ____  _____
\ \ / / _ \  \/  |  / \  | \ | |/ _ \|  _ \| ____|
 \ V /  __/ |\/| | / _ \ |  \| | |_| | |_) |  _|  
  |_| \___|_|  |_/_/   \_\_| \_|\___/|____/|_____|
""", fg="cyan")
    click.secho(f"  Multi-target ethical security scanner  v{__version__}\n", fg="cyan")
    click.secho("  Targets: source folder · API / OpenAPI · JWT · APK · binary · Hacker Mode (L1-10) · Load Testing\n", fg="bright_black")


def _timestamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


def _get_git_diff_files(repo_path, base_branch="origin/main"):
    """Returns set of file paths modified relative to base branch."""
    try:
        res = subprocess.run(
            ["git", "diff", "--name-only", base_branch],
            cwd=repo_path, capture_output=True, text=True, timeout=15
        )
        if res.returncode == 0:
            lines = res.stdout.splitlines()
            return {os.path.abspath(os.path.join(repo_path, f)) for f in lines if f.strip()}
    except Exception:
        pass
    return None


def _handle_report_output(base_output, title, target, findings, format_choice="md", extra_notes=None):
    base_no_ext = os.path.splitext(base_output)[0]
    formats_to_write = ["md", "json", "html", "sarif"] if format_choice == "all" else [format_choice]

    click.echo("")
    for fmt in formats_to_write:
        fmt = fmt.lower().strip()
        if fmt == "md" or fmt == "markdown":
            out_file = base_no_ext + ".md"
            report.write_generic_report(out_file, title, target, findings, extra_notes=extra_notes)
            click.secho(f"[+] Markdown Report : {out_file}", fg="cyan")
        elif fmt == "json":
            out_file = base_no_ext + ".json"
            report.write_json_report(out_file, title, target, findings)
            click.secho(f"[+] JSON Report     : {out_file}", fg="cyan")
        elif fmt == "html":
            out_file = base_no_ext + ".html"
            report.write_html_report(out_file, title, target, findings)
            click.secho(f"[+] HTML Report     : {out_file}", fg="cyan")
        elif fmt == "sarif":
            out_file = base_no_ext + ".sarif"
            report.write_sarif_report(out_file, title, target, findings)
            click.secho(f"[+] SARIF 2.1 Report: {out_file}", fg="cyan")


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """Yemanode — analyze source, website URLs, APK, API, JWT, binary, load testing, or Hacker Pentest Mode (Levels 1-10)."""
    if ctx.invoked_subcommand is None:
        _banner()
        click.echo("What would you like to scan?\n")
        click.echo("  [1] Local source / project folder")
        click.echo("  [2] Live API URL or OpenAPI / Postman spec")
        click.echo("  [3] 🌐 Website URL Loophole & Security Auditor (analyse-url)")
        click.echo("  [4] Android APK file")
        click.echo("  [5] Desktop / native binary (ELF, PE, Mach-O, etc.)")
        click.echo("  [6] JWT Token / payload analyzer")
        click.echo("  [7] 🥷 Hacker Pentest Mode (Progressive Attack Levels 1 to 10)")
        click.echo("  [8] ⚡ API Load Test & Rate-Limit Audit")
        click.echo("")
        choice = click.prompt("Choice", type=click.Choice(["1", "2", "3", "4", "5", "6", "7", "8"]), default="1", show_choices=False)

        if choice == "1":
            path = click.prompt("Enter path to the project / source folder")
            ctx.invoke(scan_repo_cmd, repo_path=path)
        elif choice == "2":
            target = click.prompt("Enter the API URL or path to OpenAPI / Postman spec file")
            if os.path.isfile(target):
                ctx.invoke(scan_api_cmd, spec=target)
            else:
                ctx.invoke(scan_api_cmd, url=target)
        elif choice == "3":
            url = click.prompt("Enter website URL to analyse (e.g. https://example.com)")
            ctx.invoke(analyse_url_cmd, url=url)
        elif choice == "4":
            path = click.prompt("Enter path to the .apk file")
            ctx.invoke(scan_apk_cmd, apk_path=path)
        elif choice == "5":
            path = click.prompt("Enter path to the binary / executable")
            ctx.invoke(scan_binary_cmd, binary_path=path)
        elif choice == "6":
            token = click.prompt("Enter raw JWT token or path to file containing JWT")
            ctx.invoke(scan_jwt_cmd, token_or_file=token)
        elif choice == "7":
            target = click.prompt("Enter target (repo path, API URL, file, APK, or binary)")
            lvl = click.prompt("Enter Hacker Attack Level (1 to 10, max: 10)", type=int, default=5)
            ctx.invoke(hacker_test_cmd, target=target, level=lvl)
        else:
            url = click.prompt("Enter API target URL")
            n = click.prompt("Total requests to send", type=int, default=100)
            c = click.prompt("Concurrent worker threads", type=int, default=10)
            ctx.invoke(load_test_cmd, url=url, total_requests=n, concurrency=c)



@cli.command("hacker-test")
@click.argument("target", required=False)
@click.option("-H", "--level", type=int, default=5, help="Hacker Pentest Level (1 to 10 max methods)")
@click.option("-m", "--mode", type=click.Choice(["safe", "aggressive"]), default="safe", help="Pentest mode (safe/aggressive)")
@click.option("-f", "--format", "report_format", type=click.Choice(["md", "json", "html", "sarif", "all"]), default="md", help="Report export format")
@click.option("-o", "--output", default=None, help="Output report path base")
def hacker_test_cmd(target, level, mode, report_format, output):
    """🥷 Hacker Pentest Mode — runs progressive security attack methods (Levels 1 to 10) against target."""
    if not target:
        target = click.prompt("Enter target (repo path, API URL, spec file, APK, or binary)")

    if level < 1 or level > hacker_mode.MAX_HACKER_LEVEL:
        click.secho(f"Warning: Hacker Level must be between 1 and {hacker_mode.MAX_HACKER_LEVEL}. Capping level.", fg="yellow")
        level = max(1, min(level, hacker_mode.MAX_HACKER_LEVEL))

    click.secho(f"\n[🥷] Launching Hacker Pentest Mode — Level {level}/{hacker_mode.MAX_HACKER_LEVEL} (Mode: {mode.upper()})", fg="magenta", bold=True)
    click.echo(f"[*] Target: {target}")

    results = hacker_mode.run_hacker_test(target, level=level, mode=mode)

    click.secho(f"[*] Completed {len(results['executed_methods'])} progressive pentest method(s).", fg="cyan")
    click.secho(f"[*] Scan complete — {len(results['findings'])} vulnerability finding(s).", fg="green")
    if results.get("vulnerability_chains"):
        click.secho(f"[!] Discovered {len(results['vulnerability_chains'])} exploitable vulnerability chain(s)!", fg="red", bold=True)

    if not output:
        output = os.path.join(os.getcwd(), f"HACKER_PENTEST_REPORT_L{level}_{_timestamp()}")

    # Generate Markdown Hacker Report
    md_output = output if output.endswith(".md") else output + ".md"
    hacker_mode.write_hacker_report(md_output, results)

    # Multi-format reporting if requested
    if report_format != "md":
        _handle_report_output(output, f"Hacker Pentest Report L{level}", target, results["findings"], format_choice=report_format)
    else:
        click.secho(f"\n[+] Executive Hacker Pentest Report written to:\n    {md_output}", fg="cyan")


@cli.command("scan-repo")
@click.argument("repo_path", required=False)
@click.option("-o", "--output", default=None, help="Output report path")
@click.option("-f", "--format", "report_format", type=click.Choice(["md", "json", "html", "sarif", "all"]), default="md", help="Report export format")
@click.option("--diff", is_flag=True, default=False, help="Scope scan to git diff changes only")
@click.option("--diff-base", default="origin/main", help="Base branch for git diff scoping (default: origin/main)")
@click.option("--git-history/--no-git-history", default=True, help="Scan Git commit history for leaked secrets")
@click.option("-H", "--hacker-level", type=int, default=None, help="Trigger Hacker Pentest Mode (Level 1-10)")
def scan_repo_cmd(repo_path, output, report_format, diff, diff_base, git_history, hacker_level):
    """Deep static analysis of a local source repository / folder (with optional PR diff scoping or Hacker Mode)."""
    if hacker_level is not None:
        return click.get_current_context().invoke(hacker_test_cmd, target=repo_path, level=hacker_level, output=output, report_format=report_format)

    if not repo_path:
        repo_path = click.prompt("Enter the path to your repository folder")
    repo_path = os.path.abspath(os.path.expanduser(repo_path))

    if not os.path.isdir(repo_path):
        click.secho(f"Error: '{repo_path}' is not a valid directory.", fg="red")
        return

    click.secho(f"\n[*] Scanning source tree: {repo_path}", fg="yellow")

    lang_counts, all_files, manifests = language.scan_repo(repo_path)
    langs = language.primary_languages(lang_counts)
    project_type = language.detect_project_type(repo_path, manifests)

    if diff:
        click.echo(f"[*] Scope mode: PR Git Diff against `{diff_base}` ...")
        diff_files = _get_git_diff_files(repo_path, diff_base)
        if diff_files is not None:
            all_files = [f for f in all_files if f in diff_files]
            click.echo(f"[*] Filtered target files to {len(all_files)} modified file(s).")
        else:
            click.secho("[-] Could not retrieve git diff files — scanning full repository.", fg="yellow")

    click.echo(f"[*] Project type   : {project_type}")
    click.echo(f"[*] Languages      : {', '.join(langs) if langs else 'none'}")
    click.echo(f"[*] Files scanned  : {len(all_files)}")
    click.echo(f"[*] Manifests found: {len(manifests)}")

    click.echo("[*] Checking for hardcoded secrets / credentials / sensitive files ...")
    secret_findings = secrets.scan_files(all_files)
    if git_history and not diff:
        click.echo("[*] Mining Git commit logs for historical secrets ...")
        secret_findings.extend(secrets.scan_git_history(repo_path, max_commits=50))

    click.echo("[*] Checking for insecure code patterns (SQLi, NoSQLi, RCE, SSRF, XSS, Path Traversal, IaC) ...")
    pattern_findings = patterns.scan_files(all_files)

    click.echo("[*] Checking for embedded JWT tokens and claims ...")
    jwt_findings = []
    for f in all_files:
        jwt_findings.extend(jwt_scanner.scan_file_for_jwts(f))

    click.echo("[*] Checking dependency manifests for known-vulnerable packages ...")
    dep_findings = dependencies.check_manifests(manifests)

    all_findings = secret_findings + pattern_findings + jwt_findings + dep_findings
    click.secho(f"[*] Scan complete — {len(all_findings)} finding(s).", fg="green")

    if not output:
        output = os.path.join(repo_path, f"SECURITY_REPORT_{_timestamp()}")

    if report_format == "md":
        md_file = output if output.endswith(".md") else output + ".md"
        report.write_code_report(
            md_file, repo_path, langs, project_type,
            secret_findings, pattern_findings + jwt_findings, dep_findings,
        )
        click.secho(f"\n[+] Full Markdown report written to:\n    {md_file}", fg="cyan")
    else:
        _handle_report_output(
            output, f"Security Audit — {os.path.basename(repo_path)}",
            repo_path, all_findings, format_choice=report_format
        )


@cli.command("scan-api")
@click.argument("url", required=False)
@click.option("-s", "--spec", default=None, help="Path to OpenAPI/Swagger (.yaml/.json) or Postman collection file")
@click.option("-f", "--format", "report_format", type=click.Choice(["md", "json", "html", "sarif", "all"]), default="md", help="Report export format")
@click.option("-o", "--output", default=None, help="Output report path")
@click.option("-H", "--hacker-level", type=int, default=None, help="Trigger Hacker Pentest Mode (Level 1-10)")
def scan_api_cmd(url, spec, report_format, output, hacker_level):
    """Passive security checks against a live API URL or OpenAPI / Postman specification."""
    if hacker_level is not None:
        target = spec or url
        return click.get_current_context().invoke(hacker_test_cmd, target=target, level=hacker_level, output=output, report_format=report_format)

    spec_findings = []
    if spec:
        spec_path = os.path.abspath(os.path.expanduser(spec))
        click.secho(f"\n[*] Parsing API contract: {spec_path}", fg="yellow")
        parsed = openapi.parse_spec_file(spec_path)
        if parsed:
            click.echo(f"[*] API Spec Type : {parsed['spec_type']}")
            click.echo(f"[*] Endpoints     : {len(parsed['endpoints'])}")
            click.echo("[*] Conducting static security analysis of API contract (Auth, BOLA, sensitive query params) ...")
            spec_findings.extend(openapi.audit_spec_statically(parsed))

            if not url and parsed.get("base_url"):
                url = parsed["base_url"]

            if url:
                click.echo(f"[*] Probing declared spec endpoints against target: {url} ...")
                spec_findings.extend(openapi.probe_spec_endpoints(parsed, target_url=url))
        else:
            click.secho(f"Error: Unable to parse API specification file '{spec_path}'.", fg="red")

    if url and not spec_findings:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        click.secho(f"\n[*] Running passive security checks against:\n    {url}", fg="yellow")
        click.echo("    (TLS, security headers, auth presence, CORS, rate limits, HTTP methods, shadow routes)")
        findings = api_security.run_all(url)
    else:
        findings = spec_findings

    click.secho(f"[*] Scan complete — {len(findings)} finding(s).", fg="green")

    if not output:
        output = os.path.join(os.getcwd(), f"API_SECURITY_REPORT_{_timestamp()}")

    _handle_report_output(
        output, f"API Security Report — {url or spec or 'API'}",
        url or (spec or "API Spec"), findings, format_choice=report_format
    )


@cli.command("scan-jwt")
@click.argument("token_or_file", required=False)
@click.option("-f", "--format", "report_format", type=click.Choice(["md", "json", "html", "sarif", "all"]), default="md", help="Report export format")
@click.option("-o", "--output", default=None, help="Output report path")
def scan_jwt_cmd(token_or_file, report_format, output):
    """Decode and analyze JWT tokens for security risks (unsigned tokens, weak alg, expired, sensitive claims)."""
    if not token_or_file:
        token_or_file = click.prompt("Enter raw JWT token or file path containing JWT")

    findings = []
    if os.path.isfile(token_or_file):
        click.secho(f"\n[*] Scanning file for embedded JWTs: {token_or_file}", fg="yellow")
        findings = jwt_scanner.scan_file_for_jwts(os.path.abspath(token_or_file))
    else:
        click.secho("\n[*] Auditing JWT Token payload and header ...", fg="yellow")
        findings = jwt_scanner.analyze_jwt_token(token_or_file)

    click.secho(f"[*] Scan complete — {len(findings)} finding(s).", fg="green")

    if not output:
        output = os.path.join(os.getcwd(), f"JWT_SECURITY_REPORT_{_timestamp()}")

    _handle_report_output(
        output, "JWT Security Audit Report",
        token_or_file[:60] + ("..." if len(token_or_file) > 60 else ""),
        findings, format_choice=report_format,
        extra_notes=[
            "JWT signatures were analyzed structurally without verifying secret keys.",
            "Always enforce asymmetric (RS256/ES256) or strong secret verification in API gateways.",
        ],
    )


@cli.command("scan-apk")
@click.argument("apk_path", required=False)
@click.option("-f", "--format", "report_format", type=click.Choice(["md", "json", "html", "sarif", "all"]), default="md", help="Report export format")
@click.option("-o", "--output", default=None, help="Output report path")
def scan_apk_cmd(apk_path, report_format, output):
    """Static analysis of an Android APK (manifest, secrets, cleartext, exported components, etc.)."""
    if not apk_path:
        apk_path = click.prompt("Enter path to the .apk file")
    apk_path = os.path.abspath(os.path.expanduser(apk_path))

    if not os.path.isfile(apk_path):
        click.secho(f"Error: '{apk_path}' is not a valid file.", fg="red")
        return
    if not apk_path.lower().endswith((".apk", ".aab")):
        click.secho("Warning: file does not end with .apk / .aab — continuing anyway.", fg="yellow")

    click.secho(f"\n[*] Analyzing APK: {apk_path}", fg="yellow")
    click.echo("    (AndroidManifest flags, dangerous permissions, Firebase DBs, WebViews, secrets, native .so libs)")

    findings = apk_scanner.scan_apk(apk_path)
    click.secho(f"[*] Scan complete — {len(findings)} finding(s).", fg="green")

    if not output:
        output = os.path.join(os.getcwd(), f"APK_SECURITY_REPORT_{_timestamp()}")

    _handle_report_output(
        output, f"APK Security Report — {os.path.basename(apk_path)}",
        apk_path, findings, format_choice=report_format,
        extra_notes=[
            "This is static analysis only (no dynamic instrumentation or runtime testing).",
            "For deeper Android analysis consider MobSF, jadx + manual review, or Frida on a test device you own.",
        ],
    )


@cli.command("scan-binary")
@click.argument("binary_path", required=False)
@click.option("-f", "--format", "report_format", type=click.Choice(["md", "json", "html", "sarif", "all"]), default="md", help="Report export format")
@click.option("-o", "--output", default=None, help="Output report path")
def scan_binary_cmd(binary_path, report_format, output):
    """Static analysis of desktop/native binaries (PIE, NX, RELRO, stack canaries, dangerous C functions)."""
    if not binary_path:
        binary_path = click.prompt("Enter path to the binary / executable")
    binary_path = os.path.abspath(os.path.expanduser(binary_path))

    if not os.path.isfile(binary_path):
        click.secho(f"Error: '{binary_path}' is not a valid file.", fg="red")
        return

    click.secho(f"\n[*] Analyzing binary: {binary_path}", fg="yellow")
    click.echo("    (file type, security mitigations ASLR/NX/RELRO/Canary, dangerous C functions, embedded secrets)")

    findings = binary_scanner.scan_binary(binary_path)
    click.secho(f"[*] Scan complete — {len(findings)} finding(s).", fg="green")

    if not output:
        output = os.path.join(os.getcwd(), f"BINARY_SECURITY_REPORT_{_timestamp()}")

    _handle_report_output(
        output, f"Binary Security Report — {os.path.basename(binary_path)}",
        binary_path, findings, format_choice=report_format,
        extra_notes=[
            "This is a lightweight static binary scan auditing ELF mitigations, strings, and symbols.",
            "For deep reverse engineering, pair with Ghidra, IDA Pro, or Binary Ninja.",
        ],
    )


@cli.command("load-test")
@click.argument("url", required=False)
@click.option("-n", "--requests", "total_requests", type=int, default=100, help="Total number of requests (default: 100)")
@click.option("-c", "--concurrency", type=int, default=10, help="Concurrent worker threads (default: 10)")
@click.option("-m", "--method", default="GET", help="HTTP method (GET, POST, PUT, DELETE, etc.)")
@click.option("-H", "--header", "custom_headers", multiple=True, help="Custom HTTP headers in 'Key: Value' format")
@click.option("-d", "--data", default=None, help="HTTP request body data")
@click.option("-f", "--format", "report_format", type=click.Choice(["md", "json", "html", "sarif", "all"]), default="md", help="Report export format")
@click.option("-o", "--output", default=None, help="Output report path")
def load_test_cmd(url, total_requests, concurrency, method, custom_headers, data, report_format, output):
    """⚡ Controlled concurrent load testing & API rate-limit resilience audit."""
    if not url:
        url = click.prompt("Enter API target URL")

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    headers_dict = {}
    if custom_headers:
        for h in custom_headers:
            if ":" in h:
                k, v = h.split(":", 1)
                headers_dict[k.strip()] = v.strip()

    click.secho(f"\n[⚡] Starting Load & Rate-Limit Audit against: {url}", fg="yellow", bold=True)
    click.echo(f"[*] Method: {method.upper()} | Total Requests: {total_requests} | Concurrency: {concurrency} workers")
    click.echo("[*] Sending concurrent requests ...")

    results = load_test.run_load_test(
        url=url,
        method=method,
        total_requests=total_requests,
        concurrency=concurrency,
        headers=headers_dict,
        data=data,
    )

    lat = results["latencies"]
    rps = results["rps"]
    duration = results["duration_sec"]
    status_counts = results["status_counts"]
    findings = results["findings"]

    click.secho(f"\n[+] Test Completed in {duration:.2f}s — Throughput: {rps:.1f} req/sec", fg="green", bold=True)
    click.echo(f"[*] Latency: Avg={lat['avg_ms']:.1f}ms | P50={lat['median_ms']:.1f}ms | P95={lat['p95_ms']:.1f}ms | Max={lat['max_ms']:.1f}ms")
    click.echo(f"[*] Response Statuses: {status_counts}")
    if findings:
        for f in findings:
            sev = f.get("severity", "info")
            click.echo(f"    {report.SEVERITY_ICON.get(sev, '⚪')} [{sev.upper()}] {f['type']}")

    if not output:
        output = os.path.join(os.getcwd(), f"LOAD_TEST_REPORT_{_timestamp()}")

    md_file = output if output.endswith(".md") else output + ".md"
    load_test.write_load_test_report(md_file, results)

    if report_format == "md":
        click.secho(f"\n[+] Full Markdown Report written to:\n    {md_file}", fg="cyan")
    else:
        _handle_report_output(
            output, f"API Load & Rate-Limit Report — {url}",
            url, findings, format_choice=report_format
        )


@cli.command("analyse-url")
@click.argument("url", required=False)
@click.option("-o", "--output", default=None, help="Output report path base")
@click.option("-f", "--format", "report_format", type=click.Choice(["md", "json", "html", "sarif", "all"]), default="md", help="Report export format (default: md)")
@click.option("--deep/--no-deep", default=True, help="Conduct deep path enumeration and DOM security audit (default: True)")
@click.option("--timeout", type=int, default=8, help="HTTP request timeout in seconds (default: 8)")
def analyse_url_cmd(url, output, report_format, deep, timeout):
    """🌐 Website URL Loophole & Security Auditor — finds all vulnerabilities, misconfigurations, and generates an actionable fix report in Markdown."""
    if not url:
        url = click.prompt("Enter website URL to analyse (e.g. https://example.com)")

    target_url = url_analyzer.normalize_target_url(url)
    click.secho(f"\n[🌐] Launching Professional Website Loophole Audit against:\n     {target_url}", fg="cyan", bold=True)
    click.echo(f"[*] Assessment Scope: TLS · Security Headers · Cookies · CORS · HTTP Verbs · Recon Paths · DOM/Secrets · Redirects · Error Leaks")
    click.echo(f"[*] Deep Audit Mode : {'ENABLED' if deep else 'DISABLED'} | Timeout: {timeout}s")
    click.echo("[*] Analyzing website security posture ...")

    results = url_analyzer.analyse_url(target_url, deep=deep, timeout=timeout)

    score = results["security_score"]
    grade = results["security_grade"]
    desc = results["grade_description"]
    counts = results["severity_counts"]
    findings = results["findings"]
    chains = results.get("vulnerability_chains", [])

    # Color grading
    grade_color = "green" if grade in ("A+", "A") else ("yellow" if grade == "B" else "red")
    click.secho(f"\n[+] Audit Complete — Overall Security Grade: {grade} ({score}/100)", fg=grade_color, bold=True)
    click.secho(f"[*] Rating Status: {desc}", fg="bright_black")
    click.echo(f"[*] Findings Breakdown: {counts['critical']} Critical · {counts['high']} High · {counts['medium']} Medium · {counts['low']} Low · {counts['info']} Info")
    
    if chains:
        click.secho(f"[!] Discovered {len(chains)} high-impact chained attack path(s)!", fg="red", bold=True)

    if not output:
        clean_name = re.sub(r'[^a-zA-Z0-9]', '_', results['hostname'])
        output = os.path.join(os.getcwd(), f"WEBSITE_SECURITY_REPORT_{clean_name}_{_timestamp()}")

    md_output = output if output.endswith(".md") else output + ".md"
    url_analyzer.write_website_markdown_report(md_output, results)

    if report_format == "md":
        click.secho(f"\n[+] Professional Website Security & Loophole Report written to:\n    {md_output}", fg="cyan", bold=True)
    else:
        _handle_report_output(
            output, f"Website Security Audit — {target_url}",
            target_url, findings, format_choice=report_format
        )


@cli.command("analyze-url", hidden=True)
@click.argument("url", required=False)
@click.option("-o", "--output", default=None, help="Output report path base")
@click.option("-f", "--format", "report_format", type=click.Choice(["md", "json", "html", "sarif", "all"]), default="md", help="Report export format")
@click.option("--deep/--no-deep", default=True, help="Conduct deep path enumeration and DOM audit")
@click.option("--timeout", type=int, default=8, help="HTTP request timeout in seconds")
def analyze_url_cmd(url, output, report_format, deep, timeout):
    """Alias for analyse-url."""
    return click.get_current_context().invoke(analyse_url_cmd, url=url, output=output, report_format=report_format, deep=deep, timeout=timeout)


def main():
    cli()


if __name__ == "__main__":
    main()

