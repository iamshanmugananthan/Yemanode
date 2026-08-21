#!/usr/bin/env python3
"""
Yemanode v2 – multi-target ethical security scanner.
Supports: source folders, API URLs / OpenAPI specs, JWT tokens, APK files, desktop binaries, and Hacker Pentest Mode (Levels 1 to 10).
"""
import os
import sys
import datetime
import subprocess

import click

from .detectors import language
from .scanners import (
    secrets, patterns, dependencies, api_security,
    apk_scanner, binary_scanner, openapi, jwt_scanner, hacker_mode
)
from . import report
from . import __version__


def _banner():
    click.secho(r"""
__   _____ __  __    _    _   _  ___  ____  _____
\ \ / / _ \  \/  |  / \  | \ | |/ _ \|  _ \| ____|
 \ V /  __/ |\/| | / _ \ |  \| | |_| | |_) |  _|  
  |_| \___|_|  |_/_/   \_\_| \_|\___/|____/|_____|
""", fg="cyan")
    click.secho(f"  Multi-target ethical security scanner  v{__version__}\n", fg="cyan")
    click.secho("  Targets: source folder · API / OpenAPI · JWT · APK · binary · Hacker Mode (L1-10)\n", fg="bright_black")


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


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """Yemanode — analyze source, APK, API, JWT, binary, or run Hacker Pentest Mode (Levels 1-10)."""
    if ctx.invoked_subcommand is None:
        _banner()
        click.echo("What would you like to scan?\n")
        click.echo("  [1] Local source / project folder")
        click.echo("  [2] Live API URL or OpenAPI / Postman spec")
        click.echo("  [3] Android APK file")
        click.echo("  [4] Desktop / native binary (ELF, PE, Mach-O, etc.)")
        click.echo("  [5] JWT Token / payload analyzer")
        click.echo("  [6] 🥷 Hacker Pentest Mode (Progressive Attack Levels 1 to 10)")
        click.echo("")
        choice = click.prompt("Choice", type=click.Choice(["1", "2", "3", "4", "5", "6"]), default="1", show_choices=False)

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
            path = click.prompt("Enter path to the .apk file")
            ctx.invoke(scan_apk_cmd, apk_path=path)
        elif choice == "4":
            path = click.prompt("Enter path to the binary / executable")
            ctx.invoke(scan_binary_cmd, binary_path=path)
        elif choice == "5":
            token = click.prompt("Enter raw JWT token or path to file containing JWT")
            ctx.invoke(scan_jwt_cmd, token_or_file=token)
        else:
            target = click.prompt("Enter target (repo path, API URL, file, APK, or binary)")
            lvl = click.prompt("Enter Hacker Attack Level (1 to 10, max: 10)", type=int, default=5)
            ctx.invoke(hacker_test_cmd, target=target, level=lvl)


@cli.command("hacker-test")
@click.argument("target", required=False)
@click.option("-H", "--level", type=int, default=5, help="Hacker Pentest Level (1 to 10 max methods)")
@click.option("-o", "--output", default=None, help="Output Markdown report path")
def hacker_test_cmd(target, level, output):
    """🥷 Hacker Pentest Mode — runs progressive security attack methods (Levels 1 to 10) against target."""
    if not target:
        target = click.prompt("Enter target (repo path, API URL, spec file, APK, or binary)")

    if level < 1 or level > hacker_mode.MAX_HACKER_LEVEL:
        click.secho(f"Warning: Hacker Level must be between 1 and {hacker_mode.MAX_HACKER_LEVEL}. Capping level.", fg="yellow")
        level = max(1, min(level, hacker_mode.MAX_HACKER_LEVEL))

    click.secho(f"\n[🥷] Launching Hacker Pentest Mode — Level {level}/{hacker_mode.MAX_HACKER_LEVEL}", fg="magenta", bold=True)
    click.echo(f"[*] Target: {target}")

    results = hacker_mode.run_hacker_test(target, level=level)

    click.secho(f"[*] Completed {len(results['executed_methods'])} progressive pentest method(s).", fg="cyan")
    click.secho(f"[*] Scan complete — {len(results['findings'])} vulnerability finding(s).", fg="green")

    if not output:
        output = os.path.join(os.getcwd(), f"HACKER_PENTEST_REPORT_L{level}_{_timestamp()}.md")

    hacker_mode.write_hacker_report(output, results)
    click.secho(f"\n[+] Executive Hacker Pentest Report written to:\n    {output}", fg="cyan")


@cli.command("scan-repo")
@click.argument("repo_path", required=False)
@click.option("-o", "--output", default=None, help="Output Markdown report path")
@click.option("--diff", is_flag=True, default=False, help="Scope scan to git diff changes only")
@click.option("--diff-base", default="origin/main", help="Base branch for git diff scoping (default: origin/main)")
@click.option("-H", "--hacker-level", type=int, default=None, help="Trigger Hacker Pentest Mode (Level 1-10)")
def scan_repo_cmd(repo_path, output, diff, diff_base, hacker_level):
    """Deep static analysis of a local source repository / folder (with optional PR diff scoping or Hacker Mode)."""
    if hacker_level is not None:
        return click.get_current_context().invoke(hacker_test_cmd, target=repo_path, level=hacker_level, output=output)

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

    click.echo("[*] Checking for hardcoded secrets / credentials ...")
    secret_findings = secrets.scan_files(all_files)

    click.echo("[*] Checking for insecure code patterns (injection, XSS, SSRF, SSTI, crypto, config) ...")
    pattern_findings = patterns.scan_files(all_files)

    click.echo("[*] Checking for embedded JWT tokens and claims ...")
    jwt_findings = []
    for f in all_files:
        jwt_findings.extend(jwt_scanner.scan_file_for_jwts(f))

    click.echo("[*] Checking dependency manifests for known-vulnerable packages ...")
    dep_findings = dependencies.check_manifests(manifests)

    total = len(secret_findings) + len(pattern_findings) + len(jwt_findings) + len(dep_findings)
    click.secho(f"[*] Scan complete — {total} finding(s).", fg="green")

    if not output:
        output = os.path.join(repo_path, f"SECURITY_REPORT_{_timestamp()}.md")

    report.write_code_report(
        output, repo_path, langs, project_type,
        secret_findings, pattern_findings + jwt_findings, dep_findings,
    )
    click.secho(f"\n[+] Full Markdown report written to:\n    {output}", fg="cyan")


@cli.command("scan-api")
@click.argument("url", required=False)
@click.option("-s", "--spec", default=None, help="Path to OpenAPI/Swagger (.yaml/.json) or Postman collection file")
@click.option("-o", "--output", default=None, help="Output Markdown report path")
@click.option("-H", "--hacker-level", type=int, default=None, help="Trigger Hacker Pentest Mode (Level 1-10)")
def scan_api_cmd(url, spec, output, hacker_level):
    """Passive security checks against a live API URL or OpenAPI / Postman specification."""
    if hacker_level is not None:
        target = spec or url
        return click.get_current_context().invoke(hacker_test_cmd, target=target, level=hacker_level, output=output)

    spec_findings = []
    if spec:
        spec_path = os.path.abspath(os.path.expanduser(spec))
        click.secho(f"\n[*] Parsing API contract: {spec_path}", fg="yellow")
        parsed = openapi.parse_spec_file(spec_path)
        if parsed:
            click.echo(f"[*] API Spec Type : {parsed['spec_type']}")
            click.echo(f"[*] Endpoints     : {len(parsed['endpoints'])}")
            click.echo("[*] Conducting static security analysis of API contract ...")
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
        click.echo("    (TLS, security headers, auth presence, CORS, HTTP methods, common sensitive paths)")
        findings = api_security.run_all(url)
    else:
        findings = spec_findings

    click.secho(f"[*] Scan complete — {len(findings)} finding(s).", fg="green")

    if not output:
        output = os.path.join(os.getcwd(), f"API_SECURITY_REPORT_{_timestamp()}.md")

    report.write_api_report(output, url or (spec or "API Spec"), findings)
    click.secho(f"\n[+] Full Markdown report written to:\n    {output}", fg="cyan")


@cli.command("scan-jwt")
@click.argument("token_or_file", required=False)
@click.option("-o", "--output", default=None, help="Output Markdown report path")
def scan_jwt_cmd(token_or_file, output):
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
        output = os.path.join(os.getcwd(), f"JWT_SECURITY_REPORT_{_timestamp()}.md")

    report.write_generic_report(
        output,
        title="JWT Security Audit Report",
        target_desc=token_or_file[:60] + ("..." if len(token_or_file) > 60 else ""),
        findings=findings,
        extra_notes=[
            "JWT signatures were analyzed structurally without verifying secret keys.",
            "Always enforce asymmetric (RS256/ES256) or strong secret verification in API gateways.",
        ],
    )
    click.secho(f"\n[+] Full Markdown report written to:\n    {output}", fg="cyan")


@cli.command("scan-apk")
@click.argument("apk_path", required=False)
@click.option("-o", "--output", default=None, help="Output Markdown report path")
def scan_apk_cmd(apk_path, output):
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
    click.echo("    (string extraction, AndroidManifest flags, secrets, cleartext URLs, insecure modes)")

    findings = apk_scanner.scan_apk(apk_path)
    click.secho(f"[*] Scan complete — {len(findings)} finding(s).", fg="green")

    if not output:
        output = os.path.join(os.getcwd(), f"APK_SECURITY_REPORT_{_timestamp()}.md")

    notes = [
        "This is static analysis only (no dynamic instrumentation or runtime testing).",
        "For deeper Android analysis consider MobSF, jadx + manual review, or Frida on a test device you own.",
        "Binary XML (AndroidManifest) is only partially readable without apktool/aapt; some flags may be missed.",
    ]
    report.write_generic_report(
        output,
        title=f"APK Security Report — `{os.path.basename(apk_path)}`",
        target_desc=apk_path,
        findings=findings,
        extra_notes=notes,
    )
    click.secho(f"\n[+] Full Markdown report written to:\n    {output}", fg="cyan")


@cli.command("scan-binary")
@click.argument("binary_path", required=False)
@click.option("-o", "--output", default=None, help="Output Markdown report path")
def scan_binary_cmd(binary_path, output):
    """Static string / pattern analysis of a desktop or native binary."""
    if not binary_path:
        binary_path = click.prompt("Enter path to the binary / executable")
    binary_path = os.path.abspath(os.path.expanduser(binary_path))

    if not os.path.isfile(binary_path):
        click.secho(f"Error: '{binary_path}' is not a valid file.", fg="red")
        return

    click.secho(f"\n[*] Analyzing binary: {binary_path}", fg="yellow")
    click.echo("    (file type, embedded secrets, dangerous C functions, hardcoded credentials)")

    findings = binary_scanner.scan_binary(binary_path)
    click.secho(f"[*] Scan complete — {len(findings)} finding(s).", fg="green")

    if not output:
        output = os.path.join(os.getcwd(), f"BINARY_SECURITY_REPORT_{_timestamp()}.md")

    notes = [
        "This is a lightweight static string scan — not full reverse engineering or symbolic execution.",
        "For serious binary auditing use Ghidra, IDA, Binary Ninja, or dedicated tools (e.g. checksec, hardened runtime analysis).",
        "Packed or heavily obfuscated binaries will yield fewer useful strings.",
    ]
    report.write_generic_report(
        output,
        title=f"Binary Security Report — `{os.path.basename(binary_path)}`",
        target_desc=binary_path,
        findings=findings,
        extra_notes=notes,
    )
    click.secho(f"\n[+] Full Markdown report written to:\n    {output}", fg="cyan")


def main():
    cli()


if __name__ == "__main__":
    main()
