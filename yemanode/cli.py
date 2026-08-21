#!/usr/bin/env python3
"""
Yemanode v2 – multi-target ethical security scanner.
Supports: source folders, API URLs, APK files, and desktop binaries.
"""
import os
import sys
import datetime

import click

from .detectors import language
from .scanners import secrets, patterns, dependencies, api_security, apk_scanner, binary_scanner
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
    click.secho("  Targets: source folder · API URL · APK · desktop binary\n", fg="bright_black")


def _timestamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """Yemanode — analyze source, APK, API, or binary and produce a Markdown fix report."""
    if ctx.invoked_subcommand is None:
        _banner()
        click.echo("What would you like to scan?\n")
        click.echo("  [1] Local source / project folder")
        click.echo("  [2] Live API URL (AWS API Gateway, REST, etc.)")
        click.echo("  [3] Android APK file")
        click.echo("  [4] Desktop / native binary (ELF, PE, Mach-O, etc.)")
        click.echo("")
        choice = click.prompt("Choice", type=click.Choice(["1", "2", "3", "4"]), default="1", show_choices=False)

        if choice == "1":
            path = click.prompt("Enter path to the project / source folder")
            ctx.invoke(scan_repo_cmd, repo_path=path)
        elif choice == "2":
            url = click.prompt("Enter the API URL to test")
            ctx.invoke(scan_api_cmd, url=url)
        elif choice == "3":
            path = click.prompt("Enter path to the .apk file")
            ctx.invoke(scan_apk_cmd, apk_path=path)
        else:
            path = click.prompt("Enter path to the binary / executable")
            ctx.invoke(scan_binary_cmd, binary_path=path)


@cli.command("scan-repo")
@click.argument("repo_path", required=False)
@click.option("-o", "--output", default=None, help="Output Markdown report path")
def scan_repo_cmd(repo_path, output):
    """Deep static analysis of a local source repository / folder."""
    if not repo_path:
        repo_path = click.prompt("Enter the path to your repository folder")
    repo_path = os.path.abspath(os.path.expanduser(repo_path))

    if not os.path.isdir(repo_path):
        click.secho(f"Error: '{repo_path}' is not a valid directory.", fg="red")
        sys.exit(1)

    click.secho(f"\n[*] Scanning source tree: {repo_path}", fg="yellow")

    lang_counts, all_files, manifests = language.scan_repo(repo_path)
    langs = language.primary_languages(lang_counts)
    project_type = language.detect_project_type(repo_path, manifests)

    click.echo(f"[*] Project type   : {project_type}")
    click.echo(f"[*] Languages      : {', '.join(langs) if langs else 'none'}")
    click.echo(f"[*] Files scanned  : {len(all_files)}")
    click.echo(f"[*] Manifests found: {len(manifests)}")

    click.echo("[*] Checking for hardcoded secrets / credentials ...")
    secret_findings = secrets.scan_files(all_files)

    click.echo("[*] Checking for insecure code patterns (injection, XSS, crypto, config, etc.) ...")
    pattern_findings = patterns.scan_files(all_files)

    click.echo("[*] Checking dependency manifests for known-vulnerable packages ...")
    dep_findings = dependencies.check_manifests(manifests)

    total = len(secret_findings) + len(pattern_findings) + len(dep_findings)
    click.secho(f"[*] Scan complete — {total} finding(s).", fg="green")

    if not output:
        output = os.path.join(repo_path, f"SECURITY_REPORT_{_timestamp()}.md")

    report.write_code_report(
        output, repo_path, langs, project_type,
        secret_findings, pattern_findings, dep_findings,
    )
    click.secho(f"\n[+] Full Markdown report written to:\n    {output}", fg="cyan")


@cli.command("scan-api")
@click.argument("url", required=False)
@click.option("-o", "--output", default=None, help="Output Markdown report path")
def scan_api_cmd(url, output):
    """Passive, non-destructive security checks against a live API URL."""
    if not url:
        url = click.prompt("Enter the API URL to test")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    click.secho(f"\n[*] Running passive security checks against:\n    {url}", fg="yellow")
    click.echo("    (TLS, security headers, auth presence, CORS, HTTP methods, common sensitive paths)")

    findings = api_security.run_all(url)
    click.secho(f"[*] Scan complete — {len(findings)} finding(s).", fg="green")

    if not output:
        output = os.path.join(os.getcwd(), f"API_SECURITY_REPORT_{_timestamp()}.md")

    report.write_api_report(output, url, findings)
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
        sys.exit(1)
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
        sys.exit(1)

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
