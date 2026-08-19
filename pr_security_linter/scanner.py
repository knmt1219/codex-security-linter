"""Core scanner orchestration, diff analysis, offline filesystem scanning, and CLI entry point."""

import argparse
import json
import os
import pathlib
import sys
import time
from typing import Any, Dict, List, Optional, Tuple
import requests

from . import __version__
from .diff import chunk_diff_smart, count_scanned_lines
from .engine import SecurityEngine
from .models import Finding, Severity
from .patterns import (
    COMMON_SECRET_PATTERNS,
    LANGUAGE_VULN_PATTERNS,
    MALWARE_PATTERNS,
    SEVERITY_RANKS,
)
from .reporters import (
    build_markdown_summary_table,
    export_html,
    export_json,
    export_sarif,
    generate_svg_badge,
)


def heuristic_scan_structured(diff_text: str, custom_ignore_paths: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Analyze git diff line-by-line using rule engine and return serialized findings."""
    engine = SecurityEngine(custom_ignore_paths=custom_ignore_paths)
    findings = engine.scan_diff(diff_text)
    return [f.to_dict() for f in findings]


def scan_local_path_offline(target_path: str, custom_ignore_paths: Optional[List[str]] = None) -> Tuple[List[Dict[str, Any]], int]:
    """Scan a local file or recursively walk a directory offline."""
    engine = SecurityEngine(custom_ignore_paths=custom_ignore_paths)
    findings, lines_scanned = engine.scan_path(target_path)
    return [f.to_dict() for f in findings], lines_scanned


def parse_simple_yaml(text: str) -> Dict[str, Any]:
    """Lightweight fallback YAML parser for configuration without external dependencies."""
    config: Dict[str, Any] = {}
    current_section: Optional[str] = None

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if not raw_line.startswith(" ") and line.endswith(":"):
            current_section = line[:-1].strip()
            config[current_section] = {}
            continue

        if current_section and raw_line.startswith("  ") and ":" in line:
            parts = line.split(":", 1)
            k = parts[0].strip()
            v = parts[1].strip().strip('"').strip("'")
            if isinstance(config[current_section], dict):
                config[current_section][k] = v
            continue

        if current_section and line.startswith("- "):
            item = line[2:].strip().strip('"').strip("'")
            if not isinstance(config[current_section], list):
                config[current_section] = []
            config[current_section].append(item)
            continue

        if ":" in line:
            parts = line.split(":", 1)
            k = parts[0].strip()
            v = parts[1].strip().strip('"').strip("'")
            config[k] = v
            current_section = None

    return config


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load configuration from specified path or standard configuration files."""
    candidate_paths = [config_path] if config_path else [".pr-security.yml", ".pr-security-linter.yml", ".codex-security.yml"]

    for path in candidate_paths:
        if path and os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()

                try:
                    import yaml  # type: ignore
                    data = yaml.safe_load(content)
                    if isinstance(data, dict):
                        return data
                except ImportError:
                    pass

                return parse_simple_yaml(content)
            except Exception as e:
                print(f"Warning: Failed to load config from '{path}': {e}", file=sys.stderr)
                return {}

    return {}


def install_pre_commit_hook() -> None:
    """Scaffold a .pre-commit-config.yaml configured for PR Security Linter."""
    config_path = ".pre-commit-config.yaml"
    hook_config = f"""repos:
  - repo: https://github.com/knmt1219/pr-security-linter
    rev: v{__version__}
    hooks:
      - id: pr-security-linter
"""
    if os.path.exists(config_path):
        print(f"File '{config_path}' already exists. Please verify hook configuration.")
    else:
        with open(config_path, "w", encoding="utf-8") as f:
            f.write(hook_config)
        print(f"✅ Generated '{config_path}' configured for PR Security Linter v{__version__}.")
    print("Next step: Run `pre-commit install` to activate the hook locally.")


def set_github_output(name: str, value: Any) -> None:
    """Write an output parameter to $GITHUB_OUTPUT file in GitHub Actions."""
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        try:
            with open(output_file, "a", encoding="utf-8") as f:
                f.write(f"{name}={value}\n")
        except Exception as e:
            print(f"Warning: Failed to write output to GITHUB_OUTPUT: {e}", file=sys.stderr)


def write_github_action_outputs(findings: list, sarif_path: str = "", html_path: str = "") -> None:
    """Record GitHub Action step outputs for downstream workflow steps."""
    total_count = len(findings)
    has_critical = any(f.get("severity") == "CRITICAL" for f in findings)
    set_github_output("findings-count", str(total_count))
    set_github_output("has-critical", "true" if has_critical else "false")
    set_github_output("sarif-path", sarif_path or "")
    set_github_output("html-report-path", html_path or "")


def should_fail_on_severity(findings: list, fail_on_threshold: str) -> bool:
    """Return True if any finding meets or exceeds the specified fail_on severity threshold."""
    if not fail_on_threshold or not findings:
        return False

    threshold_rank = SEVERITY_RANKS.get(fail_on_threshold.upper(), 3)
    for f in findings:
        sev = f.get("severity", "LOW").upper()
        if SEVERITY_RANKS.get(sev, 1) >= threshold_rank:
            return True
    return False


def get_pr_diff(repo_full_name: str, pr_number: int, github_token: str) -> str:
    """Fetch pull request diff from GitHub API."""
    url = f"https://api.github.com/repos/{repo_full_name}/pulls/{pr_number}"
    headers = {"Authorization": f"Bearer {github_token}", "Accept": "application/vnd.github.v3.diff"}
    res = requests.get(url, headers=headers, timeout=30)
    return res.text if res.status_code == 200 else ""


def post_comment(repo_full_name: str, pr_number: int, github_token: str, body: str) -> bool:
    """Post comment to PR on GitHub."""
    url = f"https://api.github.com/repos/{repo_full_name}/issues/{pr_number}/comments"
    headers = {"Authorization": f"Bearer {github_token}", "Accept": "application/vnd.github.v3+json"}
    res = requests.post(url, headers=headers, json={"body": body}, timeout=30)
    return res.status_code == 201


def audit_diff_with_ai(diff_text: str, api_key: str, model_name: str = "gpt-4o-mini") -> str:
    """Optional LLM-based triage to review code diff and suggest remediation patches."""
    from .analyzers.ai import AIReviewProvider
    provider = AIReviewProvider(api_key=api_key, model=model_name)
    return provider.review_diff(diff_text)


def main() -> None:
    """CLI and GitHub Action entry point."""
    if sys.stdout and hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if sys.stderr and hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    if len(sys.argv) > 1 and sys.argv[1] == "benchmark":
        from .benchmark import main as run_benchmark_cli
        run_benchmark_cli()
        return

    start_time = time.time()
    parser = argparse.ArgumentParser(description=f"PR Security Linter CLI & GitHub Action (v{__version__})")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--local", action="store_true", help="Run security audit on local git diff")
    parser.add_argument("--staged", action="store_true", help="Run security audit on staged git changes (git diff --cached)")
    parser.add_argument("--path", type=str, help="Scan a local file or recursive directory offline without git dependency")
    parser.add_argument("--benchmark", action="store_true", help="Run evaluation benchmark against verified fixture corpus")
    parser.add_argument("--sarif", type=str, help="Export scan results to OASIS SARIF format")
    parser.add_argument("--json", type=str, help="Export scan results to JSON format")
    parser.add_argument("--html", type=str, help="Export interactive HTML security dashboard report")
    parser.add_argument("--badge", action="store_true", help="Generate SVG status badge (security-badge.svg)")
    parser.add_argument("--strict", action="store_true", help="Fail with exit code 1 if critical or high risks are found")
    parser.add_argument("--quiet", action="store_true", help="Quiet mode: suppress info logs and only output when issues are found")
    parser.add_argument("--config", type=str, help="Path to custom YAML configuration file (default: .pr-security.yml)")
    parser.add_argument("--install-hook", action="store_true", help="Scaffold a .pre-commit-config.yaml for PR Security Linter")
    parser.add_argument(
        "--fail-on",
        type=str,
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "critical", "high", "medium", "low"],
        help="Exit with code 1 if findings meet or exceed the specified severity threshold",
    )
    args = parser.parse_args()

    if args.benchmark:
        from .benchmark import main as run_benchmark_cli
        run_benchmark_cli()
        return

    if args.install_hook:
        install_pre_commit_hook()
        return

    # Load configuration
    config = load_config(args.config)
    settings = config.get("settings", {}) if isinstance(config.get("settings"), dict) else {}
    ignore_paths = config.get("ignore_paths", []) if isinstance(config.get("ignore_paths"), list) else []

    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    model_name = os.environ.get("MODEL_NAME") or settings.get("model") or "gpt-4o-mini"

    fail_threshold = None
    if args.fail_on:
        fail_threshold = args.fail_on.upper()
    elif args.strict:
        fail_threshold = "HIGH"
    elif settings.get("severity_threshold"):
        fail_threshold = str(settings.get("severity_threshold")).upper()

    # 1. Offline path scanning mode
    if args.path:
        if not args.quiet:
            print(f"🔍 Running Offline Security Audit on '{args.path}' (v{__version__})...")
        findings, lines_scanned = scan_local_path_offline(args.path, ignore_paths)
        duration_ms = (time.time() - start_time) * 1000

        if args.badge:
            generate_svg_badge(bool(findings))
            if not args.quiet:
                print("SVG security badge generated at: security-badge.svg")

        if findings:
            print("\n📊 Security Summary Matrix:")
            print(build_markdown_summary_table(findings, lines_scanned, duration_ms))
            if args.sarif:
                export_sarif(findings, args.sarif)
                if not args.quiet:
                    print(f"SARIF report exported to: {args.sarif}")
            if args.json:
                export_json(findings, args.json)
                if not args.quiet:
                    print(f"JSON report exported to: {args.json}")
            if args.html:
                export_html(findings, args.html, lines_scanned, duration_ms)
                if not args.quiet:
                    print(f"Interactive HTML report exported to: {args.html}")

            if fail_threshold and should_fail_on_severity(findings, fail_threshold):
                print(f"\n❌ Threshold violation: Vulnerabilities matching or exceeding '{fail_threshold}' detected. Exiting with error.")
                sys.exit(1)
        else:
            if not args.quiet:
                print(f"✅ Offline Scan: Clean (Scanned {lines_scanned} lines in {duration_ms:.2f}ms)")
            if args.html:
                export_html(findings, args.html, lines_scanned, duration_ms)
        return

    # 2. Local git diff / staged mode
    if args.local or args.staged:
        if args.staged:
            diff_text = os.popen("git diff --cached").read()
        else:
            diff_text = os.popen("git diff HEAD~1").read()
            if not diff_text.strip():
                diff_text = os.popen("git diff").read()

        if not diff_text.strip():
            if not args.quiet:
                print("No local git changes detected to audit.")
            return

        lines_scanned = count_scanned_lines(diff_text)
        if not args.quiet:
            print(f"🔍 Running Security Audit on Git Diff (v{__version__})...")
        findings = heuristic_scan_structured(diff_text, ignore_paths)
        duration_ms = (time.time() - start_time) * 1000

        if args.badge:
            generate_svg_badge(bool(findings))
            if not args.quiet:
                print("SVG security badge generated at: security-badge.svg")

        if findings:
            print("\n📊 Security Summary Matrix:")
            print(build_markdown_summary_table(findings, lines_scanned, duration_ms))
            if args.sarif:
                export_sarif(findings, args.sarif)
                if not args.quiet:
                    print(f"SARIF report exported to: {args.sarif}")
            if args.json:
                export_json(findings, args.json)
                if not args.quiet:
                    print(f"JSON report exported to: {args.json}")
            if args.html:
                export_html(findings, args.html, lines_scanned, duration_ms)
                if not args.quiet:
                    print(f"Interactive HTML report exported to: {args.html}")

            if fail_threshold and should_fail_on_severity(findings, fail_threshold):
                print(f"\n❌ Threshold violation: Vulnerabilities matching or exceeding '{fail_threshold}' detected. Exiting with error.")
                sys.exit(1)
        else:
            if not args.quiet:
                print(f"✅ Heuristic Scan: Clean (Scanned {lines_scanned} lines in {duration_ms:.2f}ms)")
            if args.html:
                export_html(findings, args.html, lines_scanned, duration_ms)

        if api_key:
            if not args.quiet:
                print("\n🤖 Running Optional AI Review...")
            ai_report = audit_diff_with_ai(diff_text, api_key, model_name)
            print("\n" + ai_report)
        return

    # 3. GitHub Action Mode
    token = os.environ.get("GITHUB_TOKEN")
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not (token and event_path):
        print("PR Security Linter: No target path, local flag, or GitHub Action event detected. Run with --help for usage.")
        return

    try:
        with open(event_path, "r", encoding="utf-8") as f:
            event_data = json.load(f)
    except Exception as e:
        print(f"Error loading GitHub event payload: {e}")
        return

    pr_data = event_data.get("pull_request")
    if not pr_data:
        print("Not a pull request event.")
        return

    repo_full_name = event_data["repository"]["full_name"]
    pr_number = pr_data["number"]
    diff_text = get_pr_diff(repo_full_name, pr_number, token)

    if not diff_text.strip():
        print("Empty or inaccessible diff.")
        generate_svg_badge(False)
        write_github_action_outputs([], args.sarif or "", args.html or "")
        return

    lines_scanned = count_scanned_lines(diff_text)
    findings = heuristic_scan_structured(diff_text, ignore_paths)
    duration_ms = (time.time() - start_time) * 1000

    generate_svg_badge(bool(findings))

    summary_table = build_markdown_summary_table(findings, lines_scanned, duration_ms)
    report_sections = [f"#### 📊 Security Summary\n{summary_table}"]

    if args.sarif:
        export_sarif(findings, args.sarif)
    if args.json:
        export_json(findings, args.json)
    if args.html:
        export_html(findings, args.html, lines_scanned, duration_ms)

    write_github_action_outputs(findings, args.sarif or "", args.html or "")

    if api_key:
        try:
            ai_report = audit_diff_with_ai(diff_text, api_key, model_name)
            report_sections.append("#### 🤖 AI Review & Suggested Fixes\n" + ai_report)
        except Exception as e:
            report_sections.append(f"*(AI review unavailable: {e})*")

    badge_img = (
        "https://img.shields.io/badge/PR%20Security-ISSUES%20FOUND-red"
        if findings
        else "https://img.shields.io/badge/PR%20Security-PASSED-brightgreen"
    )

    final_comment = (
        f"![Security Status]({badge_img})\n\n"
        f"### 🛡️ PR Security Linter Report (v{__version__})\n\n"
        + "\n\n".join(report_sections)
        + f"\n\n---\n*Automated audit by [pr-security-linter](https://github.com/knmt1219/pr-security-linter)*"
    )

    post_comment(repo_full_name, pr_number, token, final_comment)
    print(f"Security audit posted to PR #{pr_number} ({lines_scanned} lines scanned in {duration_ms:.2f}ms).")

    if fail_threshold and should_fail_on_severity(findings, fail_threshold):
        sys.exit(1)


if __name__ == "__main__":
    main()
