import os
import sys
import re
import json
import argparse
import html
import requests

VERSION = "2.0.0"

COMMON_SECRET_PATTERNS = [
    (r'(?i)(?:aws_access_key_id|aws_secret_access_key|aws_session_token)\s*=\s*["\']?([A-Za-z0-9/+=]{20,})', "AWS Credential Leak", "10.0"),
    (r'(?i)(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}', "GitHub Personal Access Token", "9.5"),
    (r'-----BEGIN\s+([A-Z\s]+)?PRIVATE\s+KEY-----', "Exposed Private Key", "10.0"),
    (r'(?i)(?:api[_-]?key|secret[_-]?key|auth[_-]?token)\s*=\s*["\']([a-zA-Z0-9_\-]{16,})["\']', "Potential Hardcoded API Key/Token", "8.5"),
    (r'(?i)password\s*=\s*["\']([^"\']{4,})["\']', "Hardcoded Plaintext Password", "8.0"),
]

LANGUAGE_VULN_PATTERNS = [
    (r'(?i)(?:eval|exec)\s*\(', "Dangerous Dynamic Code Execution (eval/exec)", "9.0"),
    (r'(?i)subprocess\.(?:Popen|call|run)\s*\(.*shell\s*=\s*True', "Command Injection Risk (shell=True)", "9.5"),
    (r'(?i)dangerouslySetInnerHTML', "Cross-Site Scripting (XSS) via dangerouslySetInnerHTML", "7.5"),
    (r'(?i)pickle\.loads\s*\(', "Insecure Deserialization (pickle.loads)", "9.8"),
]

SEVERITY_RANKS = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

def mask_sensitive_value(line: str) -> str:
    def mask_match(m):
        val = m.group(0)
        if len(val) > 8:
            return val[:4] + "..." + val[-4:]
        return val
    return re.sub(r'[A-Za-z0-9_\-]{12,}', mask_match, line)

def get_pr_diff(repo_full_name: str, pr_number: int, github_token: str) -> str:
    url = f"https://api.github.com/repos/{repo_full_name}/pulls/{pr_number}"
    headers = {"Authorization": f"Bearer {github_token}", "Accept": "application/vnd.github.v3.diff"}
    res = requests.get(url, headers=headers, timeout=30)
    return res.text if res.status_code == 200 else ""

def post_comment(repo_full_name: str, pr_number: int, github_token: str, body: str) -> bool:
    url = f"https://api.github.com/repos/{repo_full_name}/issues/{pr_number}/comments"
    headers = {"Authorization": f"Bearer {github_token}", "Accept": "application/vnd.github.v3+json"}
    res = requests.post(url, headers=headers, json={"body": body}, timeout=30)
    return res.status_code == 201

def heuristic_scan_structured(diff_text: str) -> list:
    findings = []
    for line in diff_text.splitlines():
        if line.startswith('+') and not line.startswith('+++'):
            clean_line = line[1:].strip()
            masked_line = mask_sensitive_value(clean_line)
            for pattern, desc, score in COMMON_SECRET_PATTERNS:
                if re.search(pattern, line):
                    findings.append({
                        "severity": "CRITICAL",
                        "type": desc,
                        "score": score,
                        "confidence": "99%",
                        "snippet": masked_line[:80]
                    })
            for pattern, desc, score in LANGUAGE_VULN_PATTERNS:
                if re.search(pattern, line):
                    findings.append({
                        "severity": "HIGH",
                        "type": desc,
                        "score": score,
                        "confidence": "95%",
                        "snippet": masked_line[:80]
                    })
    return findings

def build_markdown_summary_table(findings: list) -> str:
    if not findings:
        return "✅ **Security Status:** No vulnerabilities or secret leaks detected."
    
    table = "| Severity | Vulnerability Type | CVSS | Confidence | Code Snippet |\n"
    table += "| :--- | :--- | :---: | :---: | :--- |\n"
    for f in findings:
        badge = "🔴 `CRITICAL`" if f["severity"] == "CRITICAL" else "🟠 `HIGH`"
        table += f"| {badge} | {f['type']} | **{f['score']}** | {f['confidence']} | `{f['snippet']}` |\n"
    return table

def generate_svg_badge(has_issues: bool, output_path: str = "security-badge.svg"):
    color = "#e05d44" if has_issues else "#4c1"
    status_text = "issues found" if has_issues else "passed"
    svg_content = f"""<svg xmlns="http://www.w3.org/2000/svg" width="140" height="20">
  <linearGradient id="b" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
  <mask id="a"><rect width="140" height="20" rx="3" fill="#fff"/></mask>
  <g mask="url(#a)">
    <path fill="#555" d="M0 0h90v20H0z"/>
    <path fill="{color}" d="M90 0h50v20H90z"/>
    <path fill="url(#b)" d="M0 0h140v20H0z"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="45" y="15" fill="#010101" fill-opacity=".3">security audit</text>
    <text x="45" y="14">security audit</text>
    <text x="115" y="15" fill="#010101" fill-opacity=".3">{status_text}</text>
    <text x="115" y="14">{status_text}</text>
  </g>
</svg>"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(svg_content)
    print(f"SVG security badge generated at: {output_path}")

def export_html(findings: list, output_path: str = "security-report.html"):
    critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
    medium_count = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    low_count = sum(1 for f in findings if f.get("severity") in ("LOW", "INFO"))
    total_count = len(findings)
    status_text = "FAILED" if total_count > 0 else "PASSED"
    status_color = "#e53e3e" if total_count > 0 else "#38a169"

    table_rows = ""
    if findings:
        for f in findings:
            sev = f.get("severity", "LOW")
            badge_class = "badge-critical" if sev == "CRITICAL" else ("badge-high" if sev == "HIGH" else "badge-medium")
            safe_type = html.escape(str(f.get("type", "")))
            safe_score = html.escape(str(f.get("score", "N/A")))
            safe_conf = html.escape(str(f.get("confidence", "N/A")))
            safe_snip = html.escape(str(f.get("snippet", "")))
            table_rows += f"""
            <tr>
                <td><span class="badge {badge_class}">{sev}</span></td>
                <td><strong>{safe_type}</strong></td>
                <td><span class="cvss-score">{safe_score}</span></td>
                <td>{safe_conf}</td>
                <td><code>{safe_snip}</code></td>
            </tr>
            """
    else:
        table_rows = """
        <tr>
            <td colspan="5" style="text-align: center; color: #718096; padding: 2rem;">
                🎉 No vulnerabilities or security risks detected in scanned diff!
            </td>
        </tr>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Codex Security Linter - Audit Report v{VERSION}</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-card: #334155;
            --text-primary: #f8fafc;
            --text-muted: #94a3b8;
            --accent-red: #ef4444;
            --accent-orange: #f97316;
            --accent-green: #10b981;
            --accent-blue: #3b82f6;
            --border-color: #475569;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }}
        body {{ background-color: var(--bg-primary); color: var(--text-primary); padding: 2rem; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; padding-bottom: 1rem; border-bottom: 1px solid var(--border-color); }}
        .header-title h1 {{ font-size: 1.8rem; display: flex; align-items: center; gap: 0.5rem; }}
        .header-title p {{ color: var(--text-muted); font-size: 0.9rem; margin-top: 0.25rem; }}
        .status-badge {{ background: {status_color}; color: #fff; padding: 0.5rem 1rem; border-radius: 9999px; font-weight: bold; font-size: 0.9rem; text-transform: uppercase; }}
        .metrics-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
        .card {{ background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 0.5rem; padding: 1.25rem; text-align: center; }}
        .card-value {{ font-size: 2rem; font-weight: bold; margin-top: 0.5rem; }}
        .text-red {{ color: var(--accent-red); }}
        .text-orange {{ color: var(--accent-orange); }}
        .text-green {{ color: var(--accent-green); }}
        .table-container {{ background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 0.5rem; overflow-x: auto; }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 0.95rem; }}
        th, td {{ padding: 1rem; border-bottom: 1px solid var(--border-color); }}
        th {{ background: rgba(0,0,0,0.2); color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 0.8rem; letter-spacing: 0.05em; }}
        tr:hover {{ background: rgba(255,255,255,0.02); }}
        .badge {{ display: inline-block; padding: 0.25rem 0.5rem; border-radius: 0.25rem; font-weight: bold; font-size: 0.75rem; }}
        .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }}
        .badge-high {{ background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid #f97316; }}
        .badge-medium {{ background: rgba(234, 179, 8, 0.2); color: #facc15; border: 1px solid #eab308; }}
        .cvss-score {{ font-weight: bold; color: #cbd5e1; }}
        code {{ background: #0f172a; border: 1px solid var(--border-color); color: #38bdf8; padding: 0.2rem 0.4rem; border-radius: 0.25rem; font-family: 'Fira Code', monospace; font-size: 0.85rem; word-break: break-all; }}
        footer {{ margin-top: 2.5rem; text-align: center; color: var(--text-muted); font-size: 0.85rem; }}
        footer a {{ color: var(--accent-blue); text-decoration: none; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-title">
                <h1>🛡️ Codex Security Linter Report</h1>
                <p>AI-Powered Vulnerability & Secret Leak Audit Engine v{VERSION}</p>
            </div>
            <div class="status-badge">{status_text}</div>
        </header>

        <div class="metrics-grid">
            <div class="card">
                <div>Total Findings</div>
                <div class="card-value">{total_count}</div>
            </div>
            <div class="card">
                <div>Critical Severity</div>
                <div class="card-value text-red">{critical_count}</div>
            </div>
            <div class="card">
                <div>High Severity</div>
                <div class="card-value text-orange">{high_count}</div>
            </div>
            <div class="card">
                <div>Audit Status</div>
                <div class="card-value text-green" style="color: {status_color};">{status_text}</div>
            </div>
        </div>

        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Vulnerability Type</th>
                        <th>CVSS</th>
                        <th>Confidence</th>
                        <th>Code Snippet</th>
                    </tr>
                </thead>
                <tbody>
                    {table_rows}
                </tbody>
            </table>
        </div>

        <footer>
            Audited automatically by <a href="https://github.com/knmt1219/codex-security-linter">Codex Security Linter v{VERSION}</a> &bull; Open Source MIT License
        </footer>
    </div>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"✅ Interactive HTML report exported to: {output_path}")

def export_sarif(findings: list, output_path: str = "results.sarif"):
    sarif_data = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Codex Security Linter",
                    "version": VERSION,
                    "informationUri": "https://github.com/knmt1219/codex-security-linter",
                    "rules": [{
                        "id": "CSL001",
                        "name": "SecurityVulnerabilityOrSecret",
                        "shortDescription": {"text": "Security flaw or secret detected in code changes"}
                    }]
                }
            },
            "results": [
                {
                    "ruleId": "CSL001",
                    "level": "error" if f.get("severity") in ["CRITICAL", "HIGH"] else "warning",
                    "message": {"text": f"{f.get('type')} (CVSS: {f.get('score')}) in `{f.get('snippet')}`"}
                } for f in findings
            ]
        }]
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif_data, f, indent=2)

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

def audit_diff_with_ai(diff_text: str, api_key: str, model_name: str = "gpt-4o-mini") -> str:
    try:
        from openai import OpenAI
    except ImportError:
        return "*(OpenAI SDK not installed. Please run `pip install openai` to enable AI vulnerability analysis)*"

    client = OpenAI(api_key=api_key)
    prompt = (
        "You are an application security expert auditing an open-source Pull Request.\n"
        "Analyze the following code diff and report:\n"
        "1. [SEVERITY: CRITICAL/HIGH/MEDIUM/LOW] (Include Confidence % and estimated CVSS score).\n"
        "2. Concrete remediation code patches formatted as GitHub suggestions (```suggestion ... ```) when applicable.\n"
        "3. Best practices recommendation.\n"
        "If no vulnerabilities are detected, state: 'No security vulnerabilities detected.'\n\n"
        f"Diff:\n```diff\n{diff_text[:12000]}\n```"
    )
    res = client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "system", "content": "You are a specialized security audit agent for open-source repositories."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.1,
    )
    return res.choices[0].message.content

def main():
    parser = argparse.ArgumentParser(description=f"Codex Security Linter CLI & GitHub Action (v{VERSION})")
    parser.add_argument("--local", action="store_true", help="Run scan on local git diff")
    parser.add_argument("--sarif", type=str, help="Export scan results to SARIF format")
    parser.add_argument("--json", type=str, help="Export scan results to JSON format")
    parser.add_argument("--html", type=str, help="Export interactive HTML security dashboard report")
    parser.add_argument("--badge", action="store_true", help="Generate SVG status badge")
    parser.add_argument("--strict", action="store_true", help="Fail with exit code 1 if critical/high risks found")
    parser.add_argument(
        "--fail-on",
        type=str,
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "critical", "high", "medium", "low"],
        help="Exit with code 1 if findings meet or exceed the specified severity threshold",
    )
    args = parser.parse_args()

    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    model_name = os.environ.get("MODEL_NAME", "gpt-4o-mini")

    fail_threshold = None
    if args.fail_on:
        fail_threshold = args.fail_on.upper()
    elif args.strict:
        fail_threshold = "HIGH"

    if args.local:
        diff_text = os.popen("git diff HEAD~1").read()
        if not diff_text.strip():
            diff_text = os.popen("git diff").read()
        if not diff_text.strip():
            print("No local git changes detected to audit.")
            return

        print(f"🔍 Running Heuristic & Language-Aware Security Scan (v{VERSION})...")
        findings = heuristic_scan_structured(diff_text)
        if args.badge:
            generate_svg_badge(bool(findings))

        if findings:
            print("\n📊 Security Summary Matrix:")
            print(build_markdown_summary_table(findings))
            if args.sarif:
                export_sarif(findings, args.sarif)
            if args.json:
                with open(args.json, "w", encoding="utf-8") as jf:
                    json.dump(findings, jf, indent=2)
                print(f"JSON report exported to: {args.json}")
            if args.html:
                export_html(findings, args.html)
            
            if fail_threshold and should_fail_on_severity(findings, fail_threshold):
                print(f"\n❌ Threshold violation: Vulnerabilities matching or exceeding '{fail_threshold}' detected. Exiting with error.")
                sys.exit(1)
        else:
            print("✅ Heuristic Scan: Clean (No secrets or dangerous patterns detected)")
            if args.html:
                export_html(findings, args.html)

        if api_key:
            print("\n🤖 Running Deep AI Security Analysis...")
            ai_report = audit_diff_with_ai(diff_text, api_key, model_name)
            print("\n" + ai_report)
        return

    # Chế độ GitHub Action
    token = os.environ.get("GITHUB_TOKEN")
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not (token and event_path):
        print("Warning: GITHUB_TOKEN or GITHUB_EVENT_PATH not set. Exiting cleanly.")
        return

    try:
        with open(event_path, "r", encoding="utf-8") as f:
            event_data = json.load(f)
    except Exception as e:
        print(f"Error loading event payload: {e}")
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
        return

    findings = heuristic_scan_structured(diff_text)
    if args.badge:
        generate_svg_badge(bool(findings))

    summary_table = build_markdown_summary_table(findings)
    report_sections = [f"#### 📊 Executive Security Summary\n{summary_table}"]

    if args.sarif:
        export_sarif(findings, args.sarif)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as jf:
            json.dump(findings, jf, indent=2)
    if args.html:
        export_html(findings, args.html)

    if api_key:
        try:
            ai_report = audit_diff_with_ai(diff_text, api_key, model_name)
            report_sections.append("#### 🤖 Deep AI Security Analysis & Fixes\n" + ai_report)
        except Exception as e:
            report_sections.append(f"*(AI analysis unavailable: {e})*")

    final_comment = (
        f"### 🛡️ Codex Security Audit Report (v{VERSION})\n\n"
        + "\n\n".join(report_sections)
        + f"\n\n---\n*Automated audit powered by [codex-security-linter](https://github.com/knmt1219/codex-security-linter)*"
    )

    post_comment(repo_full_name, pr_number, token, final_comment)
    print("Security audit executed and posted successfully.")

    if fail_threshold and should_fail_on_severity(findings, fail_threshold):
        sys.exit(1)

if __name__ == "__main__":
    main()
