import os
import sys
import re
import json
import argparse
import requests

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

def heuristic_scan(diff_text: str) -> list:
    findings = []
    for line in diff_text.splitlines():
        if line.startswith('+') and not line.startswith('+++'):
            clean_line = line[1:].strip()
            masked_line = mask_sensitive_value(clean_line)
            for pattern, desc, score in COMMON_SECRET_PATTERNS:
                if re.search(pattern, line):
                    findings.append(f"- **[CRITICAL SECRET LEAK]** `{desc}` (CVSS: {score} | Confidence: 99%): `{masked_line[:80]}`")
            for pattern, desc, score in LANGUAGE_VULN_PATTERNS:
                if re.search(pattern, line):
                    findings.append(f"- **[HIGH SECURITY RISK]** `{desc}` (CVSS: {score} | Confidence: 95%): `{masked_line[:80]}`")
    return findings

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

def export_sarif(findings: list, output_path: str = "results.sarif"):
    sarif_data = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Codex Security Linter",
                    "version": "1.6.0",
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
                    "level": "error" if "CRITICAL" in f or "HIGH" in f else "warning",
                    "message": {"text": f}
                } for f in findings
            ]
        }]
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif_data, f, indent=2)

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
    parser = argparse.ArgumentParser(description="Codex Security Linter CLI & GitHub Action")
    parser.add_argument("--local", action="store_true", help="Run scan on local git diff")
    parser.add_argument("--sarif", type=str, help="Export scan results to SARIF format")
    parser.add_argument("--badge", action="store_true", help="Generate SVG status badge")
    parser.add_argument("--strict", action="store_true", help="Fail with exit code 1 if critical/high risks found")
    args = parser.parse_args()

    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    model_name = os.environ.get("MODEL_NAME", "gpt-4o-mini")

    if args.local:
        diff_text = os.popen("git diff HEAD~1").read()
        if not diff_text.strip():
            diff_text = os.popen("git diff").read()
        if not diff_text.strip():
            print("No local git changes detected to audit.")
            return

        print("🔍 Running Heuristic & Language-Aware Security Scan (v1.6.0)...")
        findings = heuristic_scan(diff_text)
        if args.badge:
            generate_svg_badge(bool(findings))

        if findings:
            print("\n⚠️ Scan Findings:")
            for f in findings:
                print(f"  {f}")
            if args.sarif:
                export_sarif(findings, args.sarif)
            if args.strict:
                print("\n❌ Strict mode: Vulnerabilities detected. Exiting with error.")
                sys.exit(1)
        else:
            print("✅ Heuristic Scan: Clean (No secrets or dangerous patterns detected)")

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

    findings = heuristic_scan(diff_text)
    if args.badge:
        generate_svg_badge(bool(findings))

    report_sections = []
    if findings:
        report_sections.append("#### 🚨 Immediate Risks Detected (Heuristic Engine v1.6.0)\n" + "\n".join(findings))
        if args.sarif:
            export_sarif(findings, args.sarif)

    if api_key:
        try:
            ai_report = audit_diff_with_ai(diff_text, api_key, model_name)
            report_sections.append("#### 🤖 Deep AI Security Analysis\n" + ai_report)
        except Exception as e:
            report_sections.append(f"*(AI analysis unavailable: {e})*")

    final_comment = (
        "### 🛡️ Codex Security Audit Report (v1.6.0)\n\n"
        + "\n\n".join(report_sections)
        + "\n\n---\n*Automated audit powered by [codex-security-linter](https://github.com/knmt1219/codex-security-linter)*"
    )

    post_comment(repo_full_name, pr_number, token, final_comment)
    print("Security audit executed and posted successfully.")

if __name__ == "__main__":
    main()
