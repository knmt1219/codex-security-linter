import os
import sys
import re
import json
import argparse
import requests
from openai import OpenAI

COMMON_SECRET_PATTERNS = [
    (r'(?i)(?:aws_access_key_id|aws_secret_access_key|aws_session_token)\s*=\s*["\']?([A-Za-z0-9/+=]{20,})', "AWS Credential Leak"),
    (r'(?i)(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}', "GitHub Personal Access Token"),
    (r'-----BEGIN\s+PRIVATE\s+KEY-----', "Exposed Private Key"),
    (r'(?i)(?:api[_-]?key|secret[_-]?key|auth[_-]?token)\s*=\s*["\']([a-zA-Z0-9_\-]{16,})["\']', "Potential Hardcoded API Key/Token"),
    (r'(?i)password\s*=\s*["\']([^"\']{4,})["\']', "Hardcoded Plaintext Password"),
]

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

def heuristic_regex_scan(diff_text: str) -> list:
    findings = []
    for line in diff_text.splitlines():
        if line.startswith('+') and not line.startswith('+++'):
            for pattern, desc in COMMON_SECRET_PATTERNS:
                if re.search(pattern, line):
                    findings.append(f"- **[CRITICAL SECRET LEAK]** `{desc}` found in added line:\n  > `{line[1:].strip()[:80]}`")
    return findings

def audit_diff_with_ai(diff_text: str, api_key: str, model_name: str = "gpt-4o-mini") -> str:
    client = OpenAI(api_key=api_key)
    prompt = (
        "You are an application security expert auditing an open-source Pull Request.\n"
        "Analyze the following code diff and report:\n"
        "1. [SEVERITY: CRITICAL/HIGH/MEDIUM/LOW] Summary of found risks (Secret leaks, SQLi, XSS, RCE, SSRF).\n"
        "2. Concrete remediation code patches (Before vs After) with GitHub suggestion formatting when applicable.\n"
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

def export_sarif(findings: list, output_path: str = "results.sarif"):
    sarif_data = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Codex Security Linter",
                    "version": "1.3.0",
                    "informationUri": "https://github.com/knmt1219/codex-security-linter",
                    "rules": [{
                        "id": "CSL001",
                        "name": "HardcodedSecretOrVulnerability",
                        "shortDescription": {"text": "Security flaw or secret detected in code changes"}
                    }]
                }
            },
            "results": [
                {
                    "ruleId": "CSL001",
                    "level": "error",
                    "message": {"text": f}
                } for f in findings
            ]
        }]
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif_data, f, indent=2)
    print(f"✅ SARIF report successfully exported to {output_path}")

def main():
    parser = argparse.ArgumentParser(description="Codex Security Linter CLI & GitHub Action")
    parser.add_argument("--local", action="store_true", help="Run scan on local git diff")
    parser.add_argument("--sarif", nargs="?", const="results.sarif", default=None, help="Export scan results to SARIF format")
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

        print("🔍 Scanning local diff for secrets (Heuristic)...")
        regex_findings = heuristic_regex_scan(diff_text)
        if regex_findings:
            print("\n⚠️ Heuristic Scanner Findings:\n" + "\n".join(regex_findings))

        ai_report = None
        if api_key:
            print("\n🤖 Running Deep AI Security Audit...")
            ai_report = audit_diff_with_ai(diff_text, api_key, model_name)
            print("\n" + ai_report)
        else:
            print("\nℹ️ Tip: Set OPENAI_API_KEY for advanced AI vulnerability analysis.")

        if args.sarif:
            all_findings = list(regex_findings)
            if ai_report:
                all_findings.append(ai_report)
            export_sarif(all_findings, args.sarif)
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

    # 1. Chạy quét regex nhanh
    regex_findings = heuristic_regex_scan(diff_text)
    report_sections = []

    if regex_findings:
        report_sections.append("#### 🚨 Immediate Secret Leaks Detected (Regex Engine)\n" + "\n".join(regex_findings))

    # 2. Chạy quét AI nếu có key
    ai_report = None
    if api_key:
        try:
            ai_report = audit_diff_with_ai(diff_text, api_key, model_name)
            report_sections.append("#### 🤖 Deep AI Security Analysis\n" + ai_report)
        except Exception as e:
            report_sections.append(f"*(AI analysis unavailable: {e})*")
    else:
        report_sections.append("ℹ️ *Note: Add `OPENAI_API_KEY` to repository secrets to enable deep AI vulnerability analysis.*")

    final_comment = (
        "### 🛡️ Codex Security Audit Report\n\n"
        + "\n\n".join(report_sections)
        + "\n\n---\n*Automated audit powered by [codex-security-linter](https://github.com/knmt1219/codex-security-linter)*"
    )

    post_comment(repo_full_name, pr_number, token, final_comment)
    print("Security audit executed and posted successfully.")

    if args.sarif:
        all_findings = list(regex_findings)
        if ai_report:
            all_findings.append(ai_report)
        export_sarif(all_findings, args.sarif)

if __name__ == "__main__":
    main()
