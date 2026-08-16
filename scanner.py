import os
import sys
import json
import argparse
import requests
from openai import OpenAI

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

def audit_diff_with_ai(diff_text: str, api_key: str, model_name: str = "gpt-4o-mini") -> str:
    client = OpenAI(api_key=api_key)
    prompt = (
        "You are an application security expert auditing an open-source Pull Request.\n"
        "Analyze the following code diff and report:\n"
        "1. [SEVERITY: CRITICAL/HIGH/MEDIUM/LOW] Summary of found risks (Secret leaks, SQLi, XSS, RCE, SSRF).\n"
        "2. Concrete remediation code patches (Before vs After).\n"
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
    args = parser.parse_args()

    api_key = os.environ.get("OPENAI_API_KEY")
    model_name = os.environ.get("MODEL_NAME", "gpt-4o-mini")

    if not api_key:
        print("Error: OPENAI_API_KEY environment variable is required.", file=sys.stderr)
        sys.exit(1)

    if args.local:
        # Chế độ quét cục bộ trên máy
        diff_text = os.popen("git diff HEAD~1").read()
        if not diff_text.strip():
            diff_text = os.popen("git diff").read()
        if not diff_text.strip():
            print("No local git changes detected to audit.")
            return
        print("🔍 Auditing local git diff...")
        report = audit_diff_with_ai(diff_text, api_key, model_name)
        print("\n" + report)
        return

    # Chế độ chạy trên GitHub Action
    token = os.environ.get("GITHUB_TOKEN")
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not (token and event_path):
        print("Error: GITHUB_TOKEN and GITHUB_EVENT_PATH are required in Action mode.", file=sys.stderr)
        return

    with open(event_path, "r", encoding="utf-8") as f:
        event_data = json.load(f)

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

    report = audit_diff_with_ai(diff_text, api_key, model_name)
    comment_body = (
        "### 🛡️ Codex Security Audit Report\n\n"
        f"{report}\n\n"
        "---\n*Automated audit powered by [codex-security-linter](https://github.com/knmt1219/codex-security-linter)*"
    )
    post_comment(repo_full_name, pr_number, token, comment_body)
    print("Security audit posted successfully.")

if __name__ == "__main__":
    main()
