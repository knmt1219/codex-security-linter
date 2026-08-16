import os
import json
import requests
from openai import OpenAI

def get_pr_diff(repo_full_name: str, pr_number: int, github_token: str) -> str:
    url = f"https://api.github.com/repos/{repo_full_name}/pulls/{pr_number}"
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github.v3.diff",
    }
    res = requests.get(url, headers=headers, timeout=30)
    return res.text if res.status_code == 200 else ""

def post_comment(repo_full_name: str, pr_number: int, github_token: str, body: str) -> bool:
    url = f"https://api.github.com/repos/{repo_full_name}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github.v3+json",
    }
    res = requests.post(url, headers=headers, json={"body": body}, timeout=30)
    return res.status_code == 201

def build_audit_prompt(diff_text: str) -> str:
    return (
        "You are an application security expert reviewing an open-source Pull Request.\n"
        "Audit the following code diff for security concerns:\n"
        "1. Hardcoded secrets, API keys, tokens, or credentials.\n"
        "2. Injection vulnerabilities (SQLi, XSS, Command Injection, SSRF).\n"
        "3. Insecure deserialization, memory safety risks, or broken access control.\n"
        "4. Provide concrete, copy-pasteable remediation code snippets.\n"
        "If the diff contains no security issues, explicitly state that no vulnerabilities were detected.\n\n"
        f"Diff:\n```diff\n{diff_text[:12000]}\n```"
    )

def main():
    github_token = os.environ.get("GITHUB_TOKEN")
    openai_api_key = os.environ.get("OPENAI_API_KEY")
    model_name = os.environ.get("MODEL_NAME", "gpt-4o-mini")
    event_path = os.environ.get("GITHUB_EVENT_PATH")

    if not (github_token and openai_api_key and event_path):
        print("Missing required environment variables.")
        return

    with open(event_path, "r", encoding="utf-8") as f:
        event_data = json.load(f)

    pr_data = event_data.get("pull_request")
    if not pr_data:
        print("Not a pull request event.")
        return

    pr_number = pr_data["number"]
    repo_full_name = event_data["repository"]["full_name"]
    diff_text = get_pr_diff(repo_full_name, pr_number, github_token)

    if not diff_text.strip():
        print("Empty or inaccessible diff.")
        return

    client = OpenAI(api_key=openai_api_key)
    prompt = build_audit_prompt(diff_text)

    res = client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "system", "content": "You are a specialized open-source security audit agent."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.1,
    )

    audit_result = res.choices[0].message.content
    comment_body = (
        "### 🛡️ Codex Security Audit Report\n\n"
        f"{audit_result}\n\n"
        "---\n*Automated audit powered by [codex-security-linter](https://github.com/knmt1219/codex-security-linter)*"
    )
    post_comment(repo_full_name, pr_number, github_token, comment_body)
    print("Security audit posted successfully.")

if __name__ == "__main__":
    main()
