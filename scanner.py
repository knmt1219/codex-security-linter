#!/usr/bin/env python3
"""
Codex Security Linter
=====================
AI-powered security linter for GitHub Pull Requests.
Analyzes PR git diffs to detect secret leaks, OWASP Top 10 vulnerabilities,
and propose remediation patches using OpenAI LLMs.
"""

import json
import os
import sys
from typing import Any, Dict, List, Optional
import requests
from openai import OpenAI

REPORT_MARKER = "<!-- codex-security-linter-report -->"
MAX_DIFF_LENGTH = 60_000  # Truncate diff if exceptionally large to stay within context limits

SYSTEM_PROMPT = """You are a Principal Application Security Engineer and DevSecOps Specialist conducting a strict automated security code review on a GitHub Pull Request diff.

Your mission is to perform deep security auditing on the code changes, specifically checking for:
1. Hardcoded Secrets & Sensitive Data: API keys, tokens, passwords, private keys, JWTs, cloud credentials, database connection strings.
2. Injection Flaws: SQL Injection, Command Injection (OS/shell), NoSQL Injection, LDAP Injection, Template Injection (SSTI).
3. Cross-Site Scripting (XSS) & SSRF: Reflected/Stored/DOM XSS, Server-Side Request Forgery, Unvalidated Redirects.
4. Insecure Deserialization & RCE: Unsafe pickle, yaml.load, eval, exec, untrusted object deserialization.
5. Broken Access Control & Auth: IDOR, missing permission checks, JWT validation bypass, weak cryptography, insecure random generators.
6. Path Traversal & File Uploads: Unrestricted file uploads, zip slips, directory traversal (../).

Instructions for your report:
- If NO security issues or secrets are found:
  Output a concise report stating that the code diff was reviewed and no security vulnerabilities or secret leaks were identified.
- If security issues ARE found:
  1. Provide an executive summary table with counts by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO).
  2. For each finding:
     - **Title & Severity** (e.g. `### [HIGH] SQL Injection in user query`)
     - **Vulnerability Type / CWE**: (e.g., `CWE-89: SQL Injection`, `OWASP A03:2021-Injection`)
     - **Location**: Specify file name and relevant lines from the diff.
     - **Description**: Clear technical explanation of the vulnerability and attack vector.
     - **Remediation & Secure Patch**: Provide concrete code suggestions or a diff block demonstrating the secure implementation.

Format your entire response in clean, professional GitHub Flavored Markdown.
"""


def get_required_env(var_name: str) -> str:
    """Retrieve required environment variable or exit with error."""
    value = os.getenv(var_name)
    if not value or not value.strip():
        print(f"❌ Error: Required environment variable '{var_name}' is not set.", file=sys.stderr)
        sys.exit(1)
    return value.strip()


def get_pr_context() -> Dict[str, Any]:
    """Extract PR context from GitHub Actions event payload."""
    event_path = os.getenv("GITHUB_EVENT_PATH")
    repo = os.getenv("GITHUB_REPOSITORY")
    pr_number = os.getenv("PR_NUMBER")

    if not repo:
        print("❌ Error: GITHUB_REPOSITORY environment variable is not set.", file=sys.stderr)
        sys.exit(1)

    if event_path and os.path.exists(event_path):
        try:
            with open(event_path, "r", encoding="utf-8") as f:
                event_data = json.load(f)

            if "pull_request" in event_data:
                return {
                    "repo": repo,
                    "pr_number": event_data["pull_request"]["number"],
                    "title": event_data["pull_request"].get("title", ""),
                    "action": event_data.get("action", ""),
                }
            elif "issue" in event_data and "pull_request" in event_data["issue"]:
                return {
                    "repo": repo,
                    "pr_number": event_data["issue"]["number"],
                    "title": event_data["issue"].get("title", ""),
                    "action": event_data.get("action", ""),
                }
        except Exception as e:
            print(f"⚠️ Warning: Failed to parse GITHUB_EVENT_PATH payload: {e}", file=sys.stderr)

    if pr_number and pr_number.isdigit():
        return {
            "repo": repo,
            "pr_number": int(pr_number),
            "title": "Manual PR Scan",
            "action": "manual",
        }

    print(
        "❌ Error: Could not determine Pull Request number from GITHUB_EVENT_PATH or PR_NUMBER.",
        file=sys.stderr,
    )
    sys.exit(1)


def fetch_pr_diff(repo: str, pr_number: int, token: str) -> str:
    """Fetch PR git diff using the GitHub REST API."""
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3.diff",
        "User-Agent": "codex-security-linter",
    }

    print(f"📥 Fetching diff for {repo} PR #{pr_number}...")
    response = requests.get(url, headers=headers, timeout=30)

    if response.status_code != 200:
        print(
            f"❌ Error: GitHub API returned status {response.status_code}: {response.text}",
            file=sys.stderr,
        )
        sys.exit(1)

    diff_text = response.text
    if not diff_text.strip():
        print("ℹ️ Pull Request contains no code changes (empty diff).")
        return ""

    print(f"✅ Successfully retrieved PR diff ({len(diff_text):,} characters).")
    return diff_text


def analyze_diff_with_ai(diff: str, api_key: str, model: str) -> str:
    """Send PR diff to OpenAI for security vulnerability analysis."""
    truncated = False
    diff_to_send = diff
    if len(diff) > MAX_DIFF_LENGTH:
        diff_to_send = diff[:MAX_DIFF_LENGTH]
        truncated = True

    user_prompt = f"""Please review the following GitHub Pull Request diff for security vulnerabilities, secret leaks, and insecure coding patterns:

```diff
{diff_to_send}
```
"""
    if truncated:
        user_prompt += (
            f"\n\n> Note: The diff was truncated to {MAX_DIFF_LENGTH:,} characters "
            f"out of {len(diff):,} total characters."
        )

    print(f"🤖 Initiating AI security scan using model '{model}'...")
    client = OpenAI(api_key=api_key)

    try:
        completion = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.1,
        )
        report = completion.choices[0].message.content or ""
        print("✅ AI Security analysis completed.")
        return report.strip()
    except Exception as e:
        print(f"❌ Error during OpenAI API call: {e}", file=sys.stderr)
        sys.exit(1)


def find_existing_bot_comment(repo: str, pr_number: int, token: str) -> Optional[int]:
    """Find existing security linter comment on the PR to update."""
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "codex-security-linter",
    }

    try:
        response = requests.get(url, headers=headers, timeout=20)
        if response.status_code == 200:
            comments: List[Dict[str, Any]] = response.json()
            for comment in comments:
                if REPORT_MARKER in comment.get("body", ""):
                    return comment.get("id")
    except Exception as e:
        print(f"⚠️ Warning: Could not search existing comments: {e}", file=sys.stderr)

    return None


def post_pr_comment(repo: str, pr_number: int, report: str, token: str) -> None:
    """Post or update security audit report as a PR comment."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "codex-security-linter",
    }

    full_body = (
        f"{REPORT_MARKER}\n"
        f"## 🛡️ Codex Security Linter Audit\n\n"
        f"{report}\n\n"
        f"---\n"
        f"*Audited automatically by [Codex Security Linter](https://github.com/{repo})*"
    )

    comment_id = find_existing_bot_comment(repo, pr_number, token)

    if comment_id:
        print(f"🔄 Updating existing comment (ID: {comment_id}) on PR #{pr_number}...")
        url = f"https://api.github.com/repos/{repo}/issues/comments/{comment_id}"
        response = requests.patch(url, headers=headers, json={"body": full_body}, timeout=20)
    else:
        print(f"💬 Posting new security report comment to PR #{pr_number}...")
        url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
        response = requests.post(url, headers=headers, json={"body": full_body}, timeout=20)

    if response.status_code in (200, 201):
        print(f"✅ Successfully posted security audit report to PR #{pr_number}.")
    else:
        print(
            f"❌ Failed to post PR comment. HTTP {response.status_code}: {response.text}",
            file=sys.stderr,
        )
        sys.exit(1)


def main() -> None:
    print("=" * 60)
    print("🛡️  Codex Security Linter - Starting Pull Request Scan")
    print("=" * 60)

    github_token = get_required_env("GITHUB_TOKEN")
    openai_api_key = get_required_env("OPENAI_API_KEY")
    openai_model = os.getenv("OPENAI_MODEL", "gpt-4o")

    pr_context = get_pr_context()
    repo = pr_context["repo"]
    pr_number = pr_context["pr_number"]

    print(f"🎯 Target Repository : {repo}")
    print(f"🔢 Pull Request     : #{pr_number}")
    print(f"🧠 AI Model         : {openai_model}")

    diff = fetch_pr_diff(repo, pr_number, github_token)
    if not diff:
        print("🎉 No code diff to analyze. Security scan skipped.")
        return

    report = analyze_diff_with_ai(diff, openai_api_key, openai_model)
    post_pr_comment(repo, pr_number, report, github_token)

    print("=" * 60)
    print("✨ Codex Security Linter finished successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()
