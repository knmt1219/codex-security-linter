# Codex Security Linter 🛡️

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![GitHub Actions](https://img.shields.io/badge/GitHub%20Actions-Composite-green.svg)](https://github.com/features/actions)
[![AI Security](https://img.shields.io/badge/Security-AI%20Audited-purple.svg)](https://github.com/)

**Codex Security Linter** is an AI-powered GitHub Action designed to safeguard your repositories by automatically auditing Pull Request diffs. Utilizing advanced Large Language Models, it detects hardcoded secrets, flags OWASP Top 10 vulnerabilities, and directly generates secure remediation patches in PR comments.

---

## 🚀 Key Features

- 🔑 **Secret & Credential Detection**: Catches accidentally committed API keys, tokens, passwords, private keys, JWTs, and database credentials before they merge.
- 🔍 **Comprehensive Vulnerability Auditing**:
  - **SQL Injection (SQLi)** & NoSQL / ORM injection
  - **Command Injection (RCE)** & unsafe shell execution
  - **Cross-Site Scripting (XSS)** & Server-Side Request Forgery (SSRF)
  - **Insecure Deserialization** (e.g., Python `pickle`, unsafe `yaml.load`, `eval`)
  - **Broken Access Control & IDOR**
  - **Path Traversal & Insecure File Handling**
- 🛠️ **Automated Remediation & Secure Patches**: Suggests actionable, copy-pasteable code fixes and git diff snippets.
- 💬 **Intelligent PR Commenting**: Automatically creates and updates security audit reports on Pull Requests without comment spam on subsequent commits (`synchronize` events).

---

## 📋 Quick Start

### 1. Configure Secrets in GitHub Repository
Add the following secret in your GitHub repository under **Settings > Secrets and variables > Actions**:
- `OPENAI_API_KEY`: Your OpenAI API key.

*(Note: `GITHUB_TOKEN` is automatically provided by GitHub Actions).*

### 2. Add the Security Workflow
Create `.github/workflows/security.yml` in your repository:

```yaml
name: Security Audit

on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read
  pull-requests: write
  issues: write

jobs:
  security-scan:
    name: AI Security Linter
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Run Codex Security Linter
        uses: knmt1219/codex-security-linter@main
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          openai-api-key: ${{ secrets.OPENAI_API_KEY }}
          openai-model: 'gpt-4o' # Optional, defaults to 'gpt-4o'
```

---

## ⚙️ Action Inputs

| Input | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| `github-token` | GitHub token for reading PR diffs and posting review comments (`secrets.GITHUB_TOKEN`) | **Yes** | N/A |
| `openai-api-key` | OpenAI API Key for AI analysis (`secrets.OPENAI_API_KEY`) | **Yes** | N/A |
| `openai-model` | OpenAI model to use for scanning (e.g. `gpt-4o`, `gpt-4o-mini`) | No | `gpt-4o` |

---

## 🏗️ How It Works

```
┌─────────────────┐       ┌────────────────────────┐       ┌──────────────────────┐
│  Pull Request   │ ────> │  Codex Security Linter │ ────> │  GitHub REST API     │
│  (opened/sync)  │       │  (GitHub Action)       │       │  Fetch PR Git Diff   │
└─────────────────┘       └───────────┬────────────┘       └──────────────────────┘
                                      │
                                      ▼
                          ┌────────────────────────┐
                          │   OpenAI GPT-4o Engine │
                          │   Security Audit Prompt│
                          └───────────┬────────────┘
                                      │
                                      ▼
                          ┌────────────────────────┐
                          │ Post / Update Markdown │
                          │ Comment on PR with     │
                          │ Vulnerability Patches  │
                          └────────────────────────┘
```

1. **Trigger**: Pull Request is opened or updated with new commits.
2. **Fetch Diff**: The action retrieves only the modified lines (`git diff`) using the GitHub REST API.
3. **Audit**: The diff is analyzed against OWASP Top 10 and secret detection heuristics with an AppSec-tailored system prompt.
4. **Report**: An audit summary with severity levels and proposed patches is posted directly onto the PR.

---

## 💻 Local Testing & Development

You can run the scanner locally on any PR by providing environment variables:

```bash
# Clone repository and install dependencies
git clone https://github.com/knmt1219/codex-security-linter.git
cd codex-security-linter
pip install -r requirements.txt

# Run scanner manually
export GITHUB_TOKEN="ghp_xxxxxxxxxxxxxxxxxxxx"
export OPENAI_API_KEY="sk-xxxxxxxxxxxxxxxxxxxx"
export GITHUB_REPOSITORY="owner/repo"
export PR_NUMBER="1"

python scanner.py
```

---

## 🔒 Security & Privacy

- **Minimal Scope**: Only modified code diffs are transmitted to OpenAI for auditing; full repository source trees are not uploaded.
- **Data Protection**: OpenAI API data is subject to the [OpenAI API Data Usage Policies](https://openai.com/enterprise-privacy) (data is not used to train future models by default).
- **Least Privilege**: The GitHub Action requires only `pull-requests: write` and `issues: write` permissions to function.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
