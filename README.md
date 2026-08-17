# Codex Security Linter 🛡️

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Release](https://img.shields.io/badge/Release-v1.2.0-blue.svg)](https://github.com/knmt1219/codex-security-linter/releases)
[![Python Version](https://img.shields.io/badge/Python-3.11%2B-green.svg)](https://www.python.org/)
[![GitHub Action](https://img.shields.io/badge/GitHub%20Action-Security%20Linter-purple.svg)](https://github.com/marketplace)

An open-source security linter that operates both as a **GitHub Action** and a **Local CLI Tool** to detect secret leaks, injection flaws, and vulnerabilities across code diffs with automated remediation suggestions.

---

## 🏗️ Architecture Overview

```mermaid
graph LR
    A[Git Diff / PR] --> B[codex-security-linter]
    B --> C{AI Security Engine}
    C -->|Secret Leak| D[Flag Hardcoded Secret]
    C -->|Vulnerabilities| E[Propose Fix Code]
    D & E --> F[Post PR Comment / CLI Output]
```

---

## ✨ Key Features

- **Secret & Token Leak Detection**: Instantly catches hardcoded API keys, private certificates, and tokens.
- **Vulnerability Auditing**: Analyzes code diffs for SQLi, XSS, Command Injection, and SSRF flaws.
- **Remediation Suggestions**: Generates secure code replacements directly in PR comments or terminal output.
- **Dual Runtime Support**: Operates seamlessly as a GitHub Action in CI/CD pipelines or locally via CLI (`--local`).

---

## 💻 Local CLI Usage

Run a security audit directly on your local uncommitted changes or recent commits before pushing:

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Set OpenAI API Key
export OPENAI_API_KEY="sk-xxxxxxxxxxxxxxxxxxxxxxxx"

# 3. Run audit on local git diff
python scanner.py --local
```

---

## 🚀 GitHub Action Quick Setup

Add `.github/workflows/security.yml` to your repository:

```yaml
name: Security Audit
on:
  pull_request:
    types: [opened, synchronize]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: knmt1219/codex-security-linter@v1.2.0
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          openai-api-key: ${{ secrets.OPENAI_API_KEY }}
          model: 'gpt-4o-mini'
```

---

## ⚙️ Configuration (`.codex-security.yml`)

You can customize the linter behavior using `.codex-security.yml`:

```yaml
version: 1.0
settings:
  model: "gpt-4o-mini"
  severity_threshold: "MEDIUM"
ignore_paths:
  - "tests/*"
  - "docs/*"
  - "*.lock"
rules:
  secret_leak_detection: true
  injection_flaws: true
  deserialization_risks: true
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
