# Codex Security Linter 🛡️

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Release](https://img.shields.io/badge/Release-v1.0.0-blue.svg)](https://github.com/knmt1219/codex-security-linter/releases)
[![Python Version](https://img.shields.io/badge/Python-3.11%2B-green.svg)](https://www.python.org/)
[![GitHub Action](https://img.shields.io/badge/GitHub%20Action-Security%20Linter-purple.svg)](https://github.com/marketplace)

An open-source GitHub Action that performs automated vulnerability scanning, secret leak detection, and remediation patch generation on every Pull Request using OpenAI and Codex models.

## ✨ Key Features
- **Secret & Token Leak Detection**: Instantly catches hardcoded API keys, private certificates, and tokens.
- **Vulnerability Auditing**: Analyzes code diffs for SQLi, XSS, Command Injection, and SSRF flaws.
- **Remediation Suggestions**: Generates secure code replacements directly in PR comments.
- **Zero Configuration Needed**: Runs entirely within GitHub Actions without external servers.

## 🚀 Quick Setup

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
      - uses: knmt1219/codex-security-linter@v1.0.0
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          openai-api-key: ${{ secrets.OPENAI_API_KEY }}
```

## ⚙️ Inputs

| Input | Description | Required | Default |
| :--- | :--- | :---: | :---: |
| `github-token` | GitHub Token for fetching PR diffs and posting review comments | **Yes** | N/A |
| `openai-api-key` | OpenAI API Key for AI-powered security analysis | **Yes** | N/A |
| `model` | OpenAI model to use for scanning | No | `gpt-4o-mini` |

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
