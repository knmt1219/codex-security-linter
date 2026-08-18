# Codex Security Linter 🛡️

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Release](https://img.shields.io/badge/Release-v2.0.0-blue.svg)](https://github.com/knmt1219/codex-security-linter/releases)
[![Python Version](https://img.shields.io/badge/Python-3.10%2B-green.svg)](https://www.python.org/)
[![GitHub Action](https://img.shields.io/badge/GitHub%20Action-Security%20Linter-purple.svg)](https://github.com/marketplace)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)](https://github.com/knmt1219/codex-security-linter)

**Codex Security Linter** is an open-source, enterprise-grade AI security auditing and linting engine. It operates seamlessly as a **GitHub Action**, **Pre-commit Hook**, and **Cross-Platform CLI Tool** to detect secret leaks, injection flaws, and security vulnerabilities across code diffs with automated remediation suggestions, CVSS 3.1 scoring, confidence estimation, interactive HTML dashboards, SVG status badges, and SARIF/JSON reporting.

---

## 🏗️ Architecture Overview

```mermaid
graph LR
    A[Git Diff / Pull Request] --> B[codex-security-linter]
    B --> C{AI & Heuristic Engine v2.0.0}
    C -->|Secret Leak| D[Mask Secret & CVSS/Confidence Scoring]
    C -->|Vulnerabilities| E[Propose Fix Code & SVG Badge]
    D & E --> F[Post PR Summary Matrix Table / HTML Dashboard / JSON / SARIF / CLI Output]
```

---

## ✨ Key Features

- 📊 **Executive Security Summary Table**: Formats all audit findings into a high-visibility Markdown matrix table (Severity badge, Type, CVSS, Confidence %, Code snippet).
- 🌐 **Interactive HTML Dashboard (`--html`)**: Generates a modern, standalone HTML5 security audit report with metrics cards and categorized findings.
- 🛑 **Configurable Fail-On Threshold (`--fail-on`)**: Automatically fails the CI build (`exit code 1`) if vulnerabilities meet or exceed your specified threshold (`CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`).
- 🔑 **Secret & Token Leak Detection with Masking**: Catches hardcoded API keys, private certificates, and tokens with rapid regex heuristics, automatically masking sensitive values (`AKIA...12`).
- 🎯 **CVSS 3.1 Impact Scoring & Confidence Matrix**: Assigns standard CVSS severity scores and confidence percentages to all detected security findings.
- 🖼️ **Dynamic SVG Security Badges (`--badge`)**: Generates embeddable status badges (`security audit: passed / issues found`) for CI workflows and dashboards.
- 📄 **Multi-Format Export Support**: Exports findings to industry-standard **SARIF** (`--sarif`), structured **JSON** (`--json`), and interactive **HTML** (`--html`).
- 💡 **One-Click GitHub Suggestions**: Generates secure code replacements formatted as GitHub suggestions (````suggestion ... ````) directly in PR comments.
- 🪝 **Pre-commit Hook Integration**: Prevents insecure commits locally before they reach the repository.
- ⚡ **Cross-Platform**: Full native support for **Windows (PowerShell/CMD)**, **macOS (zsh/bash)**, and **Linux (Ubuntu/Debian/Arch)**.

---

## 💻 Cross-Platform Installation & Local CLI Usage

### 🪟 1. Windows (PowerShell & CMD)

#### Prerequisites
- Python 3.10+ installed (ensure **"Add Python to PATH"** is checked during installation)
- Git installed

#### Step 1: Clone Repository & Set Up Virtual Environment
**PowerShell:**
```powershell
# Clone repository
git clone https://github.com/knmt1219/codex-security-linter.git
cd codex-security-linter

# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install package
pip install -e .
```

**Command Prompt (CMD):**
```cmd
REM Clone repository
git clone https://github.com/knmt1219/codex-security-linter.git
cd codex-security-linter

REM Create and activate virtual environment
python -m venv .venv
.venv\Scripts\activate.bat

REM Install package
pip install -e .
```

#### Step 2: Configure OpenAI API Key
**PowerShell:**
```powershell
$env:OPENAI_API_KEY="sk-xxxxxxxxxxxxxxxxxxxxxxxx"
```

**Command Prompt (CMD):**
```cmd
set OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxx
```

#### Step 3: Run Local Security Audit
```powershell
# Run heuristic & AI audit on local git diff
codex-security-linter --local

# Export interactive HTML report and SARIF/JSON
codex-security-linter --local --html security-report.html --json findings.json --sarif results.sarif

# Stop process (exit code 1) on CRITICAL vulnerabilities
codex-security-linter --local --fail-on CRITICAL

# Generate SVG status badge
codex-security-linter --local --badge
```

---

### 🍎 2. macOS (Terminal / zsh / bash)

#### Prerequisites
- Python 3.10+ (`brew install python` via Homebrew)
- Git installed (`xcode-select --install` or `brew install git`)

#### Step 1: Clone Repository & Set Up Virtual Environment
```bash
# Clone repository
git clone https://github.com/knmt1219/codex-security-linter.git
cd codex-security-linter

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install package
pip install -e .
```

#### Step 2: Configure OpenAI API Key
```bash
# Set for current session
export OPENAI_API_KEY="sk-xxxxxxxxxxxxxxxxxxxxxxxx"

# (Optional) Persist in ~/.zshrc or ~/.bash_profile
echo 'export OPENAI_API_KEY="sk-xxxxxxxxxxxxxxxxxxxxxxxx"' >> ~/.zshrc
source ~/.zshrc
```

#### Step 3: Run Local Security Audit
```bash
# Run heuristic & AI audit on local git diff
codex-security-linter --local

# Generate interactive HTML dashboard and SVG badge
codex-security-linter --local --html security-report.html --badge

# Enforce fail-on threshold in CI
codex-security-linter --local --fail-on HIGH
```

---

### 🐧 3. Linux (Ubuntu / Debian / Arch / Fedora)

#### Prerequisites
```bash
# Ubuntu / Debian
sudo apt update && sudo apt install -y python3 python3-pip python3-venv git

# Arch Linux
sudo pacman -S python python-pip git

# Fedora / RHEL
sudo dnf install -y python3 python3-pip git
```

#### Step 1: Clone Repository & Set Up Virtual Environment
```bash
# Clone repository
git clone https://github.com/knmt1219/codex-security-linter.git
cd codex-security-linter

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install package
pip install -e .
```

#### Step 2: Configure OpenAI API Key
```bash
# Set for current session
export OPENAI_API_KEY="sk-xxxxxxxxxxxxxxxxxxxxxxxx"

# (Optional) Persist in ~/.bashrc
echo 'export OPENAI_API_KEY="sk-xxxxxxxxxxxxxxxxxxxxxxxx"' >> ~/.bashrc
source ~/.bashrc
```

#### Step 3: Run Local Security Audit
```bash
# Run heuristic & AI audit on local git diff
codex-security-linter --local

# Export complete multi-format reports including HTML dashboard
codex-security-linter --local --html security-report.html --json findings.json --sarif results.sarif --badge

# Fail build if any CRITICAL or HIGH vulnerabilities are detected
codex-security-linter --local --fail-on HIGH
```

---

## 🎛️ CLI Options & Flags Reference

| Option / Flag | Type | Description |
| :--- | :---: | :--- |
| `--local` | Flag | Run security audit on local `git diff` instead of GitHub Action environment. |
| `--html <path>` | String | Export interactive HTML5 security dashboard report (e.g., `--html security-report.html`). |
| `--fail-on <level>` | Choice | Exit with code `1` if findings meet or exceed severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`). |
| `--strict` | Flag | Shorthand for `--fail-on HIGH` (exits with code `1` on `CRITICAL` or `HIGH` risks). |
| `--badge` | Flag | Automatically generate a vector SVG status badge (`security-badge.svg`). |
| `--json <path>` | String | Export structured scan results to a JSON file (e.g., `--json findings.json`). |
| `--sarif <path>` | String | Export scan results to OASIS SARIF 2.1.0 format (e.g., `--sarif results.sarif`). |

---

## 🪝 Pre-commit Hook Integration

Prevent insecure code and hardcoded secrets from ever being committed:

### Method 1: Auto-generate `.pre-commit-config.yaml`
```bash
codex-security-linter --install-hook
```

### Method 2: Manual Configuration
Add Codex Security Linter to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/knmt1219/codex-security-linter
    rev: v2.0.0
    hooks:
      - id: codex-security-linter
```

Then install the pre-commit hook:
```bash
pip install pre-commit
pre-commit install
```

---

## 🚀 GitHub Action Quick Setup

Automate security audits on every Pull Request.

### 1. Add Repository Secret
In your GitHub repository, navigate to **Settings > Secrets and variables > Actions** and add:
- `OPENAI_API_KEY`: Your OpenAI API key (`sk-...`).

### 2. Create Workflow File
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
  security-audit:
    name: Codex AI Security Linter
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Run Codex Security Linter
        uses: knmt1219/codex-security-linter@v2.0.0
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          openai-api-key: ${{ secrets.OPENAI_API_KEY }}
          model: 'gpt-4o-mini'
```

---

## ⚙️ Configuration (`.codex-security.yml`)

Customize scanning behavior by creating a `.codex-security.yml` file in your repository root:

```yaml
version: 2.0
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

## 🔒 Security & Privacy

- **Diff-Only Transmission**: Only modified code diffs (`git diff`) are audited; entire source trees are never uploaded.
- **Automatic Secret Masking**: Detected credentials and tokens are masked before being included in reports to prevent secondary exposure.
- **Enterprise Safe**: Compatible with OpenAI Enterprise data privacy policies.

---

## 📄 License

This project is open-source and licensed under the [MIT License](LICENSE) (Copyright © 2026 Hồ Minh Tuấn).
