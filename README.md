# PR Security Linter 🛡️

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Release](https://img.shields.io/badge/Release-v0.9.0-blue.svg)](https://github.com/knmt1219/pr-security-linter/releases)
[![Python Version](https://img.shields.io/badge/Python-3.10%2B-green.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://hub.docker.com/)
[![GitHub Action](https://img.shields.io/badge/GitHub%20Action-PR%20Security%20Linter-purple.svg)](https://github.com/marketplace)

> **Note:** Formerly known as `codex-security-linter`. Renamed to avoid any confusion with OpenAI’s official Codex Security product.

**PR Security Linter** is a fast, lightweight security and secret scanner designed for **Pull Requests**, **Git pre-commit hooks**, and **local repositories**. It acts as a quick **first line of defense** to catch hardcoded credentials, suspicious malware/webshell patterns, and dangerous API usages before code gets merged.

---

## 🎯 What PR Security Linter Is (and Isn't)

- ✅ **A Fast First-Line Filter:** Runs in milliseconds locally or on CI without requiring heavy infrastructure or cloud dependencies.
- ✅ **Offline-First:** Audits local diffs or directory trees completely offline without sending code over the network.
- ✅ **Multi-Format Reporting:** Generates clean Markdown summary tables, interactive HTML dashboards, SARIF 2.1.0 for GitHub Security tab integration, JSON, and SVG status badges.
- ℹ️ **Optional AI Triage:** Can optionally invoke OpenAI models to summarize diffs and suggest GitHub code replacements if an API key is provided.
- ❌ **Not a Deep SAST:** This tool uses heuristic pattern matching and is **not** a full AST-based data-flow analyzer. It does **not** replace mature deep SAST tools like **Semgrep**, **CodeQL**, or **SonarQube**.

---

## 🔍 Supported Checks & Heuristics

| Category | Checks & Targets | Description |
| :--- | :--- | :--- |
| **Secrets & Keys** | AWS, GitHub tokens, Private keys, API keys, Passwords | Detects common plaintext secret assignments and masks values in reports (`AKIA...LE12`). |
| **Malware & Webshells** | Obfuscated PHP payloads, Reverse shells, Piped shells, Encoded PowerShell | Catches dangerous signatures like `eval(base64_decode(...))`, `/dev/tcp` shells, `nc -e`, `curl \| bash`, and suspicious executables (`.exe`, `.dll`, `.so`). |
| **Python** | `eval()`, `exec()`, `subprocess(shell=True)`, `pickle.loads()` | Flags arbitrary code execution and command injection risks. |
| **JavaScript / TypeScript** | `dangerouslySetInnerHTML` | Warns about unescaped React/DOM cross-site scripting (XSS) vectors. |
| **Go** | `fmt.Sprintf` in SQL queries, `unsafe.Pointer` | Flags string concatenation in SQL queries and unconstrained memory operations. |
| **Rust** | `unsafe { ... }` blocks | Highlights memory safety boundary escapes in Rust code. |
| **Java** | `Runtime.exec`, `ProcessBuilder`, `XMLDecoder`, Concatenated SQL | Flags command execution, insecure deserialization, and SQL concatenation. |
| **PHP** | `system()`, `shell_exec()`, `passthru()`, `unserialize()` | Catches OS command execution and object injection risks. |
| **C / C++** | `gets()`, `strcpy()`, `strcat()`, unbounded `sprintf()` | Flags legacy unsafe functions prone to buffer overflows. |

> **Smart Comment Filtering:** Language vulnerability patterns automatically ignore code comments (`#`, `//`, `/* */`, `--`) and strip inline comments to minimize false positives.

---

## 📦 Installation & Setup

### 1. Python Package (`pip`)

```bash
# Install from local clone or source
pip install -e .

# With optional AI triage support
pip install -e .[ai]
```

### 2. Pre-commit Hook

Add PR Security Linter to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/knmt1219/pr-security-linter
    rev: v0.9.0
    hooks:
      - id: pr-security-linter
```

Or scaffold the configuration automatically:
```bash
pr-security-linter --install-hook
```

---

## 🚀 Usage

### Local CLI

```bash
# Scan a directory or single file offline
pr-security-linter --path ./src

# Scan uncommitted changes in current Git repository
pr-security-linter --local

# Scan staged changes before committing
pr-security-linter --staged

# Export interactive HTML dashboard and SARIF
pr-security-linter --path ./src --html report.html --sarif results.sarif

# Enforce fail-on threshold (exit code 1 on HIGH or CRITICAL findings)
pr-security-linter --path ./src --fail-on HIGH
```

### GitHub Actions Integration

Create `.github/workflows/security.yml`:

```yaml
name: Security Audit

on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read
  pull-requests: write

jobs:
  security-scan:
    name: PR Security Linter
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Run PR Security Linter
        uses: knmt1219/pr-security-linter@v0.9.0
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          fail-on: 'HIGH'
          html: 'security-report.html'
          sarif: 'results.sarif'
```

### Docker Container

```bash
# Build Docker image
docker build -t pr-security-linter:v0.9.0 .

# Audit repository mounted in container
docker run --rm -v "$(pwd):/app/repo" -w /app/repo pr-security-linter:v0.9.0 --path . --fail-on HIGH
```

---

## 🎛️ CLI Reference

| Option | Type | Description |
| :--- | :---: | :--- |
| `--path <path>` | String | Scan a local file or recursive directory offline without git. |
| `--local` | Flag | Scan uncommitted changes in local git repository (`git diff`). |
| `--staged` | Flag | Scan staged git changes (`git diff --cached`). |
| `--config <path>` | String | Path to custom YAML configuration file (default: `.pr-security.yml`). |
| `--fail-on <level>` | Choice | Exit code 1 if findings meet or exceed severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`). |
| `--strict` | Flag | Shorthand for `--fail-on HIGH`. |
| `--html <path>` | String | Export interactive Dark Mode HTML report (e.g. `report.html`). |
| `--sarif <path>` | String | Export scan results in OASIS SARIF 2.1.0 format. |
| `--json <path>` | String | Export findings as JSON file. |
| `--badge` | Flag | Generate SVG status badge (`security-badge.svg`). |
| `--quiet` | Flag | Suppress informational logs, only printing when issues are detected. |
| `--install-hook` | Flag | Auto-generate `.pre-commit-config.yaml`. |
| `--version` | Flag | Show program version and exit. |

---

## ⚙️ Configuration (`.pr-security.yml`)

Create a `.pr-security.yml` file in your repository root:

```yaml
version: 1.0

settings:
  model: "gpt-4o-mini"
  severity_threshold: "HIGH"

ignore_paths:
  - "tests/*"
  - "docs/*"
  - "*.lock"
  - "dist/*"
  - "build/*"

rules:
  secret_leak_detection: true
  malware_and_webshells: true
  injection_flaws: true
  deserialization_risks: true
  memory_safety_checks: true
```

---

## 📊 Comparison with Other Security Tools

| Feature / Capability | **PR Security Linter** | **Gitleaks / Trufflehog** | **Semgrep / CodeQL** |
| :--- | :---: | :---: | :---: |
| **Primary Focus** | PR Diff & Fast Linter | Dedicated Secret Detection | Deep Semantic SAST & AST |
| **Execution Speed** | Sub-second (< 100ms) | Fast | Slower (seconds to minutes) |
| **Setup Complexity** | Zero-config / Single binary | Minimal | Moderate to High |
| **Secret Scanning** | Basic Regex Heuristics | Advanced Entropy & Validators | Via Rulesets |
| **Malware / Webshell Rules** | Built-in Heuristics | No | Custom Rules |
| **AST / Data Flow Analysis** | No | No | Yes |
| **Interactive HTML Reports** | Built-in | No (CLI/JSON) | Cloud or SARIF viewers |

---

## ⚠️ Limitations & Honest Disclosures

1. **Regex-Based Detection:** Heuristic checks match text patterns. While comments and common ignore rules are applied, heuristics can miss obfuscated code or flag benign usages.
2. **Not a Data-Flow Engine:** PR Security Linter does not construct control flow graphs (CFGs) or track tainted variables from sources to sinks.
3. **Defense in Depth:** We strongly recommend using PR Security Linter alongside dedicated secret management tools and deep semantic SAST analyzers (such as CodeQL or Semgrep).

---

## 🤝 Contributing

We welcome contributions! Please review our [Contributing Guide](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md).

---

## 📄 License

This project is licensed under the [MIT License](LICENSE) (Copyright © 2026 Hồ Minh Tuấn).
