# PR Security Linter 🛡️

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Release](https://img.shields.io/badge/Release-v0.9.0-blue.svg)](https://github.com/knmt1219/pr-security-linter/releases)
[![Python Version](https://img.shields.io/badge/Python-3.10%2B-green.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://hub.docker.com/)
[![GitHub Action](https://img.shields.io/badge/GitHub%20Action-PR%20Security%20Linter-purple.svg)](https://github.com/marketplace)

> **Notice:** Formerly known as `codex-security-linter`. Renamed to `pr-security-linter` to avoid any confusion with OpenAI’s official Codex Security offerings. This is an independent open-source project and is not affiliated with, endorsed by, or maintained by OpenAI.

**PR Security Linter** is a fast, lightweight security and secret analysis engine designed for **Pull Requests**, **Git pre-commit hooks**, and **offline local repositories**. It serves as an instant **first line of defense** to catch hardcoded credentials, suspicious malware/webshell patterns, and dangerous API usages before code gets committed or merged.

---

## 🎯 What PR Security Linter Is (and Isn't)

- ✅ **Fast Multi-Layer First-Line Filter:** Runs deterministically in sub-second execution (< 50ms) without requiring heavy server infrastructure or cloud dependencies.
- ✅ **Python AST Analysis:** Standard library AST-aware detection for Python distinguishing dynamic code execution from constant safe literals and `ast.literal_eval()`.
- ✅ **Offline-First & Privacy-Focused:** Audits local file trees and git diffs completely offline. Zero code is sent across the network.
- ✅ **Context-Aware Source Processing:** Strips inline comments (`#`, `//`, `/* */`, `--`) and excludes documentation strings to reduce false alarms.
- ✅ **Multi-Format Reporting:** Generates Markdown summary tables, interactive Dark Mode HTML5 dashboards, OASIS SARIF 2.1.0 (with per-rule CWE mappings for GitHub Code Scanning), JSON, and SVG status badges.
- ℹ️ **Optional AI Triage:** Can optionally invoke OpenAI models (`gpt-4o-mini`) for advisory remediation summaries when `OPENAI_API_KEY` is explicitly configured.
- ❌ **Not a Full Semantic SAST:** While Python uses AST analysis and multi-language rules use lexical context filtering, this tool does **not** perform whole-program inter-procedural taint/data-flow analysis. It does **not** replace deep SAST platforms like **Semgrep** or **CodeQL**.

---

## 🏗️ Architecture

```
Input Sources (Local Path / Git Diff / Staged Diff / PR Webhook)
       │
       ▼
Source Filtering & Ignore Engine (*.min.js, *.lock, dist/, vendor/)
       │
       ▼
Context Extraction & Multi-Layer Analyzers
 ├── Python AST Analyzer (ast.NodeVisitor)
 ├── Deterministic Regex Signatures (Secrets, Malware, Language Sinks)
 └── Optional AI Review Provider (OpenAI Triage)
       │
       ▼
Finding Normalization & Deduplication (Stable Rule IDs & CWEs)
       │
       ▼
Reporting Layer (Console Matrix, SARIF 2.1.0, HTML5 Dashboard, Badges)
```

See [`docs/architecture.md`](docs/architecture.md) for detailed pipeline specifications and [`THREAT_MODEL.md`](THREAT_MODEL.md) for security boundaries.

---

## 🔍 Supported Checks & Heuristics

| Category | Rule ID Prefix | Checks & Targets | Detection Mechanism |
| :--- | :---: | :--- | :--- |
| **Secrets & Keys** | `SEC-*` | AWS access keys, GitHub PATs, unencrypted private keys, API tokens, passwords | Deterministic Regex + Automatic Value Masking |
| **Malware & Webshells** | `MAL-*` | Obfuscated PHP webshells, `/dev/tcp` reverse shells, netcat listeners, piped curl shells (`curl \| bash`), encoded PowerShell | Structural Regex Signatures |
| **Python** | `PY-*` | Dynamic `eval()`/`exec()`, `subprocess(shell=True)`, `pickle.loads()` | **Python AST Analyzer** (standard library `ast`) |
| **JavaScript / TypeScript** | `JS-*` | React `dangerouslySetInnerHTML` | Context-aware Sink Filter |
| **Go** | `GO-*` | SQL injection via `fmt.Sprintf`, `unsafe.Pointer` memory manipulation | Context-aware Sink Filter |
| **Rust** | `RUST-*` | `unsafe { ... }` blocks escaping borrow checker guarantees | Context-aware Sink Filter |
| **Java** | `JAVA-*` | `Runtime.exec`, `ProcessBuilder`, `XMLDecoder` RCE, concatenated SQL queries | Context-aware Sink Filter |
| **PHP** | `PHP-*` | `system()`, `shell_exec()`, `passthru()`, `unserialize()` object injection | Context-aware Sink Filter |
| **C / C++** | `CPP-*` | Legacy unsafe functions (`gets()`, unbounded `strcpy()`, `strcat()`, `sprintf()`) | Context-aware Sink Filter |

---

## 📦 Installation & Setup

### 1. Python Package (`pip`)

```bash
# Clone the repository
git clone https://github.com/knmt1219/pr-security-linter.git
cd pr-security-linter

# Install in editable mode
pip install -e .

# Install with optional AI triage dependencies
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

Both `pr-security-linter` and `codex-security-linter` commands are supported:

```bash
# Scan a directory or single file offline
pr-security-linter --path ./src

# Scan uncommitted changes in current Git repository
pr-security-linter --local

# Scan staged changes before committing
pr-security-linter --staged

# Export interactive HTML dashboard and SARIF 2.1.0
pr-security-linter --path ./src --html report.html --sarif results.sarif

# Enforce fail-on threshold (exit code 1 on HIGH or CRITICAL findings)
pr-security-linter --path ./src --fail-on HIGH

# Run the benchmark & regression evaluation suite
pr-security-linter benchmark
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
  security-events: write

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

## 📊 Benchmark & Evaluation Suite

PR Security Linter includes a reproducible benchmark corpus (`benchmarks/`) measuring real detection performance:

```bash
pr-security-linter benchmark
```

```
================================================================================
 PR SECURITY LINTER BENCHMARK & REGRESSION EVALUATION
================================================================================
Fixture                          | Lines  | Exp  | Det  | TP  | FP  | FN  | Time (ms)
--------------------------------------------------------------------------------
secrets/sample_secrets.py        | 4      | 3    | 3    | 3   | 0   | 0   | 1.70    
python/sample_vulns.py           | 10     | 3    | 3    | 3   | 0   | 0   | 0.82    
javascript/sample_xss.jsx        | 6      | 1    | 1    | 1   | 0   | 0   | 0.60    
java/sample_vulns.java           | 11     | 3    | 3    | 3   | 0   | 0   | 0.78    
php/sample_vulns.php             | 6      | 2    | 2    | 2   | 0   | 0   | 0.66    
go/sample_vulns.go               | 14     | 2    | 2    | 2   | 0   | 0   | 0.88    
rust/sample_vulns.rs             | 5      | 1    | 1    | 1   | 0   | 0   | 1.98    
c/sample_vulns.c                 | 9      | 3    | 3    | 3   | 0   | 0   | 1.22    
safe/safe_examples.py            | 23     | 0    | 0    | 0   | 0   | 0   | 1.56    
safe/safe_examples.js            | 8      | 0    | 0    | 0   | 0   | 0   | 1.03    
================================================================================
SUMMARY METRICS:
  * Total Fixtures Scanned : 10
  * Total Lines Scanned    : 96
  * True Positives (TP)    : 18
  * False Positives (FP)   : 0
  * False Negatives (FN)   : 0
  * Precision              : 100.00%
  * Recall                 : 100.00%
  * F1 Score               : 100.00%
  * Total Execution Time   : 12.10ms
================================================================================
```

---

## 🎛️ CLI Reference

| Option | Type | Description |
| :--- | :---: | :--- |
| `--path <path>` | String | Scan a local file or recursive directory offline without git. |
| `--local` | Flag | Scan uncommitted changes in local git repository (`git diff`). |
| `--staged` | Flag | Scan staged git changes (`git diff --cached`). |
| `--benchmark` | Flag | Run evaluation benchmark against verified fixture corpus. |
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
| **Execution Speed** | Sub-second (< 50ms) | Fast | Slower (seconds to minutes) |
| **Setup Complexity** | Zero-config / Single binary | Minimal | Moderate to High |
| **Secret Scanning** | Regex Heuristics + Masking | Advanced Entropy & Validators | Via Rulesets |
| **Malware / Webshell Rules** | Built-in Signatures | No | Custom Rules |
| **Python AST Analysis** | Built-in (`ast.NodeVisitor`) | No | Yes |
| **Interactive HTML Reports** | Built-in | No (CLI/JSON) | Cloud or SARIF viewers |

---

## ⚠️ Limitations & Honest Disclosures

1. **First-Line Heuristic & Syntax Scope:** Language checks outside of Python AST rely on lexical sink pattern matching and comment filtering. They may flag safe dynamic patterns or miss deeply obfuscated payloads.
2. **Not a Data-Flow Engine:** PR Security Linter does not construct control flow graphs (CFGs) or perform whole-program taint analysis across multiple functions or modules.
3. **Defense in Depth:** PR Security Linter is designed to complement, rather than replace, dedicated secret vaults and deep semantic SAST analyzers (such as CodeQL or Semgrep).

---

## 🤝 Contributing & Security

- **Contributing:** Please review our [Contributing Guide](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md).
- **Security Disclosures:** For responsible disclosure of security vulnerabilities in this tool, see [SECURITY.md](SECURITY.md).
- **Threat Model:** Consult [THREAT_MODEL.md](THREAT_MODEL.md) for data flow and trust assumptions.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE) (Copyright © 2026 Hồ Minh Tuấn).
