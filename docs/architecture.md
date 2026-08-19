# PR Security Linter Architecture

## Architecture Overview

PR Security Linter provides a modular, multi-layer security analysis pipeline designed for sub-second execution in pre-commit hooks, CLI workflows, and GitHub Actions.

```
+-------------------------------------------------------------+
|                     Input Sources                           |
|  +--------------------+  +---------------+  +------------+  |
|  | Local / Offline    |  | Git Local /   |  | GitHub PR  |  |
|  | Path Scanning      |  | Staged Diff   |  | Webhook    |  |
|  +--------------------+  +---------------+  +------------+  |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                     Source Filtering                        |
|  * Ignore patterns (*.min.js, *.lock, node_modules/, dist/) |
|  * Diff chunking optimizer (prioritize high-risk changes)   |
|  * Inline comment & docstring stripping                     |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                    Context Extraction                       |
|                                                             |
|  +---------------------+  +------------------------------+  |
|  | Python AST Analyzer |  | Context-Aware Regex Rules    |  |
|  | (ast.NodeVisitor)   |  | (Secrets, Malware, Sinks)    |  |
|  +---------------------+  +------------------------------+  |
|                            \                                |
|                             +----------------------------+  |
|                             | Optional AI Review Provider|  |
|                             | (OpenAI / LLM Triage)      |  |
|                             +----------------------------+  |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|               Finding Normalization & Deduplication         |
|  * Merges overlapping AST & heuristic findings              |
|  * Preserves exact file, line, and column coordinates        |
|  * Evaluates confidence & severity score thresholds         |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                     Reporting Layer                         |
|  +----------------+  +---------------+  +----------------+  |
|  | Terminal Table |  | SARIF 2.1.0   |  | HTML5 DarkMode |  |
|  +----------------+  +---------------+  +----------------+  |
|  | PR Comments    |  | JSON Findings |  | SVG Badges     |  |
|  +----------------+  +---------------+  +----------------+  |
+-------------------------------------------------------------+
```

---

## Component Architecture

### 1. Data Model (`pr_security_linter/models.py`)
- `Finding`: Strongly-typed container encapsulating `rule_id`, `title`, `description`, `severity`, `confidence`, `location`, `snippet`, `analyzer`, `cwe`, and `risk_score`.
- `Location`: Tracks exact `file`, `line`, and `column` numbers.
- `Severity`: Enum with integer rankings (`CRITICAL=4`, `HIGH=3`, `MEDIUM=2`, `LOW=1`, `INFO=0`).

### 2. Rule Registry (`pr_security_linter/rules/`)
- `base.py`: Defines atomic `Rule` abstractions with pre-compiled regex patterns, remediation guidance, and CWE metadata.
- `registry.py`: Catalog of deterministic rules categorized under:
  - `SEC-*`: Credential and private key leaks.
  - `MAL-*`: Webshell, reverse shell, and dropper payloads.
  - `PY-*`, `JS-*`, `GO-*`, `RUST-*`, `JAVA-*`, `PHP-*`, `CPP-*`: Dangerous sinks and memory flaws.

### 3. Syntax Analyzers (`pr_security_linter/analyzers/`)
- `python_ast.py`: Python AST walker using standard library `ast` to detect dynamic `eval()`/`exec()`, `subprocess(shell=True)`, and `pickle.loads()`, while safely ignoring constant calls and `ast.literal_eval()`.
- `ai.py`: Optional advisory triage provider that transmits strictly scoped diff contexts when `OPENAI_API_KEY` is provided.

### 4. Reporters (`pr_security_linter/reporters.py`)
- `sarif.py`: Generates OASIS SARIF 2.1.0 with individual driver rule definitions, CWE references, and precision line locations for GitHub Code Scanning integration.
- `html.py`: Generates an interactive, zero-dependency Dark Mode HTML5 dashboard with real-time severity filtering and search.
- `badge.py`: Generates SVG status badges for repository READMEs.
