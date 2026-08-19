# Threat Model & Security Scope

## Overview
**PR Security Linter** (`pr-security-linter`) is designed as a fast, lightweight, first-line security gate for Git pull requests, CI/CD pipelines, and local pre-commit hooks.

It operates primarily as a **static heuristic and syntax-aware (AST) analyzer**, with optional LLM-assisted code review.

---

## 1. Security Invariants & Guarantees

### A. Offline Operation & Zero Data Egress
- **Offline Guarantee:** When invoked with `--path`, `--local`, `--staged`, or without `OPENAI_API_KEY`, no network requests are ever initiated.
- **Zero Third-Party Code Transmission:** Source code is never sent to external AI providers or remote servers unless explicitly configured via `OPENAI_API_KEY`.

### B. Secret Protection & Output Masking
- All identified credentials, tokens, and secret patterns are automatically sanitized via `mask_sensitive_value()`.
- Unmasked plaintext credentials are never written to Markdown comments, SARIF outputs, HTML dashboards, or terminal standard streams.

### C. Inert Security Fixtures
- All test fixtures in `tests/` and `benchmarks/` contain synthetic, inert examples.
- The scanner operates strictly through read-only static analysis and AST inspection. It never executes or imports scanned code.

---

## 2. What PR Security Linter Protects Against

| Risk Category | Detection Mechanism | Examples |
| :--- | :--- | :--- |
| **Accidental Secret Leaks** | Deterministic Regex Signatures | AWS access keys, GitHub PATs, unencrypted private key headers, hardcoded credentials |
| **Malware & Backdoor Insertion** | Static Structural Signatures | Obfuscated PHP webshells (`base64_decode`, `gzinflate`), `/dev/tcp` interactive reverse shells, netcat listener backdoors, remote piped shell execution (`curl \| bash`) |
| **Python Dangerous Execution** | Python AST (`ast.NodeVisitor`) | Arbitrary code execution (`eval()`, `exec()`), OS command injection via `subprocess(shell=True)`, insecure object deserialization (`pickle.loads()`) |
| **Language High-Risk Sinks** | Context-Aware Sinks & Regex | React `dangerouslySetInnerHTML`, Go SQL injection (`fmt.Sprintf`), Java command execution & XMLDecoder RCE, PHP command execution & `unserialize`, C/C++ buffer overflows (`gets`, unbounded `strcpy`/`sprintf`) |
| **Suspicious Binaries** | File Path & Extension Filters | Introduction of compiled `.exe`, `.dll`, `.so`, `.elf`, `.vbs` files into repositories |

---

## 3. What PR Security Linter Does NOT Protect Against (Explicit Non-Goals)

PR Security Linter is intentionally designed as a fast, zero-dependency first-line linter. It is **not** a replacement for:
- **Full-Depth Data-Flow & Taint Analysis:** Does not perform inter-procedural taint analysis across arbitrary execution paths (use CodeQL or Semgrep for deep semantic analysis).
- **Dependency Vulnerability Scanning (SCA):** Does not parse package dependency trees against CVE databases (use Dependabot, Snyk, or Trivy).
- **Dynamic Application Security Testing (DAST):** Does not execute live web applications or inspect HTTP runtime endpoints (use OWASP ZAP or Burp Suite).
- **Container / OS Image Hardening:** Does not scan underlying Docker layers or Linux kernels for OS vulnerabilities.
- **Human Security Review & Penetration Testing:** Cannot replace manual code audits and professional security architecture reviews.

---

## 4. Minimum Recommended GitHub Action Permissions

When deploying PR Security Linter via GitHub Actions, configure the minimal required permissions:

```yaml
permissions:
  contents: read          # Read repository source code
  pull-requests: write   # Post security audit summary comment on PR
  security-events: write # Upload SARIF report to GitHub Security Code Scanning (optional)
```
