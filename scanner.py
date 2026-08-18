import os
import sys
import re
import json
import time
import argparse
import html
from typing import Any, Dict, List, Optional
import requests

VERSION = "2.8.0"

COMMON_SECRET_PATTERNS = [
    (r'(?i)(?:aws_access_key_id|aws_secret_access_key|aws_session_token)\s*=\s*["\']?([A-Za-z0-9/+=]{20,})', "AWS Credential Leak", "10.0"),
    (r'(?i)(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}', "GitHub Personal Access Token", "9.5"),
    (r'-----BEGIN\s+([A-Z\s]+)?PRIVATE\s+KEY-----', "Exposed Private Key", "10.0"),
    (r'(?i)(?:api[_-]?key|secret[_-]?key|auth[_-]?token)\s*=\s*["\']([a-zA-Z0-9_\-]{16,})["\']', "Potential Hardcoded API Key/Token", "8.5"),
    (r'(?i)password\s*=\s*["\']([^"\']{4,})["\']', "Hardcoded Plaintext Password", "8.0"),
]

MALWARE_PATTERNS = [
    (r'(?i)(?:eval|assert|preg_replace)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(', "Obfuscated Webshell Payload (PHP Obfuscation)", "10.0"),
    (r'(?i)(?:/dev/tcp/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/\d+|bash\s+-i\s+>&?\s*/dev/tcp)', "Reverse Shell Connection (/dev/tcp)", "10.0"),
    (r'(?i)(?:nc|netcat|ncat)\s+(?:-[a-zA-Z]*e\s+|.*-c\s+)(?:/bin/sh|/bin/bash|cmd\.exe|powershell)', "Netcat Backdoor / Reverse Shell", "10.0"),
    (r'(?i)(?:curl|wget)\s+[^|;\n]+\|\s*(?:ba)?sh\b', "Dangerous Remote Execution via Piped Shell (curl/wget | sh)", "9.8"),
    (r'(?i)powershell(?:\.exe)?\s+.*-(?:enc|encodedcommand|e)\s+[A-Za-z0-9+/=]{8,}', "Encoded PowerShell Dropper / Payload", "9.8"),
]

LANGUAGE_VULN_PATTERNS = [
    # Python
    (r'(?i)(?<!\.)\b(?:eval|exec)\s*\(', "Dangerous Dynamic Code Execution (eval/exec)", "9.0"),
    (r'(?i)subprocess\.(?:Popen|call|run)\s*\(.*shell\s*=\s*True', "Command Injection Risk (shell=True)", "9.5"),
    (r'(?i)pickle\.loads\s*\(', "Insecure Deserialization (pickle.loads)", "9.8"),

    # JavaScript / TypeScript / React
    (r'(?i)dangerouslySetInnerHTML', "Cross-Site Scripting (XSS) via dangerouslySetInnerHTML", "7.5"),

    # Go
    (r'(?i)(?:db\.Query|db\.Exec|QueryRow)\s*\(\s*fmt\.Sprintf', "Go SQL Injection Risk (fmt.Sprintf)", "9.0"),
    (r'(?i)unsafe\.Pointer\s*\(', "Dangerous Go Memory Manipulation (unsafe.Pointer)", "7.0"),

    # Rust
    (r'\bunsafe\s*\{', "Unsafe Rust Code Block (Memory Safety Risk)", "7.2"),

    # Java
    (r'(?i)(?:Runtime(?:\.getRuntime\(\))?\.exec|ProcessBuilder)\s*\(', "Java Command Execution Risk (Runtime.exec/ProcessBuilder)", "9.5"),
    (r'(?i)XMLDecoder\s*\(', "Java Insecure Deserialization (XMLDecoder RCE)", "9.8"),
    (r'(?i)(?:executeQuery|executeUpdate)\s*\(\s*["\'].*\+\s*[a-zA-Z0-9_]+', "Java SQL Injection via String Concatenation", "9.0"),

    # PHP
    (r'(?i)(?:system|shell_exec|passthru|proc_open)\s*\(', "PHP Command Execution Vulnerability (system/shell_exec)", "9.5"),
    (r'(?i)unserialize\s*\(', "PHP Insecure Object Deserialization (unserialize)", "9.0"),

    # C / C++
    (r'\bgets\s*\(', "C/C++ Highly Dangerous Function (gets - Buffer Overflow)", "9.8"),
    (r'\b(?:strcpy|strcat)\s*\(', "C/C++ Insecure Unbounded String Copy (strcpy/strcat Buffer Overflow)", "8.5"),
    (r'(?<![a-zA-Z0-9_])sprintf\s*\(', "C/C++ Format String / Buffer Overflow Risk (sprintf)", "8.0"),
]

SUSPICIOUS_EXECUTABLE_EXTS = (
    '.exe', '.dll', '.so', '.elf', '.vbs', '.bat', '.cmd', '.scr', '.dylib'
)

DEFAULT_IGNORE_PATTERNS = [
    r'(?i)\.min\.(?:js|css)$',
    r'(?i)\.bundle\.js$',
    r'(?i)^(?:dist|build|vendor|node_modules)/',
    r'(?i)/(?:dist|build|vendor|node_modules)/',
    r'(?i)\.lock$',
    r'(?i)package-lock\.json$',
    r'(?i)yarn\.lock$',
]

SEVERITY_RANKS = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

def mask_sensitive_value(line: str) -> str:
    def mask_match(m):
        val = m.group(0)
        if len(val) > 8:
            return val[:4] + "..." + val[-4:]
        return val
    return re.sub(r'[A-Za-z0-9_\-]{12,}', mask_match, line)

def is_ignored_file(file_path: str, custom_patterns: Optional[List[str]] = None) -> bool:
    """Check if file should be ignored from security audit (minified, bundled, build artifacts)."""
    clean_path = file_path.replace("\\", "/").strip()
    if clean_path.startswith("b/"):
        clean_path = clean_path[2:]

    patterns = list(DEFAULT_IGNORE_PATTERNS)
    if custom_patterns:
        for p in custom_patterns:
            p_regex = p.replace(".", r"\.").replace("*", ".*")
            patterns.append(f"(?i){p_regex}")

    for pattern in patterns:
        if re.search(pattern, clean_path):
            return True
    return False

def chunk_diff_smart(diff_text: str, max_chars: int = 12000) -> str:
    """Smartly prioritize security-critical diff hunks when diff exceeds token budget."""
    if len(diff_text) <= max_chars:
        return diff_text

    file_diffs = re.split(r'(?=diff --git )', diff_text)
    prioritized_hunks: List[str] = []
    other_hunks: List[str] = []

    high_risk_exts = ('.py', '.go', '.rs', '.js', '.ts', '.java', '.php', '.c', '.cpp', '.h', '.hpp', '.rb', '.sh', '.yml', '.yaml')

    for chunk in file_diffs:
        chunk = chunk.strip()
        if not chunk:
            continue
        first_line = chunk.splitlines()[0] if chunk.splitlines() else ""
        is_high_risk = any(first_line.endswith(ext) or ext in first_line for ext in high_risk_exts)
        has_suspicious_patterns = any(re.search(p, chunk) for p, _, _ in COMMON_SECRET_PATTERNS + MALWARE_PATTERNS + LANGUAGE_VULN_PATTERNS)

        if is_high_risk or has_suspicious_patterns:
            prioritized_hunks.append(chunk)
        else:
            other_hunks.append(chunk)

    selected: List[str] = []
    current_length = 0

    for h in prioritized_hunks + other_hunks:
        if current_length + len(h) <= max_chars:
            selected.append(h)
            current_length += len(h)
        else:
            remaining = max_chars - current_length
            if remaining > 200:
                selected.append(h[:remaining] + "\n... [diff truncated for length]")
            break

    return "\n\n".join(selected) if selected else diff_text[:max_chars]

def install_pre_commit_hook():
    """Scaffold a .pre-commit-config.yaml configured for Codex Security Linter."""
    config_path = ".pre-commit-config.yaml"
    hook_config = f"""repos:
  - repo: https://github.com/knmt1219/codex-security-linter
    rev: v{VERSION}
    hooks:
      - id: codex-security-linter
"""
    if os.path.exists(config_path):
        print(f"File '{config_path}' already exists. Please verify hook configuration.")
    else:
        with open(config_path, "w", encoding="utf-8") as f:
            f.write(hook_config)
        print(f"✅ Generated '{config_path}' configured for Codex Security Linter v{VERSION}.")
    print("Next step: Run `pre-commit install` to activate the hook locally.")

def parse_simple_yaml(text: str) -> Dict[str, Any]:
    """Lightweight fallback YAML parser for configuration files without external dependencies."""
    config: Dict[str, Any] = {}
    current_section: Optional[str] = None

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if not raw_line.startswith(" ") and line.endswith(":"):
            current_section = line[:-1].strip()
            config[current_section] = {}
            continue

        if current_section and raw_line.startswith("  ") and ":" in line:
            parts = line.split(":", 1)
            k = parts[0].strip()
            v = parts[1].strip().strip('"').strip("'")
            if isinstance(config[current_section], dict):
                config[current_section][k] = v
            continue

        if current_section and line.startswith("- "):
            item = line[2:].strip().strip('"').strip("'")
            if not isinstance(config[current_section], list):
                config[current_section] = []
            config[current_section].append(item)
            continue

        if ":" in line:
            parts = line.split(":", 1)
            k = parts[0].strip()
            v = parts[1].strip().strip('"').strip("'")
            config[k] = v
            current_section = None

    return config

def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load configuration from specified path or default .codex-security.yml."""
    target_path = config_path or ".codex-security.yml"
    if not os.path.exists(target_path):
        return {}

    try:
        with open(target_path, "r", encoding="utf-8") as f:
            content = f.read()

        try:
            import yaml  # type: ignore
            data = yaml.safe_load(content)
            if isinstance(data, dict):
                return data
        except ImportError:
            pass

        return parse_simple_yaml(content)
    except Exception as e:
        print(f"Warning: Failed to load config from '{target_path}': {e}", file=sys.stderr)
        return {}

def set_github_output(name: str, value: Any):
    """Write an output parameter to $GITHUB_OUTPUT file in GitHub Actions."""
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        try:
            with open(output_file, "a", encoding="utf-8") as f:
                f.write(f"{name}={value}\n")
        except Exception as e:
            print(f"Warning: Failed to write output to GITHUB_OUTPUT: {e}", file=sys.stderr)

def write_github_action_outputs(findings: list, sarif_path: str = "", html_path: str = ""):
    """Record GitHub Action step outputs for subsequent workflow steps."""
    total_count = len(findings)
    has_critical = any(f.get("severity") == "CRITICAL" for f in findings)
    set_github_output("findings-count", str(total_count))
    set_github_output("has-critical", "true" if has_critical else "false")
    set_github_output("sarif-path", sarif_path or "")
    set_github_output("html-report-path", html_path or "")

def get_pr_diff(repo_full_name: str, pr_number: int, github_token: str) -> str:
    url = f"https://api.github.com/repos/{repo_full_name}/pulls/{pr_number}"
    headers = {"Authorization": f"Bearer {github_token}", "Accept": "application/vnd.github.v3.diff"}
    res = requests.get(url, headers=headers, timeout=30)
    return res.text if res.status_code == 200 else ""

def post_comment(repo_full_name: str, pr_number: int, github_token: str, body: str) -> bool:
    url = f"https://api.github.com/repos/{repo_full_name}/issues/{pr_number}/comments"
    headers = {"Authorization": f"Bearer {github_token}", "Accept": "application/vnd.github.v3+json"}
    res = requests.post(url, headers=headers, json={"body": body}, timeout=30)
    return res.status_code == 201

def heuristic_scan_structured(diff_text: str, custom_ignore_paths: Optional[List[str]] = None) -> list:
    findings = []
    current_file = ""
    ignoring_current_file = False
    reported_suspicious_files = set()

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            parts = line.split()
            if len(parts) >= 4:
                current_file = parts[3]
                clean_name = current_file.lstrip("b/").strip()
                ignoring_current_file = is_ignored_file(current_file, custom_ignore_paths)
                
                # Check for suspicious binary or script extensions added
                if not ignoring_current_file and clean_name not in reported_suspicious_files:
                    if any(clean_name.lower().endswith(ext) for ext in SUSPICIOUS_EXECUTABLE_EXTS):
                        reported_suspicious_files.add(clean_name)
                        findings.append({
                            "severity": "CRITICAL",
                            "type": "Suspicious Executable Binary / Script Added",
                            "score": "9.5",
                            "confidence": "95%",
                            "file": clean_name,
                            "snippet": f"Executable artifact detected: {clean_name}"
                        })
            continue
        elif line.startswith("+++ "):
            current_file = line[4:].strip()
            clean_name = current_file.lstrip("b/").strip()
            ignoring_current_file = is_ignored_file(current_file, custom_ignore_paths)
            if not ignoring_current_file and clean_name not in reported_suspicious_files:
                if any(clean_name.lower().endswith(ext) for ext in SUSPICIOUS_EXECUTABLE_EXTS):
                    reported_suspicious_files.add(clean_name)
                    findings.append({
                        "severity": "CRITICAL",
                        "type": "Suspicious Executable Binary / Script Added",
                        "score": "9.5",
                        "confidence": "95%",
                        "file": clean_name,
                        "snippet": f"Executable artifact detected: {clean_name}"
                    })
            continue

        if ignoring_current_file:
            continue

        if line.startswith('+') and not line.startswith('+++'):
            clean_line = line[1:].strip()
            masked_line = mask_sensitive_value(clean_line)

            for pattern, desc, score in COMMON_SECRET_PATTERNS:
                if re.search(pattern, line):
                    findings.append({
                        "severity": "CRITICAL",
                        "type": desc,
                        "score": score,
                        "confidence": "99%",
                        "file": current_file.lstrip("b/"),
                        "snippet": masked_line[:80]
                    })

            matched_malware = False
            for pattern, desc, score in MALWARE_PATTERNS:
                if re.search(pattern, line):
                    matched_malware = True
                    findings.append({
                        "severity": "CRITICAL",
                        "type": desc,
                        "score": score,
                        "confidence": "99%",
                        "file": current_file.lstrip("b/"),
                        "snippet": masked_line[:80]
                    })

            if not matched_malware:
                for pattern, desc, score in LANGUAGE_VULN_PATTERNS:
                    if re.search(pattern, line):
                        findings.append({
                            "severity": "HIGH",
                            "type": desc,
                            "score": score,
                            "confidence": "95%",
                            "file": current_file.lstrip("b/"),
                            "snippet": masked_line[:80]
                        })
    return findings

def count_scanned_lines(diff_text: str) -> int:
    """Count total added code lines analyzed from diff."""
    return sum(1 for line in diff_text.splitlines() if line.startswith('+') and not line.startswith('+++'))

def build_markdown_summary_table(findings: list, lines_scanned: int = 0, duration_ms: float = 0.0) -> str:
    metrics_line = f"⚡ **Performance:** Scanned `{lines_scanned}` lines in `{duration_ms:.2f}ms` | Findings: `{len(findings)}`\n\n"
    if not findings:
        return metrics_line + "✅ **Security Status:** No vulnerabilities or secret leaks detected."
    
    table = metrics_line
    table += "| Severity | Vulnerability Type | CVSS | Confidence | Code Snippet |\n"
    table += "| :--- | :--- | :---: | :---: | :--- |\n"
    for f in findings:
        badge = "🔴 `CRITICAL`" if f["severity"] == "CRITICAL" else "🟠 `HIGH`"
        table += f"| {badge} | {f['type']} | **{f['score']}** | {f['confidence']} | `{f['snippet']}` |\n"
    return table

def generate_svg_badge(has_issues: bool, output_path: str = "security-badge.svg"):
    color = "#e05d44" if has_issues else "#4c1"
    status_text = "issues found" if has_issues else "passed"
    svg_content = f"""<svg xmlns="http://www.w3.org/2000/svg" width="140" height="20">
  <linearGradient id="b" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
  <mask id="a"><rect width="140" height="20" rx="3" fill="#fff"/></mask>
  <g mask="url(#a)">
    <path fill="#555" d="M0 0h90v20H0z"/>
    <path fill="{color}" d="M90 0h50v20H90z"/>
    <path fill="url(#b)" d="M0 0h140v20H0z"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="45" y="15" fill="#010101" fill-opacity=".3">security audit</text>
    <text x="45" y="14">security audit</text>
    <text x="115" y="15" fill="#010101" fill-opacity=".3">{status_text}</text>
    <text x="115" y="14">{status_text}</text>
  </g>
</svg>"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(svg_content)
    print(f"SVG security badge generated at: {output_path}")

def export_html(findings: list, output_path: str = "security-report.html", lines_scanned: int = 0, duration_ms: float = 0.0):
    critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
    total_count = len(findings)
    status_text = "ACTION REQUIRED" if total_count > 0 else "PASSED"
    status_color = "#ef4444" if total_count > 0 else "#10b981"

    table_rows = ""
    if findings:
        for f in findings:
            sev = f.get("severity", "LOW").upper()
            badge_class = "badge-critical" if sev == "CRITICAL" else ("badge-high" if sev == "HIGH" else "badge-medium")
            safe_type = html.escape(str(f.get("type", "")))
            safe_score = html.escape(str(f.get("score", "N/A")))
            safe_conf = html.escape(str(f.get("confidence", "N/A")))
            safe_snip = html.escape(str(f.get("snippet", "")))
            safe_file = html.escape(str(f.get("file", "diff")))
            table_rows += f"""
            <tr data-severity="{sev}">
                <td><span class="badge {badge_class}">{sev}</span></td>
                <td><strong>{safe_type}</strong><br><small class="file-path">📁 {safe_file}</small></td>
                <td><span class="cvss-score">{safe_score}</span></td>
                <td><span class="conf-badge">{safe_conf}</span></td>
                <td><code>{safe_snip}</code></td>
            </tr>
            """
    else:
        table_rows = """
        <tr id="empty-row">
            <td colspan="5" style="text-align: center; color: #94a3b8; padding: 3rem;">
                🎉 <strong>Clean Diff:</strong> No vulnerabilities, malware, or sensitive secret leaks detected!
            </td>
        </tr>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Codex Security Linter - Interactive Security Dashboard v{VERSION}</title>
    <style>
        :root {{
            --bg-primary: #0a0f1d;
            --bg-secondary: #111827;
            --bg-card: #1f2937;
            --bg-card-hover: #374151;
            --text-primary: #f9fafb;
            --text-muted: #9ca3af;
            --accent-red: #ef4444;
            --accent-orange: #f97316;
            --accent-yellow: #eab308;
            --accent-green: #10b981;
            --accent-blue: #3b82f6;
            --accent-purple: #a855f7;
            --border-color: #374151;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }}
        body {{ background: var(--bg-primary); color: var(--text-primary); padding: 2rem 1.5rem; min-height: 100vh; }}
        .container {{ max-width: 1280px; margin: 0 auto; }}
        header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; padding-bottom: 1.5rem; border-bottom: 1px solid var(--border-color); flex-wrap: wrap; gap: 1rem; }}
        .header-title h1 {{ font-size: 1.85rem; font-weight: 800; display: flex; align-items: center; gap: 0.6rem; letter-spacing: -0.025em; }}
        .header-title p {{ color: var(--text-muted); font-size: 0.9rem; margin-top: 0.35rem; }}
        .status-badge {{ background: {status_color}; color: #fff; padding: 0.5rem 1.25rem; border-radius: 9999px; font-weight: 700; font-size: 0.85rem; letter-spacing: 0.05em; text-transform: uppercase; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }}
        
        .metrics-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
        .card {{ background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 0.75rem; padding: 1.25rem; text-align: center; transition: transform 0.2s, border-color 0.2s; }}
        .card:hover {{ transform: translateY(-2px); border-color: var(--accent-blue); }}
        .card-label {{ font-size: 0.8rem; text-transform: uppercase; color: var(--text-muted); font-weight: 600; letter-spacing: 0.05em; }}
        .card-value {{ font-size: 2rem; font-weight: 800; margin-top: 0.4rem; }}
        
        .text-red {{ color: var(--accent-red); }}
        .text-orange {{ color: var(--accent-orange); }}
        .text-green {{ color: var(--accent-green); }}
        .text-blue {{ color: var(--accent-blue); }}
        .text-purple {{ color: var(--accent-purple); }}

        .toolbar {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; flex-wrap: wrap; gap: 1rem; }}
        .filter-buttons {{ display: flex; gap: 0.5rem; flex-wrap: wrap; }}
        .filter-btn {{ background: var(--bg-secondary); color: var(--text-muted); border: 1px solid var(--border-color); padding: 0.45rem 0.9rem; border-radius: 0.5rem; font-size: 0.85rem; font-weight: 600; cursor: pointer; transition: all 0.2s; }}
        .filter-btn:hover {{ background: var(--bg-card-hover); color: var(--text-primary); }}
        .filter-btn.active {{ background: var(--accent-blue); color: #fff; border-color: var(--accent-blue); }}
        .filter-btn.active-critical {{ background: var(--accent-red); color: #fff; border-color: var(--accent-red); }}
        .filter-btn.active-high {{ background: var(--accent-orange); color: #fff; border-color: var(--accent-orange); }}
        
        .search-box {{ background: var(--bg-secondary); border: 1px solid var(--border-color); color: var(--text-primary); padding: 0.45rem 0.9rem; border-radius: 0.5rem; font-size: 0.85rem; outline: none; width: 240px; }}
        .search-box:focus {{ border-color: var(--accent-blue); }}

        .table-container {{ background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 0.75rem; overflow-x: auto; box-shadow: 0 10px 25px rgba(0,0,0,0.2); }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 0.92rem; }}
        th, td {{ padding: 1rem 1.2rem; border-bottom: 1px solid var(--border-color); vertical-align: middle; }}
        th {{ background: rgba(0,0,0,0.25); color: var(--text-muted); font-weight: 700; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; }}
        tr:hover {{ background: rgba(255,255,255,0.02); }}
        
        .badge {{ display: inline-block; padding: 0.25rem 0.6rem; border-radius: 0.35rem; font-weight: 700; font-size: 0.75rem; letter-spacing: 0.04em; }}
        .badge-critical {{ background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }}
        .badge-high {{ background: rgba(249, 115, 22, 0.15); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.4); }}
        .badge-medium {{ background: rgba(234, 179, 8, 0.15); color: #facc15; border: 1px solid rgba(234, 179, 8, 0.4); }}
        .file-path {{ color: var(--text-muted); font-size: 0.78rem; }}
        .cvss-score {{ font-weight: 800; color: #e2e8f0; font-size: 0.95rem; }}
        .conf-badge {{ background: var(--bg-card); padding: 0.2rem 0.5rem; border-radius: 0.25rem; font-size: 0.8rem; color: #38bdf8; }}
        code {{ background: #070c18; border: 1px solid var(--border-color); color: #38bdf8; padding: 0.25rem 0.5rem; border-radius: 0.35rem; font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 0.85rem; word-break: break-all; display: block; }}
        
        footer {{ margin-top: 2.5rem; text-align: center; color: var(--text-muted); font-size: 0.85rem; padding-top: 1.5rem; border-top: 1px solid var(--border-color); }}
        footer a {{ color: var(--accent-blue); text-decoration: none; font-weight: 600; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-title">
                <h1>🛡️ Codex Security Linter Report</h1>
                <p>Enterprise AI Security Audit & Vulnerability Engine v{VERSION}</p>
            </div>
            <div class="status-badge">{status_text}</div>
        </header>

        <div class="metrics-grid">
            <div class="card">
                <div class="card-label">Total Findings</div>
                <div class="card-value text-purple">{total_count}</div>
            </div>
            <div class="card">
                <div class="card-label">Critical Risks</div>
                <div class="card-value text-red">{critical_count}</div>
            </div>
            <div class="card">
                <div class="card-label">High Severity</div>
                <div class="card-value text-orange">{high_count}</div>
            </div>
            <div class="card">
                <div class="card-label">Lines Scanned</div>
                <div class="card-value text-blue">{lines_scanned}</div>
            </div>
            <div class="card">
                <div class="card-label">Execution Time</div>
                <div class="card-value text-green">{duration_ms:.1f}ms</div>
            </div>
        </div>

        <div class="toolbar">
            <div class="filter-buttons">
                <button class="filter-btn active" onclick="filterFindings('ALL', this)">All ({total_count})</button>
                <button class="filter-btn" onclick="filterFindings('CRITICAL', this)">Critical ({critical_count})</button>
                <button class="filter-btn" onclick="filterFindings('HIGH', this)">High ({high_count})</button>
            </div>
            <input type="text" class="search-box" id="search-input" placeholder="🔍 Search findings..." onkeyup="searchFindings()">
        </div>

        <div class="table-container">
            <table id="findings-table">
                <thead>
                    <tr>
                        <th style="width: 110px;">Severity</th>
                        <th>Vulnerability & File</th>
                        <th style="width: 90px;">CVSS</th>
                        <th style="width: 100px;">Confidence</th>
                        <th>Code Snippet</th>
                    </tr>
                </thead>
                <tbody>
                    {table_rows}
                </tbody>
            </table>
        </div>

        <footer>
            Audited automatically by <a href="https://github.com/knmt1219/codex-security-linter">Codex Security Linter v{VERSION}</a> &bull; Open Source MIT License &bull; Author: Hồ Minh Tuấn
        </footer>
    </div>

    <script>
        let currentFilter = 'ALL';

        function filterFindings(severity, btn) {{
            currentFilter = severity;
            document.querySelectorAll('.filter-btn').forEach(b => b.className = 'filter-btn');
            if (severity === 'CRITICAL') btn.classList.add('active-critical');
            else if (severity === 'HIGH') btn.classList.add('active-high');
            else btn.classList.add('active');
            applyFilters();
        }}

        function searchFindings() {{
            applyFilters();
        }}

        function applyFilters() {{
            const search = document.getElementById('search-input').value.toLowerCase();
            const rows = document.querySelectorAll('#findings-table tbody tr[data-severity]');
            rows.forEach(row => {{
                const rowSeverity = row.getAttribute('data-severity');
                const rowText = row.textContent.toLowerCase();
                const matchesFilter = (currentFilter === 'ALL' || rowSeverity === currentFilter);
                const matchesSearch = (!search || rowText.includes(search));
                row.style.display = (matchesFilter && matchesSearch) ? '' : 'none';
            }});
        }}
    </script>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"✅ Interactive HTML report exported to: {output_path}")

def export_sarif(findings: list, output_path: str = "results.sarif"):
    sarif_data = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Codex Security Linter",
                    "version": VERSION,
                    "informationUri": "https://github.com/knmt1219/codex-security-linter",
                    "rules": [{
                        "id": "CSL001",
                        "name": "SecurityVulnerabilityOrSecret",
                        "shortDescription": {"text": "Security flaw or secret detected in code changes"}
                    }]
                }
            },
            "results": [
                {
                    "ruleId": "CSL001",
                    "level": "error" if f.get("severity") in ["CRITICAL", "HIGH"] else "warning",
                    "message": {"text": f"{f.get('type')} (CVSS: {f.get('score')}) in `{f.get('snippet')}`"}
                } for f in findings
            ]
        }]
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif_data, f, indent=2)

def should_fail_on_severity(findings: list, fail_on_threshold: str) -> bool:
    """Return True if any finding meets or exceeds the specified fail_on severity threshold."""
    if not fail_on_threshold or not findings:
        return False
    
    threshold_rank = SEVERITY_RANKS.get(fail_on_threshold.upper(), 3)
    for f in findings:
        sev = f.get("severity", "LOW").upper()
        if SEVERITY_RANKS.get(sev, 1) >= threshold_rank:
            return True
    return False

def audit_diff_with_ai(diff_text: str, api_key: str, model_name: str = "gpt-4o-mini") -> str:
    try:
        from openai import OpenAI
    except ImportError:
        return "*(OpenAI SDK not installed. Please run `pip install openai` to enable AI vulnerability analysis)*"

    optimized_diff = chunk_diff_smart(diff_text, max_chars=12000)
    client = OpenAI(api_key=api_key)
    prompt = (
        "You are an application security expert auditing an open-source Pull Request.\n"
        "Analyze the following code diff and report:\n"
        "1. [SEVERITY: CRITICAL/HIGH/MEDIUM/LOW] (Include Confidence % and estimated CVSS score).\n"
        "2. Concrete remediation code patches formatted as GitHub suggestions (```suggestion ... ```) when applicable.\n"
        "3. Best practices recommendation.\n"
        "If no vulnerabilities are detected, state: 'No security vulnerabilities detected.'\n\n"
        f"Diff:\n```diff\n{optimized_diff}\n```"
    )
    res = client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "system", "content": "You are a specialized security audit agent for open-source repositories."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.1,
    )
    return res.choices[0].message.content

def main():
    start_time = time.time()
    parser = argparse.ArgumentParser(description=f"Codex Security Linter CLI & GitHub Action (v{VERSION})")
    parser.add_argument("--local", action="store_true", help="Run scan on local git diff")
    parser.add_argument("--staged", action="store_true", help="Run scan on staged git changes (git diff --cached)")
    parser.add_argument("--sarif", type=str, help="Export scan results to SARIF format")
    parser.add_argument("--json", type=str, help="Export scan results to JSON format")
    parser.add_argument("--html", type=str, help="Export interactive HTML security dashboard report")
    parser.add_argument("--badge", action="store_true", help="Generate SVG status badge")
    parser.add_argument("--strict", action="store_true", help="Fail with exit code 1 if critical/high risks found")
    parser.add_argument("--quiet", action="store_true", help="Quiet mode: only output messages when security issues are found")
    parser.add_argument("--config", type=str, help="Path to custom configuration file (default: .codex-security.yml)")
    parser.add_argument("--install-hook", action="store_true", help="Scaffold a .pre-commit-config.yaml configured for Codex Security Linter")
    parser.add_argument(
        "--fail-on",
        type=str,
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "critical", "high", "medium", "low"],
        help="Exit with code 1 if findings meet or exceed the specified severity threshold",
    )
    args = parser.parse_args()

    if args.install_hook:
        install_pre_commit_hook()
        return

    # Load configuration file
    config = load_config(args.config)
    settings = config.get("settings", {}) if isinstance(config.get("settings"), dict) else {}
    ignore_paths = config.get("ignore_paths", []) if isinstance(config.get("ignore_paths"), list) else []

    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    model_name = os.environ.get("MODEL_NAME") or settings.get("model") or "gpt-4o-mini"

    fail_threshold = None
    if args.fail_on:
        fail_threshold = args.fail_on.upper()
    elif args.strict:
        fail_threshold = "HIGH"
    elif settings.get("severity_threshold"):
        fail_threshold = str(settings.get("severity_threshold")).upper()

    if args.local or args.staged:
        if args.staged:
            diff_text = os.popen("git diff --cached").read()
        else:
            diff_text = os.popen("git diff HEAD~1").read()
            if not diff_text.strip():
                diff_text = os.popen("git diff").read()

        if not diff_text.strip():
            if not args.quiet:
                print("No local git changes detected to audit.")
            return

        lines_scanned = count_scanned_lines(diff_text)
        if not args.quiet:
            print(f"🔍 Running Heuristic & Language-Aware Security Scan (v{VERSION})...")
        findings = heuristic_scan_structured(diff_text, ignore_paths)
        duration_ms = (time.time() - start_time) * 1000

        if args.badge:
            generate_svg_badge(bool(findings))

        if findings:
            print("\n📊 Security Summary Matrix:")
            print(build_markdown_summary_table(findings, lines_scanned, duration_ms))
            if args.sarif:
                export_sarif(findings, args.sarif)
            if args.json:
                with open(args.json, "w", encoding="utf-8") as jf:
                    json.dump(findings, jf, indent=2)
                print(f"JSON report exported to: {args.json}")
            if args.html:
                export_html(findings, args.html, lines_scanned, duration_ms)
            
            if fail_threshold and should_fail_on_severity(findings, fail_threshold):
                print(f"\n❌ Threshold violation: Vulnerabilities matching or exceeding '{fail_threshold}' detected. Exiting with error.")
                sys.exit(1)
        else:
            if not args.quiet:
                print(f"✅ Heuristic Scan: Clean (Scanned {lines_scanned} lines in {duration_ms:.2f}ms)")
            if args.html:
                export_html(findings, args.html, lines_scanned, duration_ms)

        if api_key:
            if not args.quiet:
                print("\n🤖 Running Deep AI Security Analysis...")
            ai_report = audit_diff_with_ai(diff_text, api_key, model_name)
            print("\n" + ai_report)
        return

    # Chế độ GitHub Action
    token = os.environ.get("GITHUB_TOKEN")
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not (token and event_path):
        print("Warning: GITHUB_TOKEN or GITHUB_EVENT_PATH not set. Exiting cleanly.")
        return

    try:
        with open(event_path, "r", encoding="utf-8") as f:
            event_data = json.load(f)
    except Exception as e:
        print(f"Error loading event payload: {e}")
        return

    pr_data = event_data.get("pull_request")
    if not pr_data:
        print("Not a pull request event.")
        return

    repo_full_name = event_data["repository"]["full_name"]
    pr_number = pr_data["number"]
    diff_text = get_pr_diff(repo_full_name, pr_number, token)

    if not diff_text.strip():
        print("Empty or inaccessible diff.")
        generate_svg_badge(False)
        write_github_action_outputs([], args.sarif or "", args.html or "")
        return

    lines_scanned = count_scanned_lines(diff_text)
    findings = heuristic_scan_structured(diff_text, ignore_paths)
    duration_ms = (time.time() - start_time) * 1000

    generate_svg_badge(bool(findings))

    summary_table = build_markdown_summary_table(findings, lines_scanned, duration_ms)
    report_sections = [f"#### 📊 Executive Security Summary\n{summary_table}"]

    if args.sarif:
        export_sarif(findings, args.sarif)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as jf:
            json.dump(findings, jf, indent=2)
    if args.html:
        export_html(findings, args.html, lines_scanned, duration_ms)

    # Ghi nhận Output variables cho GitHub Actions
    write_github_action_outputs(findings, args.sarif or "", args.html or "")

    if api_key:
        try:
            ai_report = audit_diff_with_ai(diff_text, api_key, model_name)
            report_sections.append("#### 🤖 Deep AI Security Analysis & Fixes\n" + ai_report)
        except Exception as e:
            report_sections.append(f"*(AI analysis unavailable: {e})*")

    badge_img = "https://img.shields.io/badge/Codex%20Audit-ISSUES%20FOUND-red" if findings else "https://img.shields.io/badge/Codex%20Audit-PASSED-brightgreen"

    final_comment = (
        f"![Security Status]({badge_img})\n\n"
        f"### 🛡️ Codex Security Audit Report (v{VERSION})\n\n"
        + "\n\n".join(report_sections)
        + f"\n\n---\n*Automated audit powered by [codex-security-linter](https://github.com/knmt1219/codex-security-linter)*"
    )

    post_comment(repo_full_name, pr_number, token, final_comment)
    print(f"Security audit executed and posted successfully ({lines_scanned} lines scanned in {duration_ms:.2f}ms).")

    if fail_threshold and should_fail_on_severity(findings, fail_threshold):
        sys.exit(1)

if __name__ == "__main__":
    main()
