"""Reporting formats and output exporters.

Supports Markdown summary tables, interactive Dark Mode HTML reports,
OASIS SARIF 2.1.0, JSON, and SVG status badges.
"""

import html
import json
from typing import Any, Dict, List
from . import __version__


def build_markdown_summary_table(findings: List[Dict[str, Any]], lines_scanned: int = 0, duration_ms: float = 0.0) -> str:
    """Format audit findings into a clean Markdown table."""
    metrics_line = f"⚡ **Scan Metrics:** Scanned `{lines_scanned}` lines in `{duration_ms:.2f}ms` | Findings: `{len(findings)}`\n\n"
    if not findings:
        return metrics_line + "✅ **Security Status:** No vulnerabilities or secret leaks detected."

    table = metrics_line
    table += "| Severity | Vulnerability Type | CVSS | Confidence | Code Snippet |\n"
    table += "| :--- | :--- | :---: | :---: | :--- |\n"
    for f in findings:
        badge = "🔴 `CRITICAL`" if f.get("severity") == "CRITICAL" else "🟠 `HIGH`"
        table += f"| {badge} | {f.get('type')} | **{f.get('score')}** | {f.get('confidence')} | `{f.get('snippet')}` |\n"
    return table


def generate_svg_badge(has_issues: bool, output_path: str = "security-badge.svg") -> None:
    """Generate an SVG status badge."""
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


def export_html(findings: List[Dict[str, Any]], output_path: str = "security-report.html", lines_scanned: int = 0, duration_ms: float = 0.0) -> None:
    """Export an interactive Dark Mode HTML5 report with real-time filtering."""
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
                🎉 <strong>Clean:</strong> No vulnerabilities, malware patterns, or hardcoded secrets detected.
            </td>
        </tr>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PR Security Linter Report v{__version__}</title>
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
                <h1>🛡️ PR Security Linter Report</h1>
                <p>Fast, lightweight security & secret audit v{__version__}</p>
            </div>
            <div class="status-badge">{status_text}</div>
        </header>

        <div class="metrics-grid">
            <div class="card">
                <div class="card-label">Total Findings</div>
                <div class="card-value text-purple">{total_count}</div>
            </div>
            <div class="card">
                <div class="card-label">Critical Severity</div>
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
                <div class="card-label">Duration</div>
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
            Audited by <a href="https://github.com/knmt1219/pr-security-linter">PR Security Linter v{__version__}</a> &bull; Open Source MIT License
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


def export_sarif(findings: List[Dict[str, Any]], output_path: str = "results.sarif") -> None:
    """Export findings to OASIS SARIF 2.1.0 format."""
    sarif_data = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "PR Security Linter",
                    "version": __version__,
                    "informationUri": "https://github.com/knmt1219/pr-security-linter",
                    "rules": [{
                        "id": "PRSEC001",
                        "name": "SecurityFindingOrSecret",
                        "shortDescription": {"text": "Potential security flaw, dangerous API, or secret detected in code changes"}
                    }]
                }
            },
            "results": [
                {
                    "ruleId": "PRSEC001",
                    "level": "error" if f.get("severity") in ["CRITICAL", "HIGH"] else "warning",
                    "message": {"text": f"{f.get('type')} (CVSS: {f.get('score')}) in `{f.get('snippet')}`"}
                } for f in findings
            ]
        }]
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif_data, f, indent=2)


def export_json(findings: List[Dict[str, Any]], output_path: str = "findings.json") -> None:
    """Export findings as formatted JSON."""
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)
