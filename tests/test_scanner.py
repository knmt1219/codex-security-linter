import sys
import os
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

try:
    import pytest
except ImportError:
    pytest = None

from scanner import (
    heuristic_scan_structured,
    build_markdown_summary_table,
    mask_sensitive_value,
    generate_svg_badge,
    export_sarif,
    export_html,
    should_fail_on_severity,
    write_github_action_outputs,
    load_config,
    parse_simple_yaml,
    is_ignored_file,
    count_scanned_lines,
    chunk_diff_smart,
)

def test_mask_sensitive_value():
    raw_secret = "aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"
    masked = mask_sensitive_value(raw_secret)
    assert "..." in masked
    assert "wJal" in masked

def test_heuristic_scan_structured():
    diff = "+ aws_access_key_id = 'AKIAIOSFODNN7EXAMPLE12'"
    findings = heuristic_scan_structured(diff)
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"
    assert findings[0]["score"] == "10.0"
    assert findings[0]["confidence"] == "99%"
    assert "..." in findings[0]["snippet"]

def test_go_vulnerability_patterns():
    go_diff = """--- a/user.go
+++ b/user.go
+ rows, err := db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name))
+ ptr := unsafe.Pointer(&data)
"""
    findings = heuristic_scan_structured(go_diff)
    assert len(findings) == 2
    types = [f["type"] for f in findings]
    assert "Go SQL Injection Risk (fmt.Sprintf)" in types
    assert "Dangerous Go Memory Manipulation (unsafe.Pointer)" in types

def test_rust_vulnerability_patterns():
    rust_diff = """--- a/lib.rs
+++ b/lib.rs
+ unsafe {
+     *raw_ptr = 42;
+ }
"""
    findings = heuristic_scan_structured(rust_diff)
    assert len(findings) == 1
    assert findings[0]["type"] == "Unsafe Rust Code Block (Memory Safety Risk)"

def test_chunk_diff_smart():
    small_diff = "+ const x = 10;"
    assert chunk_diff_smart(small_diff, max_chars=100) == small_diff

    large_diff = "diff --git a/test.py b/test.py\n+ eval('alert()')\n" + ("diff --git a/docs.txt b/docs.txt\n+ info\n" * 50)
    chunked = chunk_diff_smart(large_diff, max_chars=200)
    assert len(chunked) <= 300
    assert "eval('alert()')" in chunked

def test_count_scanned_lines():
    diff = """--- a/file.py
+++ b/file.py
+ line 1
+ line 2
- line 3
+ line 4
"""
    assert count_scanned_lines(diff) == 3

def test_is_ignored_file():
    assert is_ignored_file("bundle.min.js") is True
    assert is_ignored_file("app.min.css") is True
    assert is_ignored_file("dist/app.js") is True
    assert is_ignored_file("build/bundle.js") is True
    assert is_ignored_file("vendor/lib.js") is True
    assert is_ignored_file("package-lock.json") is True
    assert is_ignored_file("src/auth.py") is False

def test_minified_file_diff_ignored():
    diff = """diff --git a/dist/bundle.min.js b/dist/bundle.min.js
--- a/dist/bundle.min.js
+++ b/dist/bundle.min.js
+ aws_access_key_id = 'AKIAIOSFODNN7EXAMPLE12'
diff --git a/src/app.py b/src/app.py
--- a/src/app.py
+++ b/src/app.py
+ aws_access_key_id = 'AKIAIOSFODNN7EXAMPLE12'
"""
    findings = heuristic_scan_structured(diff)
    assert len(findings) == 1
    assert findings[0]["file"] == "src/app.py"

def test_build_markdown_summary_table():
    findings = [{
        "severity": "CRITICAL",
        "type": "AWS Credential Leak",
        "score": "10.0",
        "confidence": "99%",
        "snippet": "aws_access_key_id = 'AKIA...LE12'"
    }]
    table = build_markdown_summary_table(findings, lines_scanned=25, duration_ms=12.5)
    assert "| Severity | Vulnerability Type |" in table
    assert "🔴 `CRITICAL`" in table
    assert "10.0" in table
    assert "Performance" in table
    assert "25" in table

def test_generate_svg_badge(tmp_path):
    badge_file = tmp_path / "badge.svg"
    generate_svg_badge(False, str(badge_file))
    assert badge_file.exists()
    content = badge_file.read_text(encoding="utf-8")
    assert "passed" in content
    assert "<svg" in content

def test_export_sarif(tmp_path):
    sarif_file = tmp_path / "test.sarif"
    findings = [{
        "severity": "CRITICAL",
        "type": "AWS Credential Leak",
        "score": "10.0",
        "confidence": "99%",
        "snippet": "aws_access_key_id = 'AKIA...LE12'"
    }]
    export_sarif(findings, str(sarif_file))
    assert sarif_file.exists()

def test_export_html(tmp_path):
    html_file = tmp_path / "security-report.html"
    findings = [{
        "severity": "CRITICAL",
        "type": "AWS Credential Leak",
        "score": "10.0",
        "confidence": "99%",
        "snippet": "aws_access_key_id = 'AKIA...LE12'"
    }]
    export_html(findings, str(html_file), lines_scanned=40, duration_ms=15.2)
    assert html_file.exists()
    content = html_file.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in content
    assert "Codex Security Linter Report" in content
    assert "AWS Credential Leak" in content
    assert "Lines Scanned" in content
    assert "40" in content

def test_should_fail_on_severity():
    critical_findings = [{"severity": "CRITICAL"}]
    high_findings = [{"severity": "HIGH"}]
    low_findings = [{"severity": "LOW"}]

    # When threshold is CRITICAL
    assert should_fail_on_severity(critical_findings, "CRITICAL") is True
    assert should_fail_on_severity(high_findings, "CRITICAL") is False

    # When threshold is HIGH
    assert should_fail_on_severity(critical_findings, "HIGH") is True
    assert should_fail_on_severity(high_findings, "HIGH") is True
    assert should_fail_on_severity(low_findings, "HIGH") is False

    # When threshold is LOW
    assert should_fail_on_severity(low_findings, "LOW") is True

def test_github_action_outputs(tmp_path):
    output_file = tmp_path / "github_output.txt"
    os.environ["GITHUB_OUTPUT"] = str(output_file)
    findings = [{
        "severity": "CRITICAL",
        "type": "AWS Credential Leak",
        "score": "10.0",
        "confidence": "99%",
        "snippet": "aws_access_key_id = 'AKIA...LE12'"
    }]
    write_github_action_outputs(findings, "results.sarif", "security-report.html")
    assert output_file.exists()
    content = output_file.read_text(encoding="utf-8")
    assert "findings-count=1" in content
    assert "has-critical=true" in content
    assert "sarif-path=results.sarif" in content
    assert "html-report-path=security-report.html" in content
    del os.environ["GITHUB_OUTPUT"]

def test_load_config(tmp_path):
    config_file = tmp_path / "custom.yml"
    yaml_content = """version: 2.5
settings:
  model: "gpt-4o"
  severity_threshold: "HIGH"
ignore_paths:
  - "tests/*"
"""
    config_file.write_text(yaml_content, encoding="utf-8")
    config = load_config(str(config_file))
    assert config.get("settings", {}).get("model") == "gpt-4o"
    assert config.get("settings", {}).get("severity_threshold") == "HIGH"
    assert "tests/*" in config.get("ignore_paths", [])

if __name__ == "__main__":
    import tempfile

    if sys.stdout and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if sys.stderr and hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")

    print("Running unit tests for v2.5.0...")
    test_mask_sensitive_value()
    print("✓ test_mask_sensitive_value passed")
    test_heuristic_scan_structured()
    print("✓ test_heuristic_scan_structured passed")
    test_go_vulnerability_patterns()
    print("✓ test_go_vulnerability_patterns passed")
    test_rust_vulnerability_patterns()
    print("✓ test_rust_vulnerability_patterns passed")
    test_chunk_diff_smart()
    print("✓ test_chunk_diff_smart passed")
    test_count_scanned_lines()
    print("✓ test_count_scanned_lines passed")
    test_is_ignored_file()
    print("✓ test_is_ignored_file passed")
    test_minified_file_diff_ignored()
    print("✓ test_minified_file_diff_ignored passed")
    test_build_markdown_summary_table()
    print("✓ test_build_markdown_summary_table passed")

    with tempfile.TemporaryDirectory() as td:
        tp = pathlib.Path(td)
        test_generate_svg_badge(tp)
        print("✓ test_generate_svg_badge passed")
        test_export_sarif(tp)
        print("✓ test_export_sarif passed")
        test_export_html(tp)
        print("✓ test_export_html passed")
        test_github_action_outputs(tp)
        print("✓ test_github_action_outputs passed")
        test_load_config(tp)
        print("✓ test_load_config passed")

    test_should_fail_on_severity()
    print("✓ test_should_fail_on_severity passed")
    print("🎉 All 15 unit tests passed successfully!")
