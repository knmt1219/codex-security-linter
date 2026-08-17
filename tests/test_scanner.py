import pytest
from scanner import (
    heuristic_scan_structured,
    build_markdown_summary_table,
    mask_sensitive_value,
    generate_svg_badge,
    export_sarif,
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

def test_build_markdown_summary_table():
    findings = [{
        "severity": "CRITICAL",
        "type": "AWS Credential Leak",
        "score": "10.0",
        "confidence": "99%",
        "snippet": "aws_access_key_id = 'AKIA...LE12'"
    }]
    table = build_markdown_summary_table(findings)
    assert "| Severity | Vulnerability Type |" in table
    assert "🔴 `CRITICAL`" in table
    assert "10.0" in table

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
