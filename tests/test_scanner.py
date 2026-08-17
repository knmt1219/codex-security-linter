import pytest
from scanner import heuristic_scan, mask_sensitive_value, generate_svg_badge, export_sarif

def test_mask_sensitive_value():
    raw_secret = "aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"
    masked = mask_sensitive_value(raw_secret)
    assert "..." in masked
    assert "wJal" in masked

def test_heuristic_scan_masks_output():
    diff = "+ aws_access_key_id = 'AKIAIOSFODNN7EXAMPLE12'"
    findings = heuristic_scan(diff)
    assert len(findings) == 1
    assert "..." in findings[0]
    assert "CVSS: 10.0" in findings[0]
    assert "Confidence: 99%" in findings[0]

def test_generate_svg_badge(tmp_path):
    badge_file = tmp_path / "badge.svg"
    generate_svg_badge(False, str(badge_file))
    assert badge_file.exists()
    content = badge_file.read_text(encoding="utf-8")
    assert "passed" in content
    assert "<svg" in content

def test_export_sarif(tmp_path):
    sarif_file = tmp_path / "test.sarif"
    findings = ["- **[CRITICAL SECRET LEAK]** `AWS Key`: `AKIA...`"]
    export_sarif(findings, str(sarif_file))
    assert sarif_file.exists()
