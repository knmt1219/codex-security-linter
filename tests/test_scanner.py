import os
import json
import pytest
from scanner import heuristic_regex_scan, export_sarif

def test_heuristic_regex_scan_detects_secret():
    sample_diff = "+ aws_access_key_id = 'AKIAIOSFODNN7EXAMPLE12'\n+ password = 'mysecretpassword'"
    findings = heuristic_regex_scan(sample_diff)
    assert len(findings) >= 1
    assert any("AWS Credential Leak" in f or "Password" in f for f in findings)

def test_heuristic_regex_scan_clean_diff():
    clean_diff = "+ def calculate_total(a, b):\n+     return a + b"
    findings = heuristic_regex_scan(clean_diff)
    assert len(findings) == 0

def test_export_sarif(tmp_path):
    output_file = tmp_path / "test_results.sarif"
    findings = ["- **[CRITICAL SECRET LEAK]** `AWS Credential Leak` found"]
    export_sarif(findings, str(output_file))
    
    assert os.path.exists(output_file)
    with open(output_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["version"] == "2.1.0"
    assert len(data["runs"][0]["results"]) == 1
