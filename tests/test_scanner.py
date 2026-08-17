import pytest
from scanner import heuristic_regex_scan

def test_heuristic_regex_scan_detects_secret():
    sample_diff = "+ aws_access_key_id = 'AKIAIOSFODNN7EXAMPLE12'\n+ password = 'mysecretpassword'"
    findings = heuristic_regex_scan(sample_diff)
    assert len(findings) >= 1
    assert any("AWS Credential Leak" in f or "Password" in f for f in findings)

def test_heuristic_regex_scan_clean_diff():
    clean_diff = "+ def calculate_total(a, b):\n+     return a + b"
    findings = heuristic_regex_scan(clean_diff)
    assert len(findings) == 0
