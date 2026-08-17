import pytest
from scanner import heuristic_scan, export_sarif

def test_heuristic_scan_secrets_and_vulns():
    sample_diff = """
+ aws_access_key_id = 'AKIAIOSFODNN7EXAMPLE12'
+ eval(user_input)
+ subprocess.Popen(cmd, shell=True)
"""
    findings = heuristic_scan(sample_diff)
    assert len(findings) == 3
    assert any("AWS Credential Leak" in f for f in findings)
    assert any("eval/exec" in f for f in findings)
    assert any("shell=True" in f for f in findings)

def test_heuristic_scan_clean():
    clean_diff = "+ def safe_add(a, b):\n+     return a + b"
    findings = heuristic_scan(clean_diff)
    assert len(findings) == 0

def test_sarif_export(tmp_path):
    sarif_file = tmp_path / "test.sarif"
    findings = ["- **[CRITICAL SECRET LEAK]** `AWS Key`: `AKIA...`"]
    export_sarif(findings, str(sarif_file))
    assert sarif_file.exists()
