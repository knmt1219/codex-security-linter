"""Practical verification suite testing 12 real-world security and false-positive scenarios."""

import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from pr_security_linter.engine import SecurityEngine


def test_practical_scenarios():
    with tempfile.TemporaryDirectory() as td:
        p = pathlib.Path(td)

        # 1. Fake password
        (p / "t1.py").write_text("password = 'InertSyntheticPassword123'\n", encoding="utf-8")
        # 2. Fake AWS key
        (p / "t2.py").write_text("aws_access_key_id = 'AKIAIOSFODNN7EXAMPLE12'\n", encoding="utf-8")
        # 3. Dynamic eval
        (p / "t3.py").write_text("eval(user_input)\n", encoding="utf-8")
        # 4. Constant eval
        (p / "t4.py").write_text("eval('1 + 2')\n", encoding="utf-8")
        # 5. ast.literal_eval
        (p / "t5.py").write_text("import ast\nast.literal_eval(data)\n", encoding="utf-8")
        # 6. Comment containing eval
        (p / "t6.py").write_text("# TODO: never use eval() in production\n", encoding="utf-8")
        # 7. subprocess shell=True
        (p / "t7.py").write_text("import subprocess\nsubprocess.run(cmd, shell=True)\n", encoding="utf-8")
        # 8. harmless subprocess
        (p / "t8.py").write_text("import subprocess\nsubprocess.run(['ls', '-la'])\n", encoding="utf-8")
        # 9. React XSS sink
        (p / "t9.jsx").write_text("export function UI({payload}) { return <div dangerouslySetInnerHTML={{__html: payload}} />; }\n", encoding="utf-8")
        # 10. Safe DOM
        (p / "t10.js").write_text("function render(el, msg) { el.textContent = msg; }\n", encoding="utf-8")
        # 11. Suspicious command/buffer overflow
        (p / "t11.c").write_text("void f() { char b[32]; gets(b); }\n", encoding="utf-8")
        # 12. Safe documentation
        (p / "t12.py").write_text('"""Documentation discussing eval and exec."""\npass\n', encoding="utf-8")

        engine = SecurityEngine()

        results = {}
        for i in range(1, 13):
            ext = ".jsx" if i == 9 else (".js" if i == 10 else (".c" if i == 11 else ".py"))
            f_path = p / f"t{i}{ext}"
            findings, _ = engine.scan_path(str(f_path))
            results[i] = findings

        # Assertions
        # 1: Password detected
        assert len(results[1]) == 1 and results[1][0].rule_id == "SEC-PASS-001"
        # 2: AWS key detected
        assert len(results[2]) == 1 and results[2][0].rule_id == "SEC-AWS-001"
        # 3: Dynamic eval detected (HIGH severity, confidence 0.99)
        assert len(results[3]) == 1 and results[3][0].rule_id == "PY-DYN-001" and results[3][0].severity.value == "HIGH"
        # 4: Constant eval detected (MEDIUM severity, confidence 0.80)
        assert len(results[4]) == 1 and results[4][0].rule_id == "PY-DYN-001" and results[4][0].severity.value == "MEDIUM"
        # 5: ast.literal_eval is safe -> 0 findings
        assert len(results[5]) == 0
        # 6: Comment containing eval is safe -> 0 findings
        assert len(results[6]) == 0
        # 7: subprocess shell=True detected -> PY-CMD-001
        assert len(results[7]) == 1 and results[7][0].rule_id == "PY-CMD-001"
        # 8: harmless subprocess is safe -> 0 findings
        assert len(results[8]) == 0
        # 9: React XSS sink detected -> JS-XSS-001
        assert len(results[9]) == 1 and results[9][0].rule_id == "JS-XSS-001"
        # 10: Safe DOM is safe -> 0 findings
        assert len(results[10]) == 0
        # 11: gets buffer overflow detected -> CPP-BOF-GETS-001
        assert len(results[11]) == 1 and results[11][0].rule_id == "CPP-BOF-GETS-001"
        # 12: Safe documentation is safe -> 0 findings
        assert len(results[12]) == 0


if __name__ == "__main__":
    test_practical_scenarios()
    print("✅ All 12 practical security & false-positive test cases passed successfully!")
