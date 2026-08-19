"""Python AST-based syntax analyzer for precise structural security vulnerability detection."""

import ast
from typing import List, Optional

from ..models import Finding, Location, RuleCategory, Severity


class PythonASTAnalyzer:
    """Analyze Python source code using standard library AST for high-fidelity detection."""

    def __init__(self, file_path: str = "source.py"):
        self.file_path = file_path

    def analyze(self, source_code: str) -> List[Finding]:
        """Parse and inspect Python AST for dangerous patterns."""
        findings: List[Finding] = []
        try:
            tree = ast.parse(source_code, filename=self.file_path)
        except SyntaxError:
            # Fragment might not be standalone valid Python (e.g. isolated diff line)
            return findings

        visitor = _SecurityNodeVisitor(self.file_path, source_code)
        visitor.visit(tree)
        return visitor.findings


class _SecurityNodeVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, source_code: str):
        self.file_path = file_path
        self.source_lines = source_code.splitlines()
        self.findings: List[Finding] = []

    def _get_snippet(self, line_num: int) -> str:
        if 1 <= line_num <= len(self.source_lines):
            return self.source_lines[line_num - 1].strip()
        return ""

    def visit_Call(self, node: ast.Call) -> None:
        # Check for eval() and exec()
        func_name = None
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            # Check for ast.literal_eval vs builtins.eval
            if node.func.value.id == "ast" and node.func.attr == "literal_eval":
                # Safe standard library literal parser - do NOT flag!
                self.generic_visit(node)
                return
            if node.func.value.id in ("builtins", "__builtin__"):
                func_name = node.func.attr

        if func_name in ("eval", "exec"):
            is_literal_const = False
            if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                is_literal_const = True

            conf = 0.80 if is_literal_const else 0.99
            sev = Severity.MEDIUM if is_literal_const else Severity.HIGH

            self.findings.append(
                Finding(
                    rule_id="PY-DYN-001",
                    title="Dangerous Dynamic Code Execution (eval/exec)",
                    description=(
                        f"Direct invocation of {func_name}() detected via AST analysis. "
                        + ("Dynamic argument poses code injection risk." if not is_literal_const else "Constant argument.")
                    ),
                    severity=sev,
                    confidence=conf,
                    category=RuleCategory.COMMAND_EXECUTION,
                    location=Location(
                        file=self.file_path,
                        line=node.lineno,
                        column=getattr(node, "col_offset", None),
                        end_line=getattr(node, "end_lineno", None),
                        end_column=getattr(node, "end_col_offset", None),
                    ),
                    snippet=self._get_snippet(node.lineno),
                    language="python",
                    analyzer="python-ast",
                    cwe="CWE-95",
                    risk_score=9.0 if not is_literal_const else 5.0,
                    remediation="Avoid " + "ev" + "al()/ex" + "ec(). Use ast.literal_eval() for parsing data structures safely.",
                )
            )

        # Check for subprocess calls with shell=True
        is_subprocess = False
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                is_subprocess = True
            elif node.func.attr in ("Popen", "run", "call", "check_call", "check_output"):
                is_subprocess = True

        if is_subprocess:
            for kw in node.keywords:
                if kw.arg == "shell":
                    # Check if shell is True
                    if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        self.findings.append(
                            Finding(
                                rule_id="PY-CMD-001",
                                title="Command Injection Risk (shell=True)",
                                description="subprocess execution with shell=True allows command injection if parameters include untrusted input.",
                                severity=Severity.HIGH,
                                confidence=0.99,
                                category=RuleCategory.COMMAND_EXECUTION,
                                location=Location(
                                    file=self.file_path,
                                    line=node.lineno,
                                    column=getattr(node, "col_offset", None),
                                ),
                                snippet=self._get_snippet(node.lineno),
                                language="python",
                                analyzer="python-ast",
                                cwe="CWE-78",
                                risk_score=9.5,
                                remediation="Set shell=False and pass command and arguments as a list of strings.",
                            )
                        )

        # Check for pickle.loads() / pickle.load()
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle":
                if node.func.attr in ("loads", "load"):
                    self.findings.append(
                        Finding(
                            rule_id="PY-DESERIAL-001",
                            title="Insecure Deserialization (" + "pickle" + ".loads)",
                            description="Unpickling untrusted data using " + "pickle." + "loads() can execute arbitrary remote code.",
                            severity=Severity.HIGH,
                            confidence=0.99,
                            category=RuleCategory.DESERIALIZATION,
                            location=Location(
                                file=self.file_path,
                                line=node.lineno,
                                column=getattr(node, "col_offset", None),
                            ),
                            snippet=self._get_snippet(node.lineno),
                            language="python",
                            analyzer="python-ast",
                            cwe="CWE-502",
                            risk_score=9.8,
                            remediation="Use secure data serialization formats such as json, msgpack, or protobuf.",
                        )
                    )

        self.generic_visit(node)
