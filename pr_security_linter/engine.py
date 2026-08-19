"""Analysis engine orchestrating multi-layer rules, AST parsers, context filtering, and deduplication."""

import os
import pathlib
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from .analyzers.python_ast import PythonASTAnalyzer
from .models import Finding, Location, RuleCategory, Severity
from .patterns import (
    IGNORE_DIR_NAMES,
    SUSPICIOUS_EXECUTABLE_EXTS,
    is_comment_line,
    is_ignored_file,
    mask_sensitive_value,
    strip_inline_comment,
)
from .rules.registry import (
    BINARY_ARTIFACT_RULE,
    LANGUAGE_RULES,
    MALWARE_RULES,
    SECRET_RULES,
)


class SecurityEngine:
    """Multi-layer security audit engine with deterministic AST and regex analyzers."""

    def __init__(self, custom_ignore_paths: Optional[List[str]] = None, config: Optional[Dict[str, Any]] = None):
        self.custom_ignore_paths = custom_ignore_paths or []
        self.config = config or {}
        self.secret_rules = list(SECRET_RULES)
        self.malware_rules = list(MALWARE_RULES)
        self.language_rules = list(LANGUAGE_RULES)

    def scan_diff(self, diff_text: str) -> List[Finding]:
        """Audit git diff line-by-line using context-aware rules."""
        findings: List[Finding] = []
        current_file = ""
        ignoring_current_file = False
        reported_suspicious_files: Set[str] = set()
        current_line_num = 0

        for raw_line in diff_text.splitlines():
            line = raw_line
            if line.startswith("diff --git "):
                parts = line.split()
                if len(parts) >= 4:
                    current_file = parts[3]
                    clean_name = current_file.lstrip("b/").strip()
                    ignoring_current_file = is_ignored_file(current_file, self.custom_ignore_paths)
                    current_line_num = 0

                    if not ignoring_current_file and clean_name not in reported_suspicious_files:
                        if any(clean_name.lower().endswith(ext) for ext in SUSPICIOUS_EXECUTABLE_EXTS):
                            reported_suspicious_files.add(clean_name)
                            findings.append(
                                BINARY_ARTIFACT_RULE.create_finding(
                                    file_path=clean_name,
                                    line_num=0,
                                    snippet=f"Executable artifact detected: {clean_name}",
                                    analyzer="filesystem",
                                )
                            )
                continue
            elif line.startswith("+++ "):
                current_file = line[4:].strip()
                clean_name = current_file.lstrip("b/").strip()
                ignoring_current_file = is_ignored_file(current_file, self.custom_ignore_paths)
                current_line_num = 0
                if not ignoring_current_file and clean_name not in reported_suspicious_files:
                    if any(clean_name.lower().endswith(ext) for ext in SUSPICIOUS_EXECUTABLE_EXTS):
                        reported_suspicious_files.add(clean_name)
                        findings.append(
                            BINARY_ARTIFACT_RULE.create_finding(
                                file_path=clean_name,
                                line_num=0,
                                snippet=f"Executable artifact detected: {clean_name}",
                                analyzer="filesystem",
                            )
                        )
                continue
            elif line.startswith("@@ "):
                m = re.search(r'\+(\d+)', line)
                if m:
                    current_line_num = int(m.group(1)) - 1
                continue

            if ignoring_current_file:
                continue

            if line.startswith('+') and not line.startswith('+++'):
                current_line_num += 1
                clean_line = line[1:].strip()
                if not clean_line:
                    continue

                masked_line = mask_sensitive_value(clean_line)
                clean_file_path = current_file.lstrip("b/")

                # 1. Secrets check (full line)
                for rule in self.secret_rules:
                    if rule.matches(clean_line):
                        findings.append(
                            rule.create_finding(
                                file_path=clean_file_path,
                                line_num=current_line_num if current_line_num > 0 else 0,
                                snippet=masked_line[:80],
                                analyzer="regex",
                            )
                        )

                # 2. Malware & webshells check
                matched_malware = False
                for rule in self.malware_rules:
                    if rule.matches(clean_line):
                        matched_malware = True
                        findings.append(
                            rule.create_finding(
                                file_path=clean_file_path,
                                line_num=current_line_num if current_line_num > 0 else 0,
                                snippet=masked_line[:80],
                                analyzer="regex",
                            )
                        )

                # 3. Language vulnerability check (skip comments)
                if not matched_malware and not is_comment_line(clean_line):
                    code_part = strip_inline_comment(clean_line).strip()
                    if code_part:
                        for rule in self.language_rules:
                            if rule.matches(code_part):
                                findings.append(
                                    rule.create_finding(
                                        file_path=clean_file_path,
                                        line_num=current_line_num if current_line_num > 0 else 0,
                                        snippet=masked_line[:80],
                                        analyzer="regex",
                                    )
                                )

        return self.deduplicate_findings(findings)

    def scan_path(self, target_path: str) -> Tuple[List[Finding], int]:
        """Scan a local file or recursively walk a directory offline."""
        findings: List[Finding] = []
        lines_scanned = 0
        target = pathlib.Path(target_path).resolve()

        if not target.exists():
            return findings, lines_scanned

        files_to_scan: List[pathlib.Path] = []
        if target.is_file():
            files_to_scan.append(target)
        else:
            for root, dirs, files in os.walk(target):
                dirs[:] = [d for d in dirs if d not in IGNORE_DIR_NAMES and not is_ignored_file(d, self.custom_ignore_paths)]
                for file in files:
                    files_to_scan.append(pathlib.Path(root) / file)

        reported_binaries: Set[str] = set()

        for file_path in files_to_scan:
            try:
                rel_str = str(file_path.relative_to(target.parent if target.is_file() else target)).replace("\\", "/")
            except ValueError:
                rel_str = file_path.name

            if is_ignored_file(rel_str, self.custom_ignore_paths):
                continue

            # Flag suspicious binary or executable artifacts
            if any(file_path.name.lower().endswith(ext) for ext in SUSPICIOUS_EXECUTABLE_EXTS):
                if rel_str not in reported_binaries:
                    reported_binaries.add(rel_str)
                    findings.append(
                        BINARY_ARTIFACT_RULE.create_finding(
                            file_path=rel_str,
                            line_num=0,
                            snippet=f"Executable artifact detected: {file_path.name}",
                            analyzer="filesystem",
                        )
                    )
                continue

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception:
                continue

            lines = content.splitlines()
            lines_scanned += len(lines)

            # If file is Python, run AST analyzer first for structural detection
            ast_findings: List[Finding] = []
            if file_path.suffix.lower() in (".py", ".pyw"):
                ast_analyzer = PythonASTAnalyzer(file_path=rel_str)
                ast_findings = ast_analyzer.analyze(content)
                findings.extend(ast_findings)

            ast_covered_lines: Set[int] = {f.location.line for f in ast_findings}

            for line_num, line in enumerate(lines, 1):
                clean_line = line.strip()
                if not clean_line:
                    continue

                masked_line = mask_sensitive_value(clean_line)

                # 1. Check secrets (on full line)
                for rule in self.secret_rules:
                    if rule.matches(clean_line):
                        findings.append(
                            rule.create_finding(
                                file_path=rel_str,
                                line_num=line_num,
                                snippet=masked_line[:80],
                                analyzer="regex",
                            )
                        )

                # 2. Check malware & webshells
                matched_malware = False
                for rule in self.malware_rules:
                    if rule.matches(clean_line):
                        matched_malware = True
                        findings.append(
                            rule.create_finding(
                                file_path=rel_str,
                                line_num=line_num,
                                snippet=masked_line[:80],
                                analyzer="regex",
                            )
                        )

                # 3. Check language rules (skip if covered by AST or if line is a comment)
                if not matched_malware and line_num not in ast_covered_lines and not is_comment_line(clean_line):
                    code_part = strip_inline_comment(clean_line).strip()
                    if code_part:
                        for rule in self.language_rules:
                            if rule.matches(code_part):
                                findings.append(
                                    rule.create_finding(
                                        file_path=rel_str,
                                        line_num=line_num,
                                        snippet=masked_line[:80],
                                        analyzer="regex",
                                    )
                                )

        deduped = self.deduplicate_findings(findings)
        return deduped, lines_scanned

    @staticmethod
    def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
        """Merge findings reporting the same underlying issue at the same location."""
        seen: Dict[Tuple[str, int, str], Finding] = {}
        for f in findings:
            key = (f.location.file, f.location.line, f.rule_id)
            if key not in seen:
                seen[key] = f
            else:
                existing = seen[key]
                if f.analyzer == "python-ast" and existing.analyzer != "python-ast":
                    seen[key] = f
                elif f.confidence > existing.confidence:
                    seen[key] = f
        return list(seen.values())
