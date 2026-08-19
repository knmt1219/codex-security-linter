"""Git diff parsing, smart hunk prioritization, and metric computation."""

import re
from typing import List
from .patterns import COMMON_SECRET_PATTERNS, LANGUAGE_VULN_PATTERNS, MALWARE_PATTERNS


def count_scanned_lines(diff_text: str) -> int:
    """Count total added code lines analyzed from diff."""
    return sum(1 for line in diff_text.splitlines() if line.startswith('+') and not line.startswith('+++'))


def chunk_diff_smart(diff_text: str, max_chars: int = 12000) -> str:
    """Prioritize high-risk file diffs when diff length exceeds context limits."""
    if len(diff_text) <= max_chars:
        return diff_text

    file_diffs = re.split(r'(?=diff --git )', diff_text)
    prioritized_hunks: List[str] = []
    other_hunks: List[str] = []

    high_risk_exts = ('.py', '.go', '.rs', '.js', '.ts', '.java', '.php', '.c', '.cpp', '.h', '.hpp', '.rb', '.sh', '.yml', '.yaml')

    for chunk in file_diffs:
        chunk = chunk.strip()
        if not chunk:
            continue
        first_line = chunk.splitlines()[0] if chunk.splitlines() else ""
        is_high_risk = any(first_line.endswith(ext) or ext in first_line for ext in high_risk_exts)
        has_suspicious_patterns = any(
            re.search(p, chunk) for p, _, _ in COMMON_SECRET_PATTERNS + MALWARE_PATTERNS + LANGUAGE_VULN_PATTERNS
        )

        if is_high_risk or has_suspicious_patterns:
            prioritized_hunks.append(chunk)
        else:
            other_hunks.append(chunk)

    selected: List[str] = []
    current_length = 0

    for h in prioritized_hunks + other_hunks:
        if current_length + len(h) <= max_chars:
            selected.append(h)
            current_length += len(h)
        else:
            remaining = max_chars - current_length
            if remaining > 200:
                selected.append(h[:remaining] + "\n... [diff truncated for length]")
            break

    return "\n\n".join(selected) if selected else diff_text[:max_chars]
