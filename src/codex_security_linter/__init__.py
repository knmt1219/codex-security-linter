"""Codex Security Linter package (backward compatibility wrapper for pr_security_linter)."""

from pr_security_linter import __version__
from pr_security_linter.engine import SecurityEngine
from pr_security_linter.models import Finding, Location, RuleCategory, Severity
from pr_security_linter.scanner import main

__all__ = [
    "__version__",
    "SecurityEngine",
    "Finding",
    "Location",
    "Severity",
    "RuleCategory",
    "main",
]
