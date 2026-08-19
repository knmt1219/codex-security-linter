"""Base abstractions for extensible security analysis rules."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Pattern
import re

from ..models import Finding, Location, RuleCategory, Severity


@dataclass
class Rule:
    """An atomic, deterministic security inspection rule."""
    id: str
    name: str
    description: str
    category: RuleCategory
    severity: Severity
    risk_score: float
    confidence: float
    cwe: Optional[str] = None
    supported_languages: List[str] = field(default_factory=list)
    remediation: Optional[str] = None
    analyzer_type: str = "regex"
    pattern: Optional[Pattern[str]] = None
    enabled: bool = True

    def matches(self, text: str) -> bool:
        """Check if regex pattern matches given text."""
        if not self.enabled or not self.pattern:
            return False
        return bool(self.pattern.search(text))

    def create_finding(
        self,
        file_path: str,
        line_num: int,
        snippet: str,
        evidence: str = "",
        language: Optional[str] = None,
        analyzer: Optional[str] = None,
        column: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Finding:
        """Construct a strongly-typed Finding instance from this rule."""
        return Finding(
            rule_id=self.id,
            title=self.name,
            description=self.description,
            severity=self.severity,
            confidence=self.confidence,
            category=self.category,
            location=Location(file=file_path, line=line_num, column=column),
            snippet=snippet,
            evidence=evidence,
            language=language or (self.supported_languages[0] if self.supported_languages else None),
            remediation=self.remediation,
            analyzer=analyzer or self.analyzer_type,
            cwe=self.cwe,
            risk_score=self.risk_score,
            metadata=metadata or {},
        )
