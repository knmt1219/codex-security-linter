"""Data models and type definitions for PR Security Linter findings and locations."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class Severity(str, Enum):
    """Vulnerability and risk severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        try:
            return cls[value.upper()]
        except KeyError:
            return cls.LOW

    @property
    def rank(self) -> int:
        ranks = {
            "INFO": 0,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }
        return ranks.get(self.value, 1)


class RuleCategory(str, Enum):
    """Categorization for security rules and findings."""
    SECRETS = "secrets"
    MALWARE = "malware"
    REVERSE_SHELL = "reverse_shell"
    COMMAND_EXECUTION = "command_execution"
    INJECTION = "injection"
    DESERIALIZATION = "deserialization"
    XSS = "xss"
    MEMORY_SAFETY = "memory_safety"
    GENERAL = "general"


@dataclass
class Location:
    """Source code location for an audit finding."""
    file: str
    line: int = 0
    column: Optional[int] = None
    end_line: Optional[int] = None
    end_column: Optional[int] = None

    def formatted(self) -> str:
        """Format as path:line or path:line:col."""
        if self.line > 0:
            if self.column is not None:
                return f"{self.file}:{self.line}:{self.column}"
            return f"{self.file}:{self.line}"
        return self.file


@dataclass
class Finding:
    """Structured representation of a security finding, leak, or dangerous API call."""
    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: float  # 0.0 to 1.0 (e.g. 0.99 = 99%)
    category: RuleCategory
    location: Location
    snippet: str = ""
    evidence: str = ""
    language: Optional[str] = None
    remediation: Optional[str] = None
    analyzer: str = "regex"  # "regex", "python-ast", "javascript", "ai"
    cwe: Optional[str] = None
    risk_score: float = 0.0  # Internal severity/risk score (0.0 to 10.0)
    cvss_vector: Optional[str] = None
    cvss_score: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary format for reporters and backward compatibility."""
        conf_str = f"{int(self.confidence * 100)}%" if 0.0 <= self.confidence <= 1.0 else f"{self.confidence}%"
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "type": self.title,
            "description": self.description,
            "score": f"{self.risk_score:.1f}" if self.risk_score else "N/A",
            "confidence": conf_str,
            "file": self.location.formatted(),
            "snippet": self.snippet,
            "category": self.category.value,
            "analyzer": self.analyzer,
            "cwe": self.cwe or "",
            "remediation": self.remediation or "",
            "line": self.location.line,
            "column": self.location.column,
            "cvss_vector": self.cvss_vector,
            "cvss_score": self.cvss_score,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        """Reconstruct a Finding object from a serialized dictionary."""
        file_field = str(data.get("file", "diff"))
        line = int(data.get("line", 0))
        col = data.get("column")
        if ":" in file_field and not file_field.startswith("http"):
            parts = file_field.rsplit(":", 1)
            file_name = parts[0]
            try:
                line = int(parts[1])
            except ValueError:
                file_name = file_field
        else:
            file_name = file_field

        conf_val = data.get("confidence", 0.95)
        if isinstance(conf_val, str) and "%" in conf_val:
            try:
                conf_float = float(conf_val.replace("%", "").strip()) / 100.0
            except ValueError:
                conf_float = 0.95
        elif isinstance(conf_val, (int, float)):
            conf_float = float(conf_val) if conf_val <= 1.0 else float(conf_val) / 100.0
        else:
            conf_float = 0.95

        try:
            risk = float(data.get("score", 0.0))
        except (ValueError, TypeError):
            risk = 0.0

        return cls(
            rule_id=str(data.get("rule_id", "GEN-001")),
            title=str(data.get("type", data.get("title", "Security Finding"))),
            description=str(data.get("description", data.get("type", ""))),
            severity=Severity.from_str(str(data.get("severity", "LOW"))),
            confidence=conf_float,
            category=RuleCategory(data.get("category", "general")) if data.get("category") in [c.value for c in RuleCategory] else RuleCategory.GENERAL,
            location=Location(file=file_name, line=line, column=int(col) if col is not None else None),
            snippet=str(data.get("snippet", "")),
            evidence=str(data.get("evidence", "")),
            language=data.get("language"),
            remediation=data.get("remediation"),
            analyzer=str(data.get("analyzer", "regex")),
            cwe=data.get("cwe"),
            risk_score=risk,
            cvss_vector=data.get("cvss_vector"),
            cvss_score=data.get("cvss_score"),
            metadata=data.get("metadata", {}),
        )
