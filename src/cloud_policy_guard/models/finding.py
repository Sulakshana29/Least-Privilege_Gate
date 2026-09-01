"""
Finding model — the core output unit of every security rule.

Every rule produces zero or more Finding objects. These are collected,
scored, and reported by the rest of the pipeline.

Design notes:
- Severity is an Enum so comparisons are safe (no typos, no case issues).
- Finding is a frozen dataclass — immutable once created, hashable.
- to_dict() produces the stable JSON schema documented in docs/risk-model.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """
    Security finding severity levels.

    Ordered from most to least severe — comparison operators work naturally:
        Severity.CRITICAL > Severity.HIGH  # True
        Severity.LOW < Severity.MEDIUM     # True

    Inherits from str so serialization to JSON is automatic ("critical", etc.).
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return _SEVERITY_ORDER[self] < _SEVERITY_ORDER[other]

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return _SEVERITY_ORDER[self] <= _SEVERITY_ORDER[other]

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return _SEVERITY_ORDER[self] > _SEVERITY_ORDER[other]

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return _SEVERITY_ORDER[self] >= _SEVERITY_ORDER[other]


# Higher number = higher severity (used for ordering)
_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(frozen=True)
class Finding:
    """
    A single security finding produced by a rule evaluation.

    Attributes:
        rule_id:          Unique rule identifier (e.g., "LP001").
        title:            Short human-readable title (e.g., "Wildcard IAM Action").
        severity:         Severity level of this finding.
        resource_address: Terraform resource address (e.g., "aws_iam_policy.app").
        resource_type:    Terraform resource type (e.g., "aws_iam_policy").
        description:      Full explanation of what was found and why it matters.
        evidence:         The specific policy fragment that triggered this finding.
        remediation:      Actionable advice on how to fix the issue.
    """

    rule_id: str
    title: str
    severity: Severity
    resource_address: str
    resource_type: str
    description: str
    evidence: str
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a stable JSON-compatible dictionary.

        The schema here is documented in docs/risk-model.md and must not
        change without a version bump.
        """
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "resource_address": self.resource_address,
            "resource_type": self.resource_type,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }

    def __str__(self) -> str:
        return f"[{self.severity.value.upper()}] {self.rule_id} — {self.title} ({self.resource_address})"
