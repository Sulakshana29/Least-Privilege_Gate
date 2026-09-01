"""
Scan result model — the final output of a complete Cloud Policy Guard scan.

This model is produced by the security gate and passed to the reporter.
It contains everything needed to render either a console report or a
JSON report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from cloud_policy_guard.models.finding import Finding, Severity


class GateDecision(str, Enum):
    """
    The final security gate decision.

    PASS: No policy violations exceeded the configured threshold.
          CI/CD pipeline may continue. Exit code: 0.

    FAIL: One or more policy violations exceeded the threshold.
          CI/CD pipeline should be blocked. Exit code: 1.
    """

    PASS = "passed"
    FAIL = "failed"


@dataclass
class SeveritySummary:
    """Count of findings per severity level."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "info": self.info,
        }

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.info


@dataclass
class ScanResult:
    """
    The complete result of a Cloud Policy Guard scan.

    Produced by SecurityGate.evaluate() and consumed by reporters.

    Attributes:
        gate_decision:       PASS or FAIL.
        findings:            All findings from the rule engine.
        risk_score:          Numeric risk score (see docs/risk-model.md).
        severity_summary:    Count of findings per severity level.
        resources_scanned:   Total Terraform resources in the plan.
        iam_resources_found: Number of IAM-related resources.
        policies_analyzed:   Number of IAM policy documents analyzed.
        gate_reason:         Human-readable explanation of the gate decision.
        scan_timestamp:      UTC timestamp when the scan ran.
        terraform_plan_path: Path to the plan file that was scanned.
    """

    gate_decision: GateDecision
    findings: list[Finding] = field(default_factory=list)
    risk_score: int = 0
    severity_summary: SeveritySummary = field(default_factory=SeveritySummary)
    resources_scanned: int = 0
    iam_resources_found: int = 0
    policies_analyzed: int = 0
    gate_reason: str = ""
    scan_timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    terraform_plan_path: str = ""

    @property
    def passed(self) -> bool:
        return self.gate_decision == GateDecision.PASS

    @property
    def failed(self) -> bool:
        return self.gate_decision == GateDecision.FAIL

    @property
    def findings_by_severity(self) -> list[Finding]:
        """Return findings sorted highest severity first."""
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        return sorted(self.findings, key=lambda f: severity_order.get(f.severity, 99))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to the stable JSON report schema.

        Schema version is tracked in docs/risk-model.md.
        """
        return {
            "version": "0.1.0",
            "timestamp": self.scan_timestamp,
            "terraform_plan": self.terraform_plan_path,
            "status": self.gate_decision.value,
            "gate_reason": self.gate_reason,
            "risk_score": self.risk_score,
            "resources_scanned": self.resources_scanned,
            "iam_resources_found": self.iam_resources_found,
            "policies_analyzed": self.policies_analyzed,
            "severity_summary": self.severity_summary.to_dict(),
            "findings": [f.to_dict() for f in self.findings_by_severity],
        }
