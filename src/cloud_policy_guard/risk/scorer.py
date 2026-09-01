"""
Risk Scorer
===========
Converts a list of security findings into a numeric risk score.

Risk Model (Cloud Policy Guard v0.1)
-------------------------------------
This is Cloud Policy Guard's own risk model. It is NOT an official AWS score,
CVSSv3, or any industry-standard scoring system. It is intentionally simple,
deterministic, and explainable.

Scoring weights:
    CRITICAL → 10 points per finding
    HIGH     →  7 points per finding
    MEDIUM   →  4 points per finding
    LOW      →  1 point  per finding
    INFO     →  0 points per finding

Total risk score = sum of (weight × count) for each severity level.

Why these weights?
- The ratio reflects real-world impact: a CRITICAL finding (e.g., Action: "*")
  is approximately 10× more impactful than a LOW finding (read-only wildcard resource).
- The weights are whole numbers for transparency and auditability.
- The score is additive — more findings = higher score, always.

Example:
    1 CRITICAL + 2 HIGH + 1 MEDIUM = 10 + 14 + 4 = 28

The score is used by SecurityGate as a secondary threshold:
    --max-risk-score 20 → FAIL if score > 20, regardless of individual severities.

Documentation: docs/risk-model.md
"""

from __future__ import annotations

from dataclasses import dataclass

from cloud_policy_guard.models.finding import Finding, Severity
from cloud_policy_guard.models.scan_result import SeveritySummary

# Severity → risk points mapping (documented above)
SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 7,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


@dataclass(frozen=True)
class RiskScore:
    """
    The calculated risk score for a scan.

    Attributes:
        total:    Total numeric risk score (sum of weighted findings).
        summary:  Count of findings per severity level.
    """

    total: int
    summary: SeveritySummary

    def __str__(self) -> str:
        s = self.summary
        return (
            f"Risk Score: {self.total} "
            f"(C:{s.critical} H:{s.high} M:{s.medium} L:{s.low} I:{s.info})"
        )


class RiskScorer:
    """
    Calculates the aggregate risk score from a list of findings.

    Usage:
        scorer = RiskScorer()
        score = scorer.calculate(findings)
        print(score.total)     # 28
        print(score.summary)   # SeveritySummary(critical=1, high=2, ...)
    """

    def calculate(self, findings: list[Finding]) -> RiskScore:
        """
        Calculate the risk score for a set of findings.

        Args:
            findings: All findings from the rule engine.

        Returns:
            A RiskScore with total points and per-severity breakdown.
        """
        summary = SeveritySummary()
        total = 0

        for finding in findings:
            weight = SEVERITY_WEIGHTS.get(finding.severity, 0)
            total += weight

            # Update the per-severity count
            match finding.severity:
                case Severity.CRITICAL:
                    summary.critical += 1
                case Severity.HIGH:
                    summary.high += 1
                case Severity.MEDIUM:
                    summary.medium += 1
                case Severity.LOW:
                    summary.low += 1
                case Severity.INFO:
                    summary.info += 1

        return RiskScore(total=total, summary=summary)
