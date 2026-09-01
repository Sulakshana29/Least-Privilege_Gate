"""
Security Gate
=============
Makes the final PASS/FAIL decision for a Cloud Policy Guard scan.

The security gate is the component that actually blocks CI/CD pipelines.
It evaluates findings against configurable thresholds and returns a decision.

How it works in CI/CD:
    cloud-policy-guard scan --terraform-plan plan.json
    exit_code=$?
    # exit_code=0 → PASS → pipeline continues
    # exit_code=1 → FAIL → pipeline stops

Gate configuration:
    fail_on:        The minimum severity that causes a FAIL.
                    "critical" → only CRITICAL findings trigger FAIL
                    "high"     → CRITICAL or HIGH findings trigger FAIL
                    "medium"   → CRITICAL, HIGH, or MEDIUM findings trigger FAIL
                    "low"      → any finding (except INFO) triggers FAIL

    max_risk_score: Optional. If the total risk score exceeds this number,
                    FAIL regardless of individual severities.
                    Useful for: "FAIL if the combined risk is too high even
                    without a single CRITICAL finding."

Decision priority:
    1. If any finding severity >= fail_on threshold → FAIL
    2. If risk score > max_risk_score (when configured) → FAIL
    3. Otherwise → PASS
"""

from __future__ import annotations

import logging

from cloud_policy_guard.models.finding import Severity
from cloud_policy_guard.models.scan_result import GateDecision, ScanResult, SeveritySummary
from cloud_policy_guard.risk.scorer import RiskScore

logger = logging.getLogger(__name__)

# Map CLI string to Severity enum for the fail_on threshold
SEVERITY_THRESHOLD_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class SecurityGate:
    """
    Evaluates risk score and findings to produce a PASS/FAIL gate decision.

    Usage:
        gate = SecurityGate(fail_on="critical", max_risk_score=None)
        result = gate.evaluate(
            findings=findings,
            risk_score=score,
            resources_scanned=14,
            iam_resources_found=5,
            policies_analyzed=5,
            terraform_plan_path="plan.json",
        )
        # result.gate_decision → GateDecision.PASS or GateDecision.FAIL
        # result.gate_reason   → human-readable explanation
    """

    def __init__(
        self,
        fail_on: str = "critical",
        max_risk_score: int | None = None,
    ) -> None:
        """
        Configure the security gate.

        Args:
            fail_on:        Severity threshold for FAIL. Defaults to "critical".
            max_risk_score: Optional upper bound on risk score before FAIL.
        """
        fail_on_lower = fail_on.lower()
        if fail_on_lower not in SEVERITY_THRESHOLD_MAP:
            raise ValueError(
                f"Invalid fail_on value: '{fail_on}'. "
                f"Must be one of: {list(SEVERITY_THRESHOLD_MAP.keys())}"
            )

        self._fail_threshold: Severity = SEVERITY_THRESHOLD_MAP[fail_on_lower]
        self._max_risk_score = max_risk_score

        logger.debug(
            "SecurityGate configured: fail_on=%s, max_risk_score=%s",
            self._fail_threshold.value,
            max_risk_score,
        )

    def evaluate(
        self,
        findings: list,
        risk_score: RiskScore,
        resources_scanned: int = 0,
        iam_resources_found: int = 0,
        policies_analyzed: int = 0,
        terraform_plan_path: str = "",
    ) -> ScanResult:
        """
        Evaluate findings and risk score, return a complete ScanResult.

        Args:
            findings:           All findings from the rule engine.
            risk_score:         Calculated RiskScore from RiskScorer.
            resources_scanned:  Total resource count from the plan.
            iam_resources_found: IAM resource count.
            policies_analyzed:  Number of policies that were analyzed.
            terraform_plan_path: Source plan file path (for reporting).

        Returns:
            ScanResult with gate_decision, gate_reason, and all scan metadata.
        """
        decision, reason = self._decide(findings, risk_score)

        logger.info("Gate decision: %s — %s", decision.value.upper(), reason)

        return ScanResult(
            gate_decision=decision,
            findings=findings,
            risk_score=risk_score.total,
            severity_summary=risk_score.summary,
            resources_scanned=resources_scanned,
            iam_resources_found=iam_resources_found,
            policies_analyzed=policies_analyzed,
            gate_reason=reason,
            terraform_plan_path=terraform_plan_path,
        )

    # ──────────────────────────────────────────────────────────────────────────

    def _decide(
        self, findings: list, risk_score: RiskScore
    ) -> tuple[GateDecision, str]:
        """Apply gate rules and return (decision, reason)."""

        # Rule 1: Check for findings that meet or exceed the severity threshold
        blocking_findings = [
            f for f in findings if f.severity >= self._fail_threshold
        ]

        if blocking_findings:
            count = len(blocking_findings)
            severities = ", ".join(
                sorted(
                    {f.severity.value.upper() for f in blocking_findings},
                    key=lambda s: list(SEVERITY_THRESHOLD_MAP.keys()).index(s.lower()),
                )
            )
            reason = (
                f"{count} finding(s) at or above threshold "
                f"'{self._fail_threshold.value}' ({severities}). "
                f"Risk score: {risk_score.total}."
            )
            return GateDecision.FAIL, reason

        # Rule 2: Check risk score ceiling
        if self._max_risk_score is not None and risk_score.total > self._max_risk_score:
            reason = (
                f"Risk score {risk_score.total} exceeds maximum allowed score "
                f"{self._max_risk_score}."
            )
            return GateDecision.FAIL, reason

        # All checks passed
        if not findings:
            reason = "No security findings detected."
        else:
            reason = (
                f"{len(findings)} finding(s) found, none at or above threshold "
                f"'{self._fail_threshold.value}'. Risk score: {risk_score.total}."
            )

        return GateDecision.PASS, reason
