"""Tests for the Security Gate."""

import pytest

from cloud_policy_guard.gate.security_gate import SecurityGate
from cloud_policy_guard.models.finding import Finding, Severity
from cloud_policy_guard.models.scan_result import GateDecision
from cloud_policy_guard.risk.scorer import RiskScore, RiskScorer
from cloud_policy_guard.models.scan_result import SeveritySummary


def _finding(severity: Severity) -> Finding:
    return Finding(
        rule_id="TEST", title="Test Finding", severity=severity,
        resource_address="test.resource", resource_type="aws_iam_policy",
        description="Test", evidence="test", remediation="fix it",
    )


def _score(findings):
    return RiskScorer().calculate(findings)


class TestSecurityGate:

    # ── PASS cases ────────────────────────────────────────────────────────────

    def test_pass_with_no_findings(self):
        gate = SecurityGate(fail_on="critical")
        result = gate.evaluate(findings=[], risk_score=_score([]))
        assert result.gate_decision == GateDecision.PASS
        assert result.passed is True

    def test_pass_with_only_low_findings_when_fail_on_critical(self):
        findings = [_finding(Severity.LOW), _finding(Severity.LOW)]
        gate = SecurityGate(fail_on="critical")
        result = gate.evaluate(findings=findings, risk_score=_score(findings))
        assert result.gate_decision == GateDecision.PASS

    def test_pass_with_medium_when_fail_on_high(self):
        findings = [_finding(Severity.MEDIUM)]
        gate = SecurityGate(fail_on="high")
        result = gate.evaluate(findings=findings, risk_score=_score(findings))
        assert result.gate_decision == GateDecision.PASS

    # ── FAIL cases ────────────────────────────────────────────────────────────

    def test_fail_on_critical_finding(self):
        findings = [_finding(Severity.CRITICAL)]
        gate = SecurityGate(fail_on="critical")
        result = gate.evaluate(findings=findings, risk_score=_score(findings))
        assert result.gate_decision == GateDecision.FAIL
        assert result.failed is True

    def test_fail_on_high_when_threshold_is_high(self):
        findings = [_finding(Severity.HIGH)]
        gate = SecurityGate(fail_on="high")
        result = gate.evaluate(findings=findings, risk_score=_score(findings))
        assert result.gate_decision == GateDecision.FAIL

    def test_fail_on_medium_when_threshold_is_medium(self):
        findings = [_finding(Severity.MEDIUM)]
        gate = SecurityGate(fail_on="medium")
        result = gate.evaluate(findings=findings, risk_score=_score(findings))
        assert result.gate_decision == GateDecision.FAIL

    def test_fail_on_low_when_threshold_is_low(self):
        findings = [_finding(Severity.LOW)]
        gate = SecurityGate(fail_on="low")
        result = gate.evaluate(findings=findings, risk_score=_score(findings))
        assert result.gate_decision == GateDecision.FAIL

    # ── max_risk_score ────────────────────────────────────────────────────────

    def test_fail_when_risk_score_exceeds_max(self):
        # 3 HIGH findings = 21 points, max is 20
        findings = [_finding(Severity.HIGH)] * 3
        gate = SecurityGate(fail_on="critical", max_risk_score=20)
        result = gate.evaluate(findings=findings, risk_score=_score(findings))
        assert result.gate_decision == GateDecision.FAIL
        assert "exceeds" in result.gate_reason

    def test_pass_when_risk_score_equals_max(self):
        # 2 HIGH findings = 14 points, max is 14
        findings = [_finding(Severity.HIGH)] * 2
        gate = SecurityGate(fail_on="critical", max_risk_score=14)
        result = gate.evaluate(findings=findings, risk_score=_score(findings))
        # Score equals max (not exceeds), should pass
        assert result.gate_decision == GateDecision.PASS

    # ── Gate reason ───────────────────────────────────────────────────────────

    def test_gate_reason_populated_on_fail(self):
        findings = [_finding(Severity.CRITICAL)]
        gate = SecurityGate(fail_on="critical")
        result = gate.evaluate(findings=findings, risk_score=_score(findings))
        assert len(result.gate_reason) > 0

    def test_gate_reason_populated_on_pass(self):
        gate = SecurityGate(fail_on="critical")
        result = gate.evaluate(findings=[], risk_score=_score([]))
        assert len(result.gate_reason) > 0

    # ── Invalid config ────────────────────────────────────────────────────────

    def test_invalid_fail_on_raises(self):
        with pytest.raises(ValueError, match="Invalid fail_on"):
            SecurityGate(fail_on="extreme")

    # ── Scan result metadata ──────────────────────────────────────────────────

    def test_scan_result_includes_counts(self):
        findings = [_finding(Severity.HIGH)]
        gate = SecurityGate(fail_on="critical")
        result = gate.evaluate(
            findings=findings,
            risk_score=_score(findings),
            resources_scanned=10,
            iam_resources_found=3,
            policies_analyzed=3,
        )
        assert result.resources_scanned == 10
        assert result.iam_resources_found == 3
        assert result.policies_analyzed == 3
