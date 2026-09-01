"""Tests for LP006 — Broad Trust Policy."""

from cloud_policy_guard.models.finding import Severity
from cloud_policy_guard.rules.lp006_broad_trust_policy import LP006BroadTrustPolicy
from tests.conftest import make_statement, make_trust_policy


class TestLP006BroadTrustPolicy:
    def setup_method(self):
        self.rule = LP006BroadTrustPolicy()

    # ── Critical cases ─────────────────────────────────────────────────────────

    def test_principal_star_is_critical(self):
        stmt = make_statement(effect="Allow", principals="*", actions=["sts:AssumeRole"])
        trust = make_trust_policy([stmt])
        findings = self.rule.evaluate(trust)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].rule_id == "LP006"

    def test_aws_star_principal_is_critical(self):
        stmt = make_statement(effect="Allow", principals={"AWS": "*"}, actions=["sts:AssumeRole"])
        trust = make_trust_policy([stmt])
        findings = self.rule.evaluate(trust)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_aws_star_in_list_is_critical(self):
        stmt = make_statement(effect="Allow", principals={"AWS": ["*"]}, actions=["sts:AssumeRole"])
        trust = make_trust_policy([stmt])
        findings = self.rule.evaluate(trust)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    # ── Medium cases ───────────────────────────────────────────────────────────

    def test_cross_account_without_condition_is_medium(self):
        stmt = make_statement(
            effect="Allow",
            principals={"AWS": "arn:aws:iam::987654321012:root"},
            actions=["sts:AssumeRole"],
            conditions=None,
        )
        trust = make_trust_policy([stmt])
        findings = self.rule.evaluate(trust)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert "confused deputy" in findings[0].remediation.lower()

    def test_cross_account_with_condition_is_ok(self):
        stmt = make_statement(
            effect="Allow",
            principals={"AWS": "arn:aws:iam::987654321012:root"},
            actions=["sts:AssumeRole"],
            conditions={"StringEquals": {"sts:ExternalId": "my-secret-id"}},
        )
        trust = make_trust_policy([stmt])
        findings = self.rule.evaluate(trust)
        assert len(findings) == 0

    # ── Negative cases ─────────────────────────────────────────────────────────

    def test_service_principal_is_ok(self):
        """Principal: {"Service": "lambda.amazonaws.com"} is expected and safe."""
        stmt = make_statement(
            effect="Allow",
            principals={"Service": "lambda.amazonaws.com"},
            actions=["sts:AssumeRole"],
        )
        trust = make_trust_policy([stmt])
        findings = self.rule.evaluate(trust)
        assert len(findings) == 0

    def test_specific_role_arn_without_cross_account_is_ok(self):
        """Same-account specific role ARNs without cross-account indicators are fine."""
        stmt = make_statement(
            effect="Allow",
            principals={"AWS": "arn:aws:iam::aws:role/some-role"},
            actions=["sts:AssumeRole"],
        )
        trust = make_trust_policy([stmt])
        findings = self.rule.evaluate(trust)
        assert len(findings) == 0

    def test_deny_statement_not_flagged(self):
        stmt = make_statement(effect="Deny", principals="*", actions=["sts:AssumeRole"])
        trust = make_trust_policy([stmt])
        findings = self.rule.evaluate(trust)
        assert len(findings) == 0

    def test_empty_trust_policy(self):
        trust = make_trust_policy([])
        findings = self.rule.evaluate(trust)
        assert len(findings) == 0

    def test_finding_contains_resource_address(self):
        stmt = make_statement(effect="Allow", principals="*", actions=["sts:AssumeRole"])
        trust = make_trust_policy([stmt], resource_address="aws_iam_role.dangerous")
        findings = self.rule.evaluate(trust)
        assert findings[0].resource_address == "aws_iam_role.dangerous"
