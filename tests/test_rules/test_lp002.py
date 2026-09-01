"""Tests for LP002 — Wildcard Resource (context-aware severity)."""

from cloud_policy_guard.models.finding import Severity
from cloud_policy_guard.rules.lp002_wildcard_resource import LP002WildcardResource
from tests.conftest import make_policy, make_statement


class TestLP002WildcardResource:
    def setup_method(self):
        self.rule = LP002WildcardResource()

    # ── Severity context tests ─────────────────────────────────────────────────

    def test_high_severity_for_iam_actions_with_wildcard_resource(self):
        stmt = make_statement(actions=["iam:PassRole"], resources=["*"])
        policy = make_policy([stmt])
        findings = self.rule.evaluate(policy)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_high_severity_for_kms_actions_with_wildcard_resource(self):
        stmt = make_statement(actions=["kms:Decrypt", "kms:Encrypt"], resources=["*"])
        policy = make_policy([stmt])
        findings = self.rule.evaluate(policy)
        assert findings[0].severity == Severity.HIGH

    def test_medium_severity_for_write_actions(self):
        stmt = make_statement(actions=["s3:PutObject", "s3:DeleteObject"], resources=["*"])
        policy = make_policy([stmt])
        findings = self.rule.evaluate(policy)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_low_severity_for_read_only_actions(self):
        stmt = make_statement(actions=["s3:GetObject", "s3:ListBucket"], resources=["*"])
        policy = make_policy([stmt])
        findings = self.rule.evaluate(policy)
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW

    # ── Negative cases ─────────────────────────────────────────────────────────

    def test_no_finding_when_resource_is_specific_arn(self):
        stmt = make_statement(
            actions=["s3:GetObject"],
            resources=["arn:aws:s3:::my-bucket/*"]
        )
        policy = make_policy([stmt])
        findings = self.rule.evaluate(policy)
        assert len(findings) == 0

    def test_skips_when_action_is_also_wildcard(self):
        """LP001 handles Action:* already — LP002 should not double-count."""
        stmt = make_statement(actions=["*"], resources=["*"])
        policy = make_policy([stmt])
        findings = self.rule.evaluate(policy)
        assert len(findings) == 0

    def test_no_finding_for_deny_statement(self):
        stmt = make_statement(effect="Deny", actions=["s3:GetObject"], resources=["*"])
        policy = make_policy([stmt])
        findings = self.rule.evaluate(policy)
        assert len(findings) == 0

    def test_no_finding_for_empty_policy(self):
        policy = make_policy([])
        findings = self.rule.evaluate(policy)
        assert len(findings) == 0

    def test_finding_includes_resource_address(self):
        stmt = make_statement(actions=["iam:PassRole"], resources=["*"])
        policy = make_policy([stmt], resource_address="aws_iam_role_policy.dangerous")
        findings = self.rule.evaluate(policy)
        assert findings[0].resource_address == "aws_iam_role_policy.dangerous"

    def test_sts_actions_rated_high(self):
        stmt = make_statement(actions=["sts:AssumeRole"], resources=["*"])
        policy = make_policy([stmt])
        findings = self.rule.evaluate(policy)
        assert findings[0].severity == Severity.HIGH
