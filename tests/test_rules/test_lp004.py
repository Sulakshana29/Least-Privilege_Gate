"""Tests for LP004 — Sensitive IAM Actions."""

from cloud_policy_guard.models.finding import Severity
from cloud_policy_guard.rules.lp004_sensitive_iam_actions import LP004SensitiveIAMActions
from tests.conftest import make_policy, make_statement


class TestLP004SensitiveIAMActions:
    def setup_method(self):
        self.rule = LP004SensitiveIAMActions()

    # ── Positive cases ─────────────────────────────────────────────────────────

    def test_detects_iam_pass_role(self):
        stmt = make_statement(actions=["iam:PassRole"], resources=["*"])
        policy = make_policy([stmt])
        findings = self.rule.evaluate(policy)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "iam:PassRole" in findings[0].description

    def test_detects_iam_create_access_key(self):
        stmt = make_statement(actions=["iam:CreateAccessKey"], resources=["*"])
        policy = make_policy([stmt])
        findings = self.rule.evaluate(policy)
        assert len(findings) == 1
        assert "CreateAccessKey" in findings[0].description

    def test_detects_iam_attach_role_policy(self):
        stmt = make_statement(actions=["iam:AttachRolePolicy"], resources=["*"])
        policy = make_policy([stmt])
        findings = self.rule.evaluate(policy)
        assert len(findings) == 1

    def test_detects_iam_put_role_policy(self):
        stmt = make_statement(actions=["iam:PutRolePolicy"], resources=["*"])
        policy = make_policy([stmt])
        findings = self.rule.evaluate(policy)
        assert len(findings) == 1

    def test_detects_iam_update_assume_role_policy(self):
        stmt = make_statement(actions=["iam:UpdateAssumeRolePolicy"], resources=["*"])
        policy = make_policy([stmt])
        findings = self.rule.evaluate(policy)
        assert len(findings) == 1

    def test_detects_sts_assume_role(self):
        stmt = make_statement(actions=["sts:AssumeRole"], resources=["*"])
        policy = make_policy([stmt])
        findings = self.rule.evaluate(policy)
        assert len(findings) == 1

    def test_multiple_sensitive_actions_produce_multiple_findings(self):
        stmt = make_statement(
            actions=["iam:PassRole", "iam:CreateAccessKey", "iam:AttachRolePolicy"],
            resources=["*"]
        )
        policy = make_policy([stmt])
        findings = self.rule.evaluate(policy)
        assert len(findings) == 3

    def test_finding_contains_remediation(self):
        stmt = make_statement(actions=["iam:PassRole"], resources=["*"])
        policy = make_policy([stmt])
        findings = self.rule.evaluate(policy)
        assert len(findings[0].remediation) > 0

    # ── Negative cases ─────────────────────────────────────────────────────────

    def test_no_finding_for_safe_iam_actions(self):
        stmt = make_statement(
            actions=["iam:GetRole", "iam:ListRoles", "iam:GetPolicy"],
            resources=["*"]
        )
        policy = make_policy([stmt])
        findings = self.rule.evaluate(policy)
        assert len(findings) == 0

    def test_skips_wildcard_action(self):
        """Wildcard action is already covered by LP001 — LP004 should skip."""
        stmt = make_statement(actions=["*"], resources=["*"])
        policy = make_policy([stmt])
        findings = self.rule.evaluate(policy)
        assert len(findings) == 0

    def test_no_finding_for_deny_statement(self):
        stmt = make_statement(effect="Deny", actions=["iam:PassRole"], resources=["*"])
        policy = make_policy([stmt])
        findings = self.rule.evaluate(policy)
        assert len(findings) == 0

    def test_no_finding_for_empty_policy(self):
        findings = self.rule.evaluate(make_policy([]))
        assert len(findings) == 0

    def test_finding_evidence_contains_action(self):
        stmt = make_statement(actions=["iam:CreatePolicyVersion"], resources=["*"])
        policy = make_policy([stmt])
        findings = self.rule.evaluate(policy)
        assert "iam:CreatePolicyVersion" in findings[0].evidence
