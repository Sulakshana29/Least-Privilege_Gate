"""Tests for LP003 — Administrative Permissions."""

from cloud_policy_guard.models.finding import Severity
from cloud_policy_guard.rules.lp003_admin_permissions import LP003AdminPermissions
from tests.conftest import make_policy, make_statement


class TestLP003AdminPermissions:
    def setup_method(self):
        self.rule = LP003AdminPermissions()

    # ── Inline admin detection ─────────────────────────────────────────────────

    def test_detects_action_star_plus_resource_star(self):
        stmt = make_statement(actions=["*"], resources=["*"])
        policy = make_policy([stmt])
        findings = self.rule.evaluate(policy)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].rule_id == "LP003"

    def test_no_finding_action_star_with_specific_resource(self):
        """LP003 requires BOTH Action:* AND Resource:* together."""
        stmt = make_statement(actions=["*"], resources=["arn:aws:s3:::my-bucket"])
        policy = make_policy([stmt])
        # LP001 fires for this, but LP003 should not (no full admin combo)
        findings = self.rule.evaluate(policy)
        assert len(findings) == 0

    # ── Managed policy attachment detection ───────────────────────────────────

    def test_detects_administrator_access_attachment(self):
        policy = make_policy(
            statements=[],
            resource_address="aws_iam_role_policy_attachment.admin",
            resource_type="aws_iam_role_policy_attachment",
            policy_name="arn:aws:iam::aws:policy/AdministratorAccess",
        )
        findings = self.rule.evaluate(policy)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert "AdministratorAccess" in findings[0].evidence

    def test_detects_iam_full_access_attachment(self):
        policy = make_policy(
            statements=[],
            resource_type="aws_iam_role_policy_attachment",
            policy_name="arn:aws:iam::aws:policy/IAMFullAccess",
        )
        findings = self.rule.evaluate(policy)
        assert len(findings) == 1

    def test_detects_power_user_access_attachment(self):
        policy = make_policy(
            statements=[],
            resource_type="aws_iam_role_policy_attachment",
            policy_name="arn:aws:iam::aws:policy/PowerUserAccess",
        )
        findings = self.rule.evaluate(policy)
        assert len(findings) == 1

    def test_no_finding_for_safe_managed_policy(self):
        policy = make_policy(
            statements=[],
            resource_type="aws_iam_role_policy_attachment",
            policy_name="arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
        )
        findings = self.rule.evaluate(policy)
        assert len(findings) == 0

    def test_no_finding_for_clean_inline_policy(self):
        stmt = make_statement(actions=["s3:GetObject"], resources=["arn:aws:s3:::bucket/*"])
        policy = make_policy([stmt])
        findings = self.rule.evaluate(policy)
        assert len(findings) == 0

    def test_deny_statement_not_flagged(self):
        stmt = make_statement(effect="Deny", actions=["*"], resources=["*"])
        policy = make_policy([stmt])
        findings = self.rule.evaluate(policy)
        assert len(findings) == 0
