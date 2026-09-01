"""Tests for LP005 — Excessive Service Permissions."""

from cloud_policy_guard.models.finding import Severity
from cloud_policy_guard.rules.lp005_excessive_service_perms import LP005ExcessiveServicePerms
from tests.conftest import make_policy, make_statement


class TestLP005ExcessiveServicePerms:
    def setup_method(self):
        self.rule = LP005ExcessiveServicePerms()

    # ── HIGH severity services ─────────────────────────────────────────────────

    def test_iam_star_is_high(self):
        stmt = make_statement(actions=["iam:*"], resources=["*"])
        findings = self.rule.evaluate(make_policy([stmt]))
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_sts_star_is_high(self):
        stmt = make_statement(actions=["sts:*"], resources=["*"])
        findings = self.rule.evaluate(make_policy([stmt]))
        assert findings[0].severity == Severity.HIGH

    def test_kms_star_is_high(self):
        stmt = make_statement(actions=["kms:*"], resources=["*"])
        findings = self.rule.evaluate(make_policy([stmt]))
        assert findings[0].severity == Severity.HIGH

    def test_secretsmanager_star_is_high(self):
        stmt = make_statement(actions=["secretsmanager:*"], resources=["*"])
        findings = self.rule.evaluate(make_policy([stmt]))
        assert findings[0].severity == Severity.HIGH

    # ── MEDIUM severity services ───────────────────────────────────────────────

    def test_s3_star_is_medium(self):
        stmt = make_statement(actions=["s3:*"], resources=["*"])
        findings = self.rule.evaluate(make_policy([stmt]))
        assert findings[0].severity == Severity.MEDIUM

    def test_ec2_star_is_medium(self):
        stmt = make_statement(actions=["ec2:*"], resources=["*"])
        findings = self.rule.evaluate(make_policy([stmt]))
        assert findings[0].severity == Severity.MEDIUM

    def test_lambda_star_is_medium(self):
        stmt = make_statement(actions=["lambda:*"], resources=["*"])
        findings = self.rule.evaluate(make_policy([stmt]))
        assert findings[0].severity == Severity.MEDIUM

    # ── LOW severity services ──────────────────────────────────────────────────

    def test_logs_star_is_low(self):
        stmt = make_statement(actions=["logs:*"], resources=["*"])
        findings = self.rule.evaluate(make_policy([stmt]))
        assert findings[0].severity == Severity.LOW

    def test_cloudwatch_star_is_low(self):
        stmt = make_statement(actions=["cloudwatch:*"], resources=["*"])
        findings = self.rule.evaluate(make_policy([stmt]))
        assert findings[0].severity == Severity.LOW

    # ── Multiple service wildcards ─────────────────────────────────────────────

    def test_multiple_wildcards_produce_multiple_findings(self):
        stmt = make_statement(actions=["s3:*", "ec2:*", "iam:*"], resources=["*"])
        findings = self.rule.evaluate(make_policy([stmt]))
        assert len(findings) == 3

    # ── Negative cases ─────────────────────────────────────────────────────────

    def test_no_finding_for_specific_actions(self):
        stmt = make_statement(actions=["s3:GetObject", "s3:PutObject"], resources=["*"])
        findings = self.rule.evaluate(make_policy([stmt]))
        assert len(findings) == 0

    def test_no_finding_for_unknown_service_wildcard(self):
        """Unknown services are not in our registry — should not fire."""
        stmt = make_statement(actions=["someservice:*"], resources=["*"])
        findings = self.rule.evaluate(make_policy([stmt]))
        assert len(findings) == 0

    def test_skips_bare_wildcard_action(self):
        """Bare '*' is Action: * — LP001 handles that, not LP005."""
        stmt = make_statement(actions=["*"], resources=["*"])
        findings = self.rule.evaluate(make_policy([stmt]))
        assert len(findings) == 0

    def test_no_finding_for_deny_statement(self):
        stmt = make_statement(effect="Deny", actions=["s3:*"], resources=["*"])
        findings = self.rule.evaluate(make_policy([stmt]))
        assert len(findings) == 0
