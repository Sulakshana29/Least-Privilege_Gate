"""Tests for LP001 — Wildcard IAM Action."""

from cloud_policy_guard.models.finding import Severity
from cloud_policy_guard.rules.lp001_wildcard_action import LP001WildcardAction
from tests.conftest import make_policy, make_statement


class TestLP001WildcardAction:
    def setup_method(self):
        self.rule = LP001WildcardAction()

    # ── Positive cases (violations should be detected) ─────────────────────────

    def test_detects_wildcard_action_string(self):
        stmt = make_statement(actions=["*"], resources=["*"])
        policy = make_policy([stmt])
        findings = self.rule.evaluate(policy)
        assert len(findings) == 1
        assert findings[0].rule_id == "LP001"
        assert findings[0].severity == Severity.CRITICAL

    def test_detects_wildcard_in_list(self):
        stmt = make_statement(actions=["*"], resources=["arn:aws:s3:::my-bucket"])
        policy = make_policy([stmt])
        findings = self.rule.evaluate(policy)
        assert len(findings) == 1

    def test_detects_multiple_statements_each_with_wildcard(self):
        stmts = [
            make_statement(actions=["*"], resources=["*"]),
            make_statement(actions=["*"], resources=["arn:aws:s3:::bucket"]),
        ]
        policy = make_policy(stmts)
        findings = self.rule.evaluate(policy)
        assert len(findings) == 2

    def test_finding_contains_resource_address(self):
        stmt = make_statement(actions=["*"], resources=["*"])
        policy = make_policy([stmt], resource_address="aws_iam_policy.dangerous")
        findings = self.rule.evaluate(policy)
        assert findings[0].resource_address == "aws_iam_policy.dangerous"

    def test_finding_contains_evidence(self):
        stmt = make_statement(actions=["*"], resources=["*"])
        policy = make_policy([stmt])
        findings = self.rule.evaluate(policy)
        assert "*" in findings[0].evidence

    # ── Negative cases (clean policies should not trigger) ─────────────────────

    def test_no_finding_for_specific_actions(self):
        stmt = make_statement(actions=["s3:GetObject", "s3:PutObject"], resources=["*"])
        policy = make_policy([stmt])
        findings = self.rule.evaluate(policy)
        assert len(findings) == 0

    def test_no_finding_for_deny_with_wildcard(self):
        """Effect: Deny with Action: '*' is a restrictive control, not a grant."""
        stmt = make_statement(effect="Deny", actions=["*"], resources=["*"])
        policy = make_policy([stmt])
        findings = self.rule.evaluate(policy)
        assert len(findings) == 0

    def test_no_finding_for_empty_policy(self):
        policy = make_policy([])
        findings = self.rule.evaluate(policy)
        assert len(findings) == 0

    def test_no_finding_for_empty_actions(self):
        stmt = make_statement(actions=[], resources=["*"])
        policy = make_policy([stmt])
        findings = self.rule.evaluate(policy)
        assert len(findings) == 0
