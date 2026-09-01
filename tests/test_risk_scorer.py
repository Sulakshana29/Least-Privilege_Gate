"""Tests for the Risk Scorer."""

from cloud_policy_guard.models.finding import Severity
from cloud_policy_guard.risk.scorer import SEVERITY_WEIGHTS, RiskScorer
from tests.conftest import make_policy, make_statement

from cloud_policy_guard.rules.lp001_wildcard_action import LP001WildcardAction
from cloud_policy_guard.rules.lp002_wildcard_resource import LP002WildcardResource


def _finding(severity: Severity):
    stmt = make_statement(actions=["s3:GetObject"], resources=["*"])
    policy = make_policy([stmt])
    from cloud_policy_guard.models.finding import Finding
    return Finding(
        rule_id="TEST", title="Test", severity=severity,
        resource_address="test", resource_type="test",
        description="", evidence="", remediation="",
    )


class TestRiskScorer:
    def setup_method(self):
        self.scorer = RiskScorer()

    def test_empty_findings_returns_zero(self):
        score = self.scorer.calculate([])
        assert score.total == 0
        assert score.summary.total == 0

    def test_single_critical_finding(self):
        score = self.scorer.calculate([_finding(Severity.CRITICAL)])
        assert score.total == SEVERITY_WEIGHTS[Severity.CRITICAL]
        assert score.summary.critical == 1

    def test_single_high_finding(self):
        score = self.scorer.calculate([_finding(Severity.HIGH)])
        assert score.total == SEVERITY_WEIGHTS[Severity.HIGH]
        assert score.summary.high == 1

    def test_single_medium_finding(self):
        score = self.scorer.calculate([_finding(Severity.MEDIUM)])
        assert score.total == SEVERITY_WEIGHTS[Severity.MEDIUM]

    def test_single_low_finding(self):
        score = self.scorer.calculate([_finding(Severity.LOW)])
        assert score.total == SEVERITY_WEIGHTS[Severity.LOW]

    def test_info_finding_scores_zero(self):
        score = self.scorer.calculate([_finding(Severity.INFO)])
        assert score.total == 0

    def test_mixed_severity_scores_sum_correctly(self):
        findings = [
            _finding(Severity.CRITICAL),  # 10
            _finding(Severity.HIGH),       # 7
            _finding(Severity.HIGH),       # 7
            _finding(Severity.MEDIUM),     # 4
        ]
        score = self.scorer.calculate(findings)
        expected = 10 + 7 + 7 + 4
        assert score.total == expected

    def test_severity_summary_counts_correctly(self):
        findings = [
            _finding(Severity.CRITICAL),
            _finding(Severity.HIGH),
            _finding(Severity.HIGH),
            _finding(Severity.MEDIUM),
            _finding(Severity.LOW),
        ]
        score = self.scorer.calculate(findings)
        assert score.summary.critical == 1
        assert score.summary.high == 2
        assert score.summary.medium == 1
        assert score.summary.low == 1
        assert score.summary.info == 0

    def test_score_is_additive(self):
        one_critical = self.scorer.calculate([_finding(Severity.CRITICAL)]).total
        two_critical = self.scorer.calculate([_finding(Severity.CRITICAL)] * 2).total
        assert two_critical == one_critical * 2

    def test_weights_document_is_consistent(self):
        """Ensure weights match documented values in the module."""
        assert SEVERITY_WEIGHTS[Severity.CRITICAL] == 10
        assert SEVERITY_WEIGHTS[Severity.HIGH] == 7
        assert SEVERITY_WEIGHTS[Severity.MEDIUM] == 4
        assert SEVERITY_WEIGHTS[Severity.LOW] == 1
        assert SEVERITY_WEIGHTS[Severity.INFO] == 0
