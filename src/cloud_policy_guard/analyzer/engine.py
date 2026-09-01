"""
Analysis Engine
===============
Orchestrates the rule engine — runs all registered rules against all
extracted IAM policies and trust policies from a Terraform plan.

This is the heart of Cloud Policy Guard's analysis pipeline.

Pipeline position:
    IAMExtractor → AnalysisEngine → RiskScorer → SecurityGate

The engine is deliberately simple:
- No caching
- No parallel execution
- No stateful state between rule evaluations

Each rule evaluation is pure: given a policy, return findings.
The engine just collects and returns all findings.
"""

from __future__ import annotations

import logging

from cloud_policy_guard.analyzer.registry import RuleRegistry
from cloud_policy_guard.models.finding import Finding
from cloud_policy_guard.models.iam import IAMPolicy, TrustPolicy

logger = logging.getLogger(__name__)


class AnalysisEngine:
    """
    Runs all registered security rules against a set of IAM policies.

    Usage:
        registry = RuleRegistry()
        engine = AnalysisEngine(registry)
        findings = engine.analyze(iam_policies, trust_policies)
    """

    def __init__(self, registry: RuleRegistry) -> None:
        self._registry = registry

    def analyze(
        self,
        iam_policies: list[IAMPolicy],
        trust_policies: list[TrustPolicy],
    ) -> list[Finding]:
        """
        Run all rules against all policies and return the collected findings.

        Args:
            iam_policies:   Identity-based policies extracted from the plan.
            trust_policies: Trust policies (assume_role_policy) from aws_iam_role resources.

        Returns:
            All findings from all rules, unsorted.
            (Sorting by severity happens in ScanResult.findings_by_severity.)
        """
        findings: list[Finding] = []

        identity_rules = self._registry.get_identity_rules()
        trust_rules = self._registry.get_trust_rules()

        logger.info(
            "Running %d identity rules against %d policies",
            len(identity_rules),
            len(iam_policies),
        )

        # Run identity rules (LP001–LP005) against each IAM policy
        for policy in iam_policies:
            for rule in identity_rules:
                try:
                    rule_findings = rule.evaluate(policy)
                    findings.extend(rule_findings)
                    if rule_findings:
                        logger.debug(
                            "%s: %s found %d finding(s)",
                            policy.resource_address,
                            rule.rule_id,
                            len(rule_findings),
                        )
                except Exception as e:
                    # Never let a rule crash the whole scan
                    logger.error(
                        "Rule %s raised an unexpected error on %s: %s",
                        rule.rule_id,
                        policy.resource_address,
                        e,
                        exc_info=True,
                    )

        logger.info(
            "Running %d trust rules against %d trust policies",
            len(trust_rules),
            len(trust_policies),
        )

        # Run trust rules (LP006) against each trust policy
        for trust_policy in trust_policies:
            for rule in trust_rules:
                try:
                    rule_findings = rule.evaluate(trust_policy)
                    findings.extend(rule_findings)
                    if rule_findings:
                        logger.debug(
                            "%s: %s found %d finding(s)",
                            trust_policy.resource_address,
                            rule.rule_id,
                            len(rule_findings),
                        )
                except Exception as e:
                    logger.error(
                        "Trust rule %s raised an unexpected error on %s: %s",
                        rule.rule_id,
                        trust_policy.resource_address,
                        e,
                        exc_info=True,
                    )

        logger.info("Analysis complete: %d total findings", len(findings))
        return findings
