"""
Base rule classes for Cloud Policy Guard.

Every security rule must extend one of these abstract base classes.

Design:
- BaseRule      → for identity-based policy analysis (LP001–LP005)
- BaseTrustRule → for trust-policy analysis (LP006)

Keeping them separate avoids passing IAMPolicy objects to a trust rule
and vice versa, which would be a type error that's easy to miss.

Adding a new rule:
1. Create a new file in rules/  (e.g., lp007_missing_mfa_condition.py)
2. Define a class extending BaseRule (or BaseTrustRule)
3. Set rule_id, title, description, default_severity as class attributes
4. Implement the evaluate() method
5. Register it in analyzer/registry.py

The rule engine will call evaluate() for every IAM policy in the plan.
Return an empty list if the policy is clean. Return one Finding per violation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from cloud_policy_guard.models.finding import Finding, Severity
from cloud_policy_guard.models.iam import IAMPolicy, TrustPolicy


class BaseRule(ABC):
    """
    Abstract base class for identity-based policy rules (LP001–LP005).

    Class attributes (must be set on subclasses):
        rule_id:          Unique identifier, e.g. "LP001"
        title:            Short display name, e.g. "Wildcard IAM Action"
        description:      Full description of what this rule checks
        default_severity: Default Severity if not overridden per-finding
    """

    rule_id: str = ""
    title: str = ""
    description: str = ""
    default_severity: Severity = Severity.MEDIUM

    @abstractmethod
    def evaluate(self, policy: IAMPolicy) -> list[Finding]:
        """
        Evaluate a single IAM policy for violations of this rule.

        Args:
            policy: The normalized IAM policy to analyze.

        Returns:
            List of Finding objects — empty if the policy is clean.
            Return one Finding per distinct violation found.
        """
        ...

    def _make_finding(
        self,
        policy: IAMPolicy,
        description: str,
        evidence: str,
        remediation: str,
        severity: Severity | None = None,
    ) -> Finding:
        """
        Convenience method to create a Finding with this rule's metadata.

        Args:
            policy:      The policy being analyzed (provides resource info).
            description: Specific description for this finding instance.
            evidence:    The exact policy fragment that triggered this finding.
            remediation: Specific remediation advice for this violation.
            severity:    Override the default severity if needed.
        """
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            severity=severity if severity is not None else self.default_severity,
            resource_address=policy.resource_address,
            resource_type=policy.resource_type,
            description=description,
            evidence=evidence,
            remediation=remediation,
        )


class BaseTrustRule(ABC):
    """
    Abstract base class for trust-policy rules (LP006).

    Trust policies control WHO can assume an IAM role. They are separate
    from identity-based policies and require different analysis logic.
    """

    rule_id: str = ""
    title: str = ""
    description: str = ""
    default_severity: Severity = Severity.HIGH

    @abstractmethod
    def evaluate(self, trust_policy: TrustPolicy) -> list[Finding]:
        """
        Evaluate a trust policy for violations.

        Args:
            trust_policy: The normalized trust policy to analyze.

        Returns:
            List of Finding objects — empty if the trust policy is clean.
        """
        ...

    def _make_finding(
        self,
        trust_policy: TrustPolicy,
        description: str,
        evidence: str,
        remediation: str,
        severity: Severity | None = None,
    ) -> Finding:
        """Convenience method to create a Finding with this rule's metadata."""
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            severity=severity if severity is not None else self.default_severity,
            resource_address=trust_policy.resource_address,
            resource_type=trust_policy.resource_type,
            description=description,
            evidence=evidence,
            remediation=remediation,
        )
