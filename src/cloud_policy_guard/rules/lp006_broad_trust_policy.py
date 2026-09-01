"""
LP006 — Broad Trust Policy
============================
Analyzes IAM role trust policies (assume_role_policy) for overly permissive
principal configurations.

IAM Trust Policy vs. Identity Policy — Understanding the Difference
-------------------------------------------------------------------
An IAM role has TWO types of policies:

1. IDENTITY POLICY (the permissions policy):
   Defines WHAT the role can do once assumed.
   Example: "Allow s3:GetObject on arn:aws:s3:::my-bucket/*"

2. TRUST POLICY (the assume role policy):
   Defines WHO is allowed to call sts:AssumeRole on this role.
   Example: "Allow lambda.amazonaws.com to assume this role"

This rule analyses ONLY the trust policy (type 2). LP001–LP005 cover type 1.

Principal formats in trust policies:
    Principal: "*"                    → Anyone (internet-accessible!) — CRITICAL
    Principal: {"AWS": "*"}           → Any AWS account — CRITICAL
    Principal: {"AWS": "arn:..."}     → Specific account/role — check for conditions
    Principal: {"Service": "..."}     → AWS service (Lambda, EC2, etc.) — usually OK
    Principal: {"Federated": "..."}   → OIDC/SAML federation — check conditions

Cross-account trust without conditions:
    When a trust policy allows an external AWS account to assume a role
    WITHOUT a Condition block, any principal in that account can assume it.
    Adding aws:PrincipalArn or sts:ExternalId conditions restricts this.
"""

from __future__ import annotations

import json

from cloud_policy_guard.models.finding import Finding, Severity
from cloud_policy_guard.models.iam import IAMStatement, TrustPolicy
from cloud_policy_guard.rules.base import BaseTrustRule

# AWS account ID pattern for detecting cross-account trust
# A 12-digit AWS account ID in an ARN looks like: arn:aws:iam::123456789012:root
_AWS_ACCOUNT_ARN_PARTS = ["arn:aws:iam::", "arn:aws-cn:iam::", "arn:aws-us-gov:iam::"]


class LP006BroadTrustPolicy(BaseTrustRule):
    rule_id = "LP006"
    title = "Broad Trust Policy"
    default_severity = Severity.HIGH
    description = (
        "Analyzes IAM role trust policies for overly permissive principal configurations. "
        "Detects Principal: '*', cross-account trust without conditions, and other "
        "risky trust relationship patterns."
    )

    def evaluate(self, trust_policy: TrustPolicy) -> list[Finding]:
        findings = []

        for stmt in trust_policy.statements:
            if not stmt.is_allow:
                continue

            principal = stmt.principals
            if principal is None:
                continue

            findings.extend(self._check_principal(trust_policy, stmt, principal))

        return findings

    def _check_principal(
        self, trust_policy: TrustPolicy, stmt: IAMStatement, principal: object
    ) -> list[Finding]:
        """Evaluate the Principal value for trust policy violations."""
        findings = []

        # Pattern 1: Principal: "*" — anyone on the internet can assume this role
        if principal == "*":
            findings.append(self._build_open_world_finding(trust_policy, stmt))
            return findings  # No need to check further — this is already CRITICAL

        if isinstance(principal, dict):
            # Pattern 2: Principal: {"AWS": "*"} — any AWS account
            aws_principal = principal.get("AWS")
            if aws_principal == "*" or aws_principal == ["*"]:
                findings.append(self._build_open_world_finding(trust_policy, stmt))
                return findings

            # Pattern 3: Cross-account trust without Condition
            if aws_principal:
                arns = [aws_principal] if isinstance(aws_principal, str) else aws_principal
                cross_account = self._has_cross_account_arn(arns)
                if cross_account and not stmt.has_conditions:
                    findings.append(
                        self._build_cross_account_no_condition_finding(
                            trust_policy, stmt, arns
                        )
                    )

            # Pattern 4: Service principal — generally fine but log for awareness
            # We don't flag service principals as they are expected and normal.

        return findings

    def _has_cross_account_arn(self, arns: list) -> bool:
        """
        Check if any ARN in the list belongs to a different account.
        We detect cross-account by presence of a 12-digit account ID in the ARN.
        (We can't know the CURRENT account from a plan, so we flag any external-looking ARN.)
        """
        import re
        for arn in arns:
            if isinstance(arn, str):
                # Look for an ARN with a 12-digit account ID
                # Example: arn:aws:iam::123456789012:role/something
                if re.match(r"^arn:aws(-cn|-us-gov)?:iam::\d{12}:", arn):
                    return True
        return False

    def _build_open_world_finding(
        self, trust_policy: TrustPolicy, stmt: IAMStatement
    ) -> Finding:
        principal = stmt.principals
        description = (
            f"The role '{trust_policy.resource_address}' has a trust policy with "
            f"Principal: {json.dumps(principal)}. This allows ANY entity — including "
            f"unauthenticated callers — to attempt to assume this role. "
            f"If the role lacks an ExternalId condition, it can be assumed by any "
            f"AWS account or internet-accessible service."
        )

        evidence = json.dumps(
            {
                "Effect": stmt.effect,
                "Principal": principal,
                "Action": stmt.raw.get("Action", "sts:AssumeRole"),
                "Condition": stmt.conditions or "(none)",
            },
            indent=2,
        )

        remediation = (
            "Replace Principal: '*' with the specific AWS service, account, or role "
            "that needs to assume this role. For example:\n"
            '  Principal: {"Service": "lambda.amazonaws.com"}\n'
            '  Principal: {"AWS": "arn:aws:iam::123456789012:role/specific-role"}\n'
            "If cross-account trust is required, always add a Condition with "
            "sts:ExternalId to prevent confused deputy attacks."
        )

        return self._make_finding(
            trust_policy=trust_policy,
            description=description,
            evidence=evidence,
            remediation=remediation,
            severity=Severity.CRITICAL,
        )

    def _build_cross_account_no_condition_finding(
        self,
        trust_policy: TrustPolicy,
        stmt: IAMStatement,
        arns: list,
    ) -> Finding:
        arns_display = json.dumps(arns if len(arns) > 1 else arns[0])

        description = (
            f"The role '{trust_policy.resource_address}' allows cross-account trust from "
            f"{arns_display} without a Condition block. Without conditions like "
            f"sts:ExternalId, any principal in the trusted account can assume this role, "
            f"not just the intended one. This is known as the 'confused deputy' problem."
        )

        evidence = json.dumps(
            {
                "Effect": stmt.effect,
                "Principal": stmt.principals,
                "Action": stmt.raw.get("Action", "sts:AssumeRole"),
                "Condition": "(none — missing)",
            },
            indent=2,
        )

        remediation = (
            "Add a Condition to restrict which principal within the trusted account "
            "can assume this role. The recommended approach is sts:ExternalId:\n\n"
            '  "Condition": {\n'
            '    "StringEquals": {\n'
            '      "sts:ExternalId": "your-unique-external-id"\n'
            "    }\n"
            "  }\n\n"
            "This prevents the 'confused deputy' attack where a trusted third-party's "
            "infrastructure is tricked into assuming your role on behalf of an attacker.\n"
            "Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html"
        )

        return self._make_finding(
            trust_policy=trust_policy,
            description=description,
            evidence=evidence,
            remediation=remediation,
            severity=Severity.MEDIUM,
        )
