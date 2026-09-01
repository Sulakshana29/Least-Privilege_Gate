"""
LP003 — Administrative Permissions
====================================
Detects IAM configurations that grant administrator-equivalent access.

Detection patterns:

1. Inline policy with Action: "*" + Resource: "*" (Effect: Allow)
   This is the inline equivalent of AdministratorAccess.
   Full AWS API access with no constraints.

2. Managed policy attachment of known admin/broad ARNs:
   - arn:aws:iam::aws:policy/AdministratorAccess
   - arn:aws:iam::aws:policy/IAMFullAccess
   - arn:aws:iam::aws:policy/PowerUserAccess

Why IAMFullAccess and PowerUserAccess are flagged:
- IAMFullAccess → Can create new IAM users/roles with AdministratorAccess,
  effectively granting root access indirectly.
- PowerUserAccess → Grants full access to all services except IAM user management,
  which still allows major damage (data exfiltration, compute abuse, etc.)

Note: LP001 catches Action: "*" in isolation. LP003 is specifically looking
for the combination of Action: "*" + Resource: "*" together, which is the
canonical "full admin" pattern, and for managed policy ARN attachments.
"""

from __future__ import annotations

import json

from cloud_policy_guard.models.finding import Finding, Severity
from cloud_policy_guard.models.iam import IAMPolicy
from cloud_policy_guard.rules.base import BaseRule

# AWS managed policy ARNs that grant dangerously broad permissions
DANGEROUS_MANAGED_POLICIES: dict[str, str] = {
    "arn:aws:iam::aws:policy/AdministratorAccess": (
        "Grants full access to all AWS services and resources. Equivalent to root."
    ),
    "arn:aws:iam::aws:policy/IAMFullAccess": (
        "Grants full IAM control. Can be used to create admin users or roles, "
        "effectively escalating to full administrator access."
    ),
    "arn:aws:iam::aws:policy/PowerUserAccess": (
        "Grants full access to all AWS services except IAM user management. "
        "Still allows significant damage including data access and resource destruction."
    ),
}


class LP003AdminPermissions(BaseRule):
    rule_id = "LP003"
    title = "Administrative Permissions"
    default_severity = Severity.CRITICAL
    description = (
        "Detects IAM configurations that grant administrator-equivalent access, either "
        "through inline Action: '*' + Resource: '*' policies or by attaching known "
        "broad AWS managed policies."
    )

    def evaluate(self, policy: IAMPolicy) -> list[Finding]:
        findings = []

        # Pattern 1: Inline admin (Action: "*" + Resource: "*" together)
        for stmt in policy.allow_statements:
            if stmt.has_wildcard_action and stmt.has_wildcard_resource:
                findings.append(self._build_inline_admin_finding(policy, stmt))

        # Pattern 2: Attachment of dangerous managed policy ARN
        # The policy_name field holds the ARN for attachment resource types
        if policy.resource_type in (
            "aws_iam_role_policy_attachment",
            "aws_iam_policy_attachment",
            "aws_iam_user_policy_attachment",
        ):
            policy_arn = policy.policy_name
            if policy_arn in DANGEROUS_MANAGED_POLICIES:
                findings.append(self._build_attachment_finding(policy, policy_arn))

        return findings

    def _build_inline_admin_finding(self, policy: IAMPolicy, stmt: object) -> Finding:
        description = (
            f"The policy '{policy.resource_address}' contains a statement with both "
            f"Action: '*' and Resource: '*' with Effect: Allow. This is equivalent to "
            f"granting AdministratorAccess — the principal can perform any action on "
            f"any resource in the account."
        )

        evidence = json.dumps(
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
            indent=2,
        )

        remediation = (
            "Remove the wildcard Action and Resource combination. Define the specific "
            "actions and resources this principal needs. If administrative access is "
            "genuinely required, use AWS Organizations SCPs and require MFA for "
            "privilege escalation rather than embedding admin permissions in policies."
        )

        return self._make_finding(
            policy=policy,
            description=description,
            evidence=evidence,
            remediation=remediation,
            severity=Severity.CRITICAL,
        )

    def _build_attachment_finding(self, policy: IAMPolicy, policy_arn: str) -> Finding:
        arn_description = DANGEROUS_MANAGED_POLICIES[policy_arn]

        description = (
            f"The resource '{policy.resource_address}' attaches the managed policy "
            f"'{policy_arn}'. {arn_description}"
        )

        evidence = json.dumps({"policy_arn": policy_arn}, indent=2)

        remediation = (
            f"Replace '{policy_arn}' with a custom managed policy or inline policy "
            f"that grants only the specific actions and resources required. "
            f"Create a least-privilege policy using AWS IAM Access Analyzer to "
            f"identify actual permissions used: "
            f"https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-generation.html"
        )

        return self._make_finding(
            policy=policy,
            description=description,
            evidence=evidence,
            remediation=remediation,
            severity=Severity.CRITICAL,
        )
