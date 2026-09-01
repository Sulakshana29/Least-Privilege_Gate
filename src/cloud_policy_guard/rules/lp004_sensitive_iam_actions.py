"""
LP004 — Sensitive IAM Actions
==============================
Detects dangerous IAM actions that are well-known privilege escalation
or lateral movement vectors, even when granted to specific resources.

Why these actions matter
------------------------
These actions are consistently identified by cloud security researchers
as the most dangerous individual permissions in AWS. They are dangerous
not because they directly destroy data, but because they can be used to
ESCALATE PRIVILEGES or MOVE LATERALLY to other resources/accounts.

Each action in SENSITIVE_ACTIONS has an explanation of its specific risk.

Reference: https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/

Detection logic:
- We check each Allow statement's actions against the sensitive list.
- We emit one Finding per sensitive action found (not per statement)
  so that each action gets its own clear explanation.
- If a wildcard action ("*") is present, LP001 already covers it —
  we don't double-report here.
- Resource scoping is noted in the finding but doesn't change severity,
  because these actions are dangerous regardless of resource scope.
"""

from __future__ import annotations

import json

from cloud_policy_guard.models.finding import Finding, Severity
from cloud_policy_guard.models.iam import IAMPolicy, IAMStatement
from cloud_policy_guard.rules.base import BaseRule

# Curated list of sensitive IAM actions with per-action explanations.
# Format: { "service:Action": "explanation of the specific risk" }
SENSITIVE_ACTIONS: dict[str, str] = {
    "iam:PassRole": (
        "Allows the principal to pass an IAM role to an AWS service (e.g., EC2, Lambda). "
        "If combined with the ability to create/modify resources (e.g., ec2:RunInstances), "
        "an attacker can pass a high-privilege role to a resource they control, "
        "effectively escalating to that role's permissions."
    ),
    "iam:CreatePolicyVersion": (
        "Allows creating a new version of an existing managed policy. An attacker can "
        "overwrite a policy's permissions (e.g., replacing a read-only policy with "
        "Action: '*', Resource: '*') while staying within the same policy ARN."
    ),
    "iam:SetDefaultPolicyVersion": (
        "Allows switching which version of a managed policy is active. If an attacker "
        "can see prior policy versions (via iam:GetPolicyVersion), they can activate "
        "a previously permissive version."
    ),
    "iam:AttachRolePolicy": (
        "Allows attaching any managed policy to any role. An attacker can attach "
        "AdministratorAccess to a role they control, gaining full AWS access."
    ),
    "iam:AttachUserPolicy": (
        "Allows attaching any managed policy to any IAM user. An attacker can attach "
        "AdministratorAccess to their own user account."
    ),
    "iam:AttachGroupPolicy": (
        "Allows attaching any managed policy to any IAM group. Can be used to escalate "
        "privileges for all members of a group."
    ),
    "iam:PutRolePolicy": (
        "Allows creating or replacing an inline policy on any role. This grants the "
        "ability to write arbitrary permissions directly onto any role."
    ),
    "iam:PutUserPolicy": (
        "Allows creating or replacing an inline policy on any IAM user. An attacker "
        "can write a policy that grants themselves full AWS access."
    ),
    "iam:PutGroupPolicy": (
        "Allows creating or replacing an inline policy on any IAM group."
    ),
    "iam:CreateAccessKey": (
        "Allows creating long-term access keys for any IAM user. An attacker can "
        "create a persistent backdoor credential for any user in the account, "
        "including users with administrator privileges."
    ),
    "iam:UpdateAssumeRolePolicy": (
        "Allows modifying the trust policy of any IAM role. An attacker can add "
        "themselves (or any external account) as a trusted principal, then assume "
        "that role."
    ),
    "iam:CreateLoginProfile": (
        "Allows setting a console password for any IAM user without a password. "
        "Can be used to take over dormant accounts."
    ),
    "iam:UpdateLoginProfile": (
        "Allows changing the console password for any IAM user. Can be used to "
        "take over any IAM user's console access."
    ),
    "sts:AssumeRole": (
        "Allows assuming IAM roles. With Resource: '*' this means any role in any "
        "account can be assumed, including cross-account roles. "
        "Should be scoped to specific role ARNs."
    ),
    "lambda:InvokeFunction": (
        "Allows invoking any Lambda function. Can be used to trigger functions that "
        "have privileged execution roles, indirectly escalating privileges."
    ),
    "lambda:UpdateFunctionCode": (
        "Allows replacing a Lambda function's code. An attacker can replace a "
        "high-privilege function's code with malicious code."
    ),
    "cloudformation:CreateStack": (
        "Allows creating CloudFormation stacks with arbitrary IAM roles. "
        "Can be used to provision new infrastructure with elevated permissions."
    ),
    "glue:CreateDevEndpoint": (
        "Allows creating Glue development endpoints with attached IAM roles. "
        "A known privilege escalation path to assume attached role permissions."
    ),
    "ec2:AssociateIamInstanceProfile": (
        "Allows attaching an IAM instance profile (role) to an EC2 instance. "
        "An attacker with access to the instance can then access the role's credentials "
        "via the instance metadata service."
    ),
}


class LP004SensitiveIAMActions(BaseRule):
    rule_id = "LP004"
    title = "Sensitive IAM Action"
    default_severity = Severity.HIGH
    description = (
        "Detects dangerous IAM actions that are known privilege escalation or lateral "
        "movement vectors, even when scoped to specific resources."
    )

    def evaluate(self, policy: IAMPolicy) -> list[Finding]:
        findings = []

        for stmt in policy.allow_statements:
            # Skip wildcard action — LP001 already fires as CRITICAL for that
            if stmt.has_wildcard_action:
                continue

            for action in stmt.actions:
                # Normalize case for comparison (AWS action names are case-insensitive)
                action_normalized = self._normalize_action(action)
                if action_normalized in SENSITIVE_ACTIONS:
                    findings.append(
                        self._build_finding_for_action(policy, stmt, action, action_normalized)
                    )

        return findings

    def _normalize_action(self, action: str) -> str:
        """Normalize action to match our dictionary keys (exact case)."""
        # Our dict uses title-case service names: iam:PassRole, sts:AssumeRole
        # AWS is case-insensitive, so "IAM:passrole" should still match
        if ":" not in action:
            return action
        service, verb = action.split(":", 1)
        # Try exact match first, then case-insensitive
        candidate = f"{service.lower()}:{verb}"
        for sensitive in SENSITIVE_ACTIONS:
            if sensitive.lower() == candidate.lower():
                return sensitive
        return action

    def _build_finding_for_action(
        self,
        policy: IAMPolicy,
        stmt: IAMStatement,
        action: str,
        normalized_action: str,
    ) -> Finding:
        action_explanation = SENSITIVE_ACTIONS.get(normalized_action, "")
        resources = stmt.raw.get("Resource", "*")

        description = (
            f"The policy '{policy.resource_address}' grants the sensitive action "
            f"'{action}'. {action_explanation}"
        )

        evidence = json.dumps(
            {
                "Effect": stmt.effect,
                "Action": action,
                "Resource": resources,
            },
            indent=2,
        )

        remediation = (
            f"Review whether '{action}' is genuinely required. If so:\n"
            f"1. Scope it to the minimum necessary resources (replace Resource: '*' "
            f"   with specific ARNs).\n"
            f"2. Add Condition keys to restrict when this action can be used "
            f"   (e.g., aws:SourceAccount, aws:PrincipalTag).\n"
            f"3. Consider whether this permission belongs in this policy, or should "
            f"   be in a separate, more controlled policy with break-glass procedures."
        )

        return self._make_finding(
            policy=policy,
            description=description,
            evidence=evidence,
            remediation=remediation,
            severity=Severity.HIGH,
        )
