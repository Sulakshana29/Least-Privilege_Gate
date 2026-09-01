"""
LP002 — Wildcard Resource
==========================
Detects IAM policy statements that use Resource: "*" and assigns severity
based on the context (what actions accompany the wildcard resource).

Why context matters
--------------------
Resource: "*" is NOT always equally dangerous.

Consider these two policies:

    Policy A:
        Effect: Allow
        Action: "s3:GetObject"
        Resource: "*"

    Policy B:
        Effect: Allow
        Action: "iam:PassRole"
        Resource: "*"

Both have Resource: "*". But Policy B is far more dangerous because
iam:PassRole with Resource: "*" allows passing ANY role to ANY AWS service,
which is a well-known privilege escalation path.

Simply treating both as CRITICAL would produce noisy, unhelpful findings.
This rule applies contextual severity:

Severity tiers:
  CRITICAL → Never triggered here (LP001+LP003 handle the worst cases)
  HIGH     → Wildcard resource + dangerous actions (IAM manipulation, KMS, STS)
  MEDIUM   → Wildcard resource + write/delete actions on data services
  LOW      → Wildcard resource + read-only actions only

Coordination with LP001:
  If a statement already has Action: "*", LP001 fires as CRITICAL.
  LP002 skips those statements to avoid duplicate findings.
"""

from __future__ import annotations

import json

from cloud_policy_guard.models.finding import Finding, Severity
from cloud_policy_guard.models.iam import IAMPolicy, IAMStatement
from cloud_policy_guard.rules.base import BaseRule

# Actions that make Resource: "*" especially dangerous (HIGH severity)
HIGH_RISK_ACTIONS_PREFIX = frozenset(
    {
        "iam:",
        "sts:",
        "kms:",
        "secretsmanager:",
        "organizations:",
        "sso:",
        "identitystore:",
    }
)

# Actions prefixes that imply write/destructive capability (MEDIUM severity)
WRITE_ACTION_VERBS = frozenset(
    {
        "Put",
        "Create",
        "Update",
        "Delete",
        "Modify",
        "Attach",
        "Detach",
        "Set",
        "Write",
        "Upload",
        "Terminate",
        "Stop",
        "Destroy",
        "Remove",
        "Revoke",
        "Reset",
    }
)


class LP002WildcardResource(BaseRule):
    rule_id = "LP002"
    title = "Wildcard Resource"
    default_severity = Severity.MEDIUM
    description = (
        "Detects IAM policy statements using Resource: '*'. Severity is determined "
        "by the actions in the statement — sensitive actions with wildcard resource "
        "are rated HIGH; read-only actions are rated LOW."
    )

    def evaluate(self, policy: IAMPolicy) -> list[Finding]:
        findings = []

        for stmt in policy.allow_statements:
            # Skip if Action is also wildcard — LP001 already handles that as CRITICAL
            if stmt.has_wildcard_action:
                continue

            if not stmt.has_wildcard_resource:
                continue

            severity = self._calculate_severity(stmt)
            findings.append(self._build_finding(policy, stmt, severity))

        return findings

    def _calculate_severity(self, stmt: IAMStatement) -> Severity:
        """
        Determine severity based on what actions accompany Resource: "*".

        Logic:
        1. Any action from a high-risk service → HIGH
        2. Any action name containing a write/destructive verb → MEDIUM
        3. Everything else (presumed read-only) → LOW
        """
        for action in stmt.actions:
            # Check if the action belongs to a high-risk service
            service_prefix = action.split(":")[0].lower() + ":" if ":" in action else ""
            if service_prefix in HIGH_RISK_ACTIONS_PREFIX:
                return Severity.HIGH

            # Check if the action verb indicates write/destructive capability
            action_verb = action.split(":")[-1] if ":" in action else action
            for write_verb in WRITE_ACTION_VERBS:
                if action_verb.startswith(write_verb):
                    return Severity.MEDIUM

        return Severity.LOW

    def _build_finding(
        self, policy: IAMPolicy, stmt: IAMStatement, severity: Severity
    ) -> Finding:
        actions_display = json.dumps(stmt.raw.get("Action", []))

        severity_context = {
            Severity.HIGH: (
                "The actions include sensitive service operations (IAM, STS, KMS, or "
                "Secrets Manager). Combining these with Resource: '*' significantly "
                "increases the blast radius of a credential compromise."
            ),
            Severity.MEDIUM: (
                "The actions include write or destructive operations. Using Resource: '*' "
                "means these can be applied to any resource in the account."
            ),
            Severity.LOW: (
                "The actions appear to be read-only. While lower risk, scoping Resource "
                "to specific ARNs is still recommended."
            ),
        }

        description = (
            f"The policy '{policy.resource_address}' uses Resource: '*' with the following "
            f"actions: {actions_display}. {severity_context.get(severity, '')}"
        )

        evidence = json.dumps(
            {
                "Effect": stmt.effect,
                "Action": stmt.raw.get("Action"),
                "Resource": stmt.raw.get("Resource", "*"),
            },
            indent=2,
        )

        remediation = (
            "Replace Resource: '*' with specific resource ARNs. For example:\n"
            "  s3:GetObject → 'arn:aws:s3:::my-bucket/*'\n"
            "  iam:PassRole → 'arn:aws:iam::123456789012:role/specific-role'\n"
            "Use ARN wildcards to scope to your account: "
            "'arn:aws:s3:::my-app-*' matches all buckets starting with 'my-app-'."
        )

        return self._make_finding(
            policy=policy,
            description=description,
            evidence=evidence,
            remediation=remediation,
            severity=severity,
        )
