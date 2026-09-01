"""
LP001 — Wildcard IAM Action
============================
Detects IAM policy statements that grant Action: "*".

Why this is CRITICAL
--------------------
When a statement contains Action: "*" with Effect: Allow, the principal
(user, role, or service) is granted permission to perform EVERY action
across EVERY AWS service — including creating IAM users, deleting S3 buckets,
terminating EC2 instances, accessing Secrets Manager, and more.

This is effectively equivalent to root-level access within the scope
of the Resource constraint (handled separately by LP002).

Real-world impact:
- If compromised, an attacker can use Action: "*" to escalate privileges,
  exfiltrate data, create backdoor IAM users, or destroy infrastructure.

Least privilege principle:
- Policies should enumerate only the specific actions required.
- Example: ["s3:GetObject", "s3:PutObject"] instead of "*".

Note on Deny statements:
- We skip Effect: Deny statements because Deny with Action: "*" is actually
  a restrictive control, not a grant of permissions.
"""

from __future__ import annotations

import json

from cloud_policy_guard.models.finding import Finding, Severity
from cloud_policy_guard.models.iam import IAMPolicy, IAMStatement
from cloud_policy_guard.rules.base import BaseRule


class LP001WildcardAction(BaseRule):
    rule_id = "LP001"
    title = "Wildcard IAM Action"
    default_severity = Severity.CRITICAL
    description = (
        "Detects IAM policy statements that grant Action: '*', allowing the principal "
        "to perform every action across all AWS services."
    )

    def evaluate(self, policy: IAMPolicy) -> list[Finding]:
        findings = []

        for stmt in policy.allow_statements:
            if stmt.has_wildcard_action:
                findings.append(self._build_finding(policy, stmt))

        return findings

    def _build_finding(self, policy: IAMPolicy, stmt: IAMStatement) -> Finding:
        resources = ", ".join(stmt.resources) if stmt.resources else "*"

        description = (
            f"The policy '{policy.resource_address}' contains a statement with "
            f"Action: '*' and Effect: Allow. This grants permission to call any AWS API "
            f"action. Combined with Resource: '{resources}', this provides extremely "
            f"broad access."
        )

        evidence = json.dumps(
            {
                "Effect": stmt.effect,
                "Action": stmt.raw.get("Action", "*"),
                "Resource": stmt.raw.get("Resource", "*"),
            },
            indent=2,
        )

        remediation = (
            "Replace Action: '*' with only the specific AWS actions this principal "
            "requires. For example, if this policy is for an S3 upload service, use "
            "['s3:PutObject', 's3:GetObject'] instead of '*'. "
            "Refer to AWS IAM documentation for service-specific action lists: "
            "https://docs.aws.amazon.com/service-authorization/latest/reference/"
        )

        return self._make_finding(
            policy=policy,
            description=description,
            evidence=evidence,
            remediation=remediation,
            severity=Severity.CRITICAL,
        )
