"""
LP005 — Excessive Service Permissions
=======================================
Detects service-level wildcard actions like s3:*, ec2:*, iam:* etc.

The problem with service-level wildcards
-----------------------------------------
Service wildcards violate least privilege by granting every action
within a service when only a subset is needed.

For example:
    "s3:*" includes s3:DeleteBucket, s3:DeleteObject, s3:PutBucketPolicy,
    s3:PutBucketAcl, s3:GetObject, and 100+ other actions.

A Lambda function that only reads from S3 should have "s3:GetObject",
not "s3:*". Granting "s3:*" means a compromised function can delete buckets,
overwrite bucket policies, expose data publicly, etc.

Severity tiers (documented in docs/risk-model.md):
  HIGH   → Identity/credential/crypto services (iam:*, sts:*, kms:*, secretsmanager:*)
           These control access itself — full service access is extremely dangerous.
  MEDIUM → Data and compute services (s3:*, ec2:*, lambda:*, rds:*, dynamodb:*)
           Full service access can lead to data exfiltration or compute abuse.
  LOW    → Observability/messaging services (logs:*, cloudwatch:*, sns:*, sqs:*)
           Still unnecessarily broad but lower direct impact.
"""

from __future__ import annotations

import json

from cloud_policy_guard.models.finding import Finding, Severity
from cloud_policy_guard.models.iam import IAMPolicy, IAMStatement
from cloud_policy_guard.rules.base import BaseRule

# Service wildcard patterns and their risk tier
# Format: { "service:*" pattern: (Severity, typical_use_case_description) }
SERVICE_WILDCARDS: dict[str, tuple[Severity, str]] = {
    # HIGH — Identity, credential, and cryptographic services
    "iam:*": (
        Severity.HIGH,
        "Full IAM control. Can create/modify/delete users, roles, and policies. "
        "Use specific IAM actions required (e.g., iam:GetRole, iam:ListRoles).",
    ),
    "sts:*": (
        Severity.HIGH,
        "Full STS control. Can assume any role, create session tokens, decode "
        "authorization messages. Use sts:AssumeRole scoped to specific role ARNs.",
    ),
    "kms:*": (
        Severity.HIGH,
        "Full KMS control. Can encrypt/decrypt data, manage keys, disable keys. "
        "Use specific KMS actions (e.g., kms:Decrypt, kms:GenerateDataKey).",
    ),
    "secretsmanager:*": (
        Severity.HIGH,
        "Full Secrets Manager control. Can read ALL secrets, rotate them, or delete them. "
        "Scope to specific secret ARNs with only GetSecretValue.",
    ),
    "organizations:*": (
        Severity.HIGH,
        "Full AWS Organizations control. Can create accounts, modify SCPs, and affect "
        "governance across the entire AWS organization.",
    ),
    # MEDIUM — Data and compute services
    "s3:*": (
        Severity.MEDIUM,
        "Full S3 control. Includes destructive actions (DeleteBucket, DeleteObject), "
        "ACL modification (PutBucketAcl), and policy manipulation (PutBucketPolicy). "
        "Scope to only the actions required for the use case.",
    ),
    "ec2:*": (
        Severity.MEDIUM,
        "Full EC2 control. Includes TerminateInstances, ModifyInstanceAttribute, and "
        "network configuration. Scope to specific EC2 actions needed.",
    ),
    "lambda:*": (
        Severity.MEDIUM,
        "Full Lambda control. Includes UpdateFunctionCode (replace function logic) and "
        "AddPermission (allow other services to invoke). Scope to required actions.",
    ),
    "rds:*": (
        Severity.MEDIUM,
        "Full RDS control. Includes DeleteDBInstance, ModifyDBInstance, and "
        "RestoreDBInstanceFromDBSnapshot. Scope to required actions.",
    ),
    "dynamodb:*": (
        Severity.MEDIUM,
        "Full DynamoDB control. Includes DeleteTable, UpdateTable. "
        "Scope to data access actions only (GetItem, PutItem, Query, Scan).",
    ),
    "cloudformation:*": (
        Severity.MEDIUM,
        "Full CloudFormation control. Can create stacks with arbitrary IAM roles, "
        "which is a known privilege escalation path.",
    ),
    "ssm:*": (
        Severity.MEDIUM,
        "Full SSM control. Includes accessing Parameter Store (may contain secrets), "
        "running remote commands on EC2 instances via Session Manager.",
    ),
    # LOW — Observability and messaging
    "logs:*": (
        Severity.LOW,
        "Full CloudWatch Logs control. Includes DeleteLogGroup and DeleteLogStream. "
        "Scope to CreateLogGroup, CreateLogStream, PutLogEvents for log writers.",
    ),
    "cloudwatch:*": (
        Severity.LOW,
        "Full CloudWatch control. Includes deleting dashboards and alarms. "
        "Scope to specific metrics/alarms operations required.",
    ),
    "sns:*": (
        Severity.LOW,
        "Full SNS control. Includes DeleteTopic and SetTopicAttributes. "
        "Scope to Publish for message producers.",
    ),
    "sqs:*": (
        Severity.LOW,
        "Full SQS control. Includes DeleteQueue and PurgeQueue (deletes all messages). "
        "Scope to SendMessage/ReceiveMessage/DeleteMessage for queue consumers.",
    ),
    "events:*": (
        Severity.LOW,
        "Full EventBridge control. Includes deleting rules and event buses. "
        "Scope to PutEvents for event producers.",
    ),
}


class LP005ExcessiveServicePerms(BaseRule):
    rule_id = "LP005"
    title = "Excessive Service Permissions"
    default_severity = Severity.MEDIUM
    description = (
        "Detects service-level wildcard actions (e.g., s3:*, iam:*, kms:*) that grant "
        "every action within a service when only a subset is required."
    )

    def evaluate(self, policy: IAMPolicy) -> list[Finding]:
        findings = []

        for stmt in policy.allow_statements:
            # Skip full wildcard — LP001 already handles that
            if stmt.has_wildcard_action:
                continue

            for action in stmt.actions:
                if action.endswith(":*") and action != "*":
                    service_wildcard = action.lower()
                    if service_wildcard in SERVICE_WILDCARDS:
                        severity, context = SERVICE_WILDCARDS[service_wildcard]
                        findings.append(
                            self._build_finding(policy, stmt, action, severity, context)
                        )

        return findings

    def _build_finding(
        self,
        policy: IAMPolicy,
        stmt: IAMStatement,
        action: str,
        severity: Severity,
        context: str,
    ) -> Finding:
        resources = stmt.raw.get("Resource", "*")

        description = (
            f"The policy '{policy.resource_address}' grants '{action}' on "
            f"Resource: {json.dumps(resources)}. {context}"
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
            f"Replace '{action}' with only the specific actions this resource needs. "
            f"To find the minimum required actions, enable AWS CloudTrail and use "
            f"IAM Access Analyzer to generate a least-privilege policy based on "
            f"actual API call history: "
            f"https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-generation.html"
        )

        return self._make_finding(
            policy=policy,
            description=description,
            evidence=evidence,
            remediation=remediation,
            severity=severity,
        )
