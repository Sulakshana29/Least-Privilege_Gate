"""
IAM policy data models.

These models represent the normalized form of AWS IAM policy documents
as extracted from a Terraform plan.

AWS IAM Background
------------------
An IAM policy document has this structure:

    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",          # string OR list of strings
                "Resource": "arn:aws:s3:::my-bucket/*",  # string OR list
                "Principal": {...},                # only in trust policies
                "Condition": {...}                 # optional
            }
        ]
    }

AWS allows Action and Resource to be either a single string or a list.
Our models always normalize them to lists so rule code never needs to
handle both cases.

Two policy types:
- IAMPolicy     → identity-based policy (attached to users, roles, groups)
- TrustPolicy   → resource-based policy defining WHO can assume a role
                  (the assume_role_policy on aws_iam_role)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class IAMStatement:
    """
    A single statement within an IAM policy document.

    Attributes:
        effect:       "Allow" or "Deny"
        actions:      List of IAM actions (normalized from string or list).
                      Examples: ["s3:GetObject"], ["*"], ["iam:PassRole"]
        not_actions:  NotAction list (inverted action matching) — flags as noteworthy.
        resources:    List of resource ARNs (normalized from string or list).
                      Examples: ["*"], ["arn:aws:s3:::my-bucket/*"]
        not_resources: NotResource list (inverted resource matching).
        principals:   Principal value (only present in trust policies).
                      Can be: "*", {"AWS": [...]}, {"Service": [...]}
        conditions:   Condition block dict (key=operator, value=context key map).
        raw:          The original statement dict (for evidence reporting).
    """

    effect: str
    actions: list[str] = field(default_factory=list)
    not_actions: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    not_resources: list[str] = field(default_factory=list)
    principals: Any = None  # str | dict | list
    conditions: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_allow(self) -> bool:
        """True when this statement grants permissions (Effect: Allow)."""
        return self.effect.lower() == "allow"

    @property
    def is_deny(self) -> bool:
        """True when this statement explicitly denies permissions (Effect: Deny)."""
        return self.effect.lower() == "deny"

    @property
    def has_wildcard_action(self) -> bool:
        """True when actions list contains a bare wildcard '*'."""
        return "*" in self.actions

    @property
    def has_wildcard_resource(self) -> bool:
        """True when resources list contains a bare wildcard '*'."""
        return "*" in self.resources

    @property
    def has_conditions(self) -> bool:
        """True when a Condition block is present (reduces risk)."""
        return bool(self.conditions)


@dataclass
class IAMPolicy:
    """
    A complete IAM identity-based policy document.

    This model represents a policy that will be created or updated
    in the Terraform plan. It is the main input to the rule engine
    for LP001–LP005.

    Attributes:
        statements:       List of normalized IAMStatement objects.
        resource_address: Terraform address (e.g., "aws_iam_policy.app").
        resource_type:    Terraform type (e.g., "aws_iam_policy").
        policy_name:      Policy name attribute from Terraform, if present.
    """

    statements: list[IAMStatement] = field(default_factory=list)
    resource_address: str = ""
    resource_type: str = ""
    policy_name: str = ""

    @property
    def allow_statements(self) -> list[IAMStatement]:
        """Return only Allow statements — Deny statements reduce risk, not increase it."""
        return [s for s in self.statements if s.is_allow]


@dataclass
class TrustPolicy:
    """
    An IAM role trust policy (assume_role_policy).

    This is fundamentally different from an identity policy:
    - It lives on an IAM Role resource
    - It controls WHO is allowed to call sts:AssumeRole on this role
    - A Principal of "*" means ANYONE (including the internet) can assume it

    This model feeds into LP006 (Broad Trust Policy).

    Attributes:
        statements:       List of normalized trust statements.
        resource_address: Terraform address (e.g., "aws_iam_role.lambda_exec").
        resource_type:    Terraform type (always "aws_iam_role").
        role_name:        Role name from Terraform, if present.
    """

    statements: list[IAMStatement] = field(default_factory=list)
    resource_address: str = ""
    resource_type: str = ""
    role_name: str = ""
