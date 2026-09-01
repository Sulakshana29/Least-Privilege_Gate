"""
Terraform plan data models.

These models represent the parsed structure of a `terraform show -json` output.

Terraform Plan JSON Structure
-----------------------------
When you run:
    terraform plan -out=tfplan
    terraform show -json tfplan > plan.json

The resulting JSON has this top-level structure:
    {
        "format_version": "1.2",
        "terraform_version": "1.6.0",
        "resource_changes": [...],   ← primary source for analysis
        "planned_values": {...},
        "configuration": {...}
    }

Each entry in resource_changes looks like:
    {
        "address": "aws_iam_policy.application",
        "type": "aws_iam_policy",
        "change": {
            "actions": ["create"],   ← what Terraform will do
            "before": null,          ← current state (null for new resources)
            "after": {               ← planned final state ← we analyze this
                "name": "app-policy",
                "policy": "{...}"    ← IAM policy JSON (often a string)
            },
            "after_unknown": {}
        }
    }

We focus on `after` because that's what will exist in AWS after apply.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# Terraform change actions we care about (resources being created or modified)
RELEVANT_CHANGE_ACTIONS = frozenset({"create", "update", "no-op"})

# IAM-related Terraform resource types we know how to parse
IAM_RESOURCE_TYPES = frozenset(
    {
        "aws_iam_policy",
        "aws_iam_role_policy",
        "aws_iam_user_policy",
        "aws_iam_group_policy",
        "aws_iam_role",
        "aws_iam_role_policy_attachment",
        "aws_iam_policy_attachment",
        "aws_iam_user_policy_attachment",
    }
)


@dataclass
class ResourceChange:
    """
    Represents a single planned resource change from a Terraform plan.

    Attributes:
        address:       Full Terraform address (e.g., "module.app.aws_iam_policy.main").
        module_address: Module path, if inside a module (e.g., "module.app").
        type:          Resource type (e.g., "aws_iam_policy").
        name:          Resource name (e.g., "main").
        change_action: The primary action Terraform will take ("create", "update", etc.).
        values:        The `after` state — what the resource will look like post-apply.
                       This is the dict we extract IAM policies from.
    """

    address: str
    type: str
    name: str
    change_action: str
    values: dict[str, Any] = field(default_factory=dict)
    module_address: str = ""

    @property
    def is_iam_resource(self) -> bool:
        """True if this resource type contains IAM policies we should analyze."""
        return self.type in IAM_RESOURCE_TYPES

    @property
    def is_relevant(self) -> bool:
        """True if this change action is something we should analyze.

        We skip 'delete' because removing a resource doesn't introduce new risk.
        """
        return self.change_action in RELEVANT_CHANGE_ACTIONS


@dataclass
class TerraformPlan:
    """
    The parsed representation of a full Terraform plan JSON file.

    Attributes:
        format_version:    The plan JSON schema version (we validate this).
        terraform_version: The Terraform CLI version that generated this plan.
        resource_changes:  All planned resource changes.
        raw:               The raw parsed JSON (kept for debugging).
    """

    format_version: str
    terraform_version: str
    resource_changes: list[ResourceChange] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def iam_resources(self) -> list[ResourceChange]:
        """Return only the relevant IAM resource changes."""
        return [r for r in self.resource_changes if r.is_iam_resource and r.is_relevant]

    @property
    def total_resources(self) -> int:
        """Total number of resources in the plan (regardless of type)."""
        return len(self.resource_changes)
