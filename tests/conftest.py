"""Shared pytest fixtures for Cloud Policy Guard tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from cloud_policy_guard.models.finding import Severity
from cloud_policy_guard.models.iam import IAMPolicy, IAMStatement, TrustPolicy


# ── Policy / Statement factories ──────────────────────────────────────────────

def make_statement(
    effect: str = "Allow",
    actions: list[str] | str | None = None,
    resources: list[str] | str | None = None,
    principals: Any = None,
    conditions: dict | None = None,
    not_actions: list[str] | None = None,
) -> IAMStatement:
    """Factory for creating IAMStatement objects in tests."""
    if actions is None:
        actions = []
    if isinstance(actions, str):
        actions = [actions]
    if resources is None:
        resources = ["*"]
    if isinstance(resources, str):
        resources = [resources]

    raw: dict[str, Any] = {"Effect": effect}
    if actions:
        raw["Action"] = actions if len(actions) > 1 else actions[0]
    if resources:
        raw["Resource"] = resources if len(resources) > 1 else resources[0]
    if principals is not None:
        raw["Principal"] = principals
    if conditions:
        raw["Condition"] = conditions

    return IAMStatement(
        effect=effect,
        actions=actions,
        not_actions=not_actions or [],
        resources=resources,
        principals=principals,
        conditions=conditions or {},
        raw=raw,
    )


def make_policy(
    statements: list[IAMStatement] | None = None,
    resource_address: str = "aws_iam_policy.test",
    resource_type: str = "aws_iam_policy",
    policy_name: str = "test-policy",
) -> IAMPolicy:
    """Factory for creating IAMPolicy objects in tests."""
    return IAMPolicy(
        statements=statements or [],
        resource_address=resource_address,
        resource_type=resource_type,
        policy_name=policy_name,
    )


def make_trust_policy(
    statements: list[IAMStatement] | None = None,
    resource_address: str = "aws_iam_role.test",
    resource_type: str = "aws_iam_role",
    role_name: str = "test-role",
) -> TrustPolicy:
    """Factory for creating TrustPolicy objects in tests."""
    return TrustPolicy(
        statements=statements or [],
        resource_address=resource_address,
        resource_type=resource_type,
        role_name=role_name,
    )


def make_plan_json(resource_changes: list[dict]) -> str:
    """Create a minimal valid Terraform plan JSON string for testing."""
    return json.dumps({
        "format_version": "1.2",
        "terraform_version": "1.6.0",
        "resource_changes": resource_changes,
    })


def make_resource_change(
    address: str = "aws_iam_policy.test",
    resource_type: str = "aws_iam_policy",
    action: str = "create",
    after: dict | None = None,
) -> dict:
    """Create a single resource_changes entry for plan JSON."""
    return {
        "address": address,
        "type": resource_type,
        "name": address.split(".")[-1] if "." in address else address,
        "change": {
            "actions": [action],
            "before": None,
            "after": after or {},
            "after_unknown": {},
        },
    }


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def examples_dir() -> Path:
    """Path to the examples/ directory."""
    return Path(__file__).parent.parent / "examples"


@pytest.fixture
def vulnerable_plan_path(examples_dir: Path) -> Path:
    return examples_dir / "vulnerable" / "plan.json"


@pytest.fixture
def secure_plan_path(examples_dir: Path) -> Path:
    return examples_dir / "secure" / "plan.json"


@pytest.fixture
def wildcard_action_policy() -> IAMPolicy:
    """A policy with Action: '*' — triggers LP001."""
    stmt = make_statement(actions=["*"], resources=["*"])
    return make_policy(statements=[stmt])


@pytest.fixture
def clean_policy() -> IAMPolicy:
    """A policy with specific, scoped permissions — should pass all rules."""
    stmt = make_statement(
        actions=["s3:GetObject", "s3:PutObject"],
        resources=["arn:aws:s3:::my-bucket/my-prefix/*"],
    )
    return make_policy(statements=[stmt])
