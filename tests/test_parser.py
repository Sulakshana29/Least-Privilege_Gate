"""Tests for the Terraform plan parser."""

from __future__ import annotations

import json

import pytest

from cloud_policy_guard.parser.plan_parser import PlanParseError, PlanParser
from tests.conftest import make_plan_json, make_resource_change


class TestPlanParser:
    def setup_method(self):
        self.parser = PlanParser()

    # ── Valid plans ────────────────────────────────────────────────────────────

    def test_parses_valid_plan_with_resources(self):
        plan_json = make_plan_json([
            make_resource_change("aws_iam_policy.test", "aws_iam_policy"),
            make_resource_change("aws_s3_bucket.logs", "aws_s3_bucket"),
        ])
        plan = self.parser.parse_json(plan_json)
        assert plan.format_version == "1.2"
        assert plan.terraform_version == "1.6.0"
        assert plan.total_resources == 2

    def test_parses_empty_resource_changes(self):
        plan_json = make_plan_json([])
        plan = self.parser.parse_json(plan_json)
        assert plan.total_resources == 0
        assert plan.iam_resources == []

    def test_filters_iam_resources_correctly(self):
        plan_json = make_plan_json([
            make_resource_change("aws_iam_policy.app", "aws_iam_policy"),
            make_resource_change("aws_s3_bucket.data", "aws_s3_bucket"),
            make_resource_change("aws_iam_role.exec", "aws_iam_role"),
        ])
        plan = self.parser.parse_json(plan_json)
        assert plan.total_resources == 3
        assert len(plan.iam_resources) == 2
        addresses = [r.address for r in plan.iam_resources]
        assert "aws_iam_policy.app" in addresses
        assert "aws_iam_role.exec" in addresses

    def test_skips_delete_actions(self):
        """Deleting a resource doesn't introduce new risk — should be skipped."""
        plan_json = make_plan_json([
            make_resource_change("aws_iam_policy.old", "aws_iam_policy", action="delete"),
        ])
        plan = self.parser.parse_json(plan_json)
        assert plan.total_resources == 0

    def test_includes_update_and_no_op_actions(self):
        plan_json = make_plan_json([
            make_resource_change("aws_iam_policy.a", "aws_iam_policy", action="update"),
            make_resource_change("aws_iam_role.b", "aws_iam_role", action="no-op"),
        ])
        plan = self.parser.parse_json(plan_json)
        assert plan.total_resources == 2

    def test_plan_missing_format_version_warns_not_fails(self):
        raw = {"resource_changes": []}
        plan = self.parser.parse_json(json.dumps(raw))
        assert plan.format_version == "unknown"

    def test_plan_without_resource_changes_key(self):
        """Plan with no resource_changes key is valid (e.g., empty module)."""
        raw = {"format_version": "1.2", "terraform_version": "1.6.0"}
        plan = self.parser.parse_json(json.dumps(raw))
        assert plan.total_resources == 0

    # ── Error cases ────────────────────────────────────────────────────────────

    def test_raises_on_empty_string(self):
        with pytest.raises(PlanParseError, match="empty"):
            self.parser.parse_json("")

    def test_raises_on_whitespace_only(self):
        with pytest.raises(PlanParseError, match="empty"):
            self.parser.parse_json("   \n  ")

    def test_raises_on_invalid_json(self):
        with pytest.raises(PlanParseError, match="invalid JSON"):
            self.parser.parse_json("{not valid json")

    def test_raises_on_json_array_instead_of_object(self):
        with pytest.raises(PlanParseError, match="JSON object"):
            self.parser.parse_json("[1, 2, 3]")

    def test_raises_on_file_not_found(self, tmp_path):
        with pytest.raises(PlanParseError, match="not found"):
            self.parser.parse_file(tmp_path / "nonexistent.json")

    def test_parses_real_file(self, vulnerable_plan_path):
        plan = self.parser.parse_file(vulnerable_plan_path)
        assert plan.total_resources >= 1
        assert len(plan.iam_resources) >= 1

    def test_resource_change_values_populated(self):
        plan_json = make_plan_json([
            make_resource_change(
                "aws_iam_policy.app",
                "aws_iam_policy",
                after={"name": "my-policy", "policy": '{"Version":"2012-10-17","Statement":[]}'},
            )
        ])
        plan = self.parser.parse_json(plan_json)
        resource = plan.resource_changes[0]
        assert resource.values["name"] == "my-policy"

    def test_malformed_resource_change_entry_skipped(self):
        """Individual malformed entries should be skipped, not crash the parse."""
        raw = {
            "format_version": "1.2",
            "terraform_version": "1.6.0",
            "resource_changes": [
                "not a dict",  # malformed
                make_resource_change("aws_iam_policy.valid", "aws_iam_policy"),
            ],
        }
        plan = self.parser.parse_json(json.dumps(raw))
        # Valid entry should still be parsed
        assert plan.total_resources == 1
