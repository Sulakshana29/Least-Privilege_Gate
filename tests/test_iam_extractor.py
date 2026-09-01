"""Tests for the IAM resource extractor."""

from __future__ import annotations

import json

from cloud_policy_guard.models.terraform import ResourceChange
from cloud_policy_guard.parser.iam_extractor import IAMExtractor
from tests.conftest import make_plan_json, make_resource_change
from cloud_policy_guard.parser.plan_parser import PlanParser


def _make_rc(address, rtype, policy_json_str=None, assume_role_policy=None, policy_arn=None):
    after = {}
    if policy_json_str is not None:
        after["policy"] = policy_json_str
    if assume_role_policy is not None:
        after["assume_role_policy"] = assume_role_policy
    if policy_arn is not None:
        after["policy_arn"] = policy_arn
    return ResourceChange(
        address=address, type=rtype, name=address.split(".")[-1],
        change_action="create", values=after
    )


SIMPLE_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]
})

ADMIN_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
})

TRUST_POLICY_LAMBDA = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]
})


class TestIAMExtractor:
    def setup_method(self):
        self.extractor = IAMExtractor()

    def test_extracts_aws_iam_policy(self):
        rc = _make_rc("aws_iam_policy.app", "aws_iam_policy", SIMPLE_POLICY)
        iam_policies, trust_policies = self.extractor.extract([rc])
        assert len(iam_policies) == 1
        assert len(trust_policies) == 0
        assert iam_policies[0].resource_address == "aws_iam_policy.app"

    def test_extracts_aws_iam_role_policy(self):
        rc = _make_rc("aws_iam_role_policy.inline", "aws_iam_role_policy", SIMPLE_POLICY)
        iam_policies, _ = self.extractor.extract([rc])
        assert len(iam_policies) == 1

    def test_extracts_trust_policy_from_aws_iam_role(self):
        rc = _make_rc("aws_iam_role.exec", "aws_iam_role", assume_role_policy=TRUST_POLICY_LAMBDA)
        iam_policies, trust_policies = self.extractor.extract([rc])
        assert len(trust_policies) == 1
        assert len(iam_policies) == 0
        assert trust_policies[0].resource_address == "aws_iam_role.exec"

    def test_extracts_attachment_resource(self):
        rc = _make_rc("aws_iam_role_policy_attachment.admin", "aws_iam_role_policy_attachment",
                      policy_arn="arn:aws:iam::aws:policy/AdministratorAccess")
        iam_policies, _ = self.extractor.extract([rc])
        # Creates synthetic policy for LP003 to inspect
        assert len(iam_policies) == 1
        assert iam_policies[0].policy_name == "arn:aws:iam::aws:policy/AdministratorAccess"

    def test_handles_double_encoded_policy_json(self):
        """Terraform plans often have the policy as a JSON string inside JSON."""
        rc = _make_rc("aws_iam_policy.app", "aws_iam_policy", ADMIN_POLICY)
        iam_policies, _ = self.extractor.extract([rc])
        assert len(iam_policies) == 1
        # Should have parsed the inner JSON and found the wildcard
        stmts = iam_policies[0].statements
        assert len(stmts) == 1
        assert stmts[0].has_wildcard_action

    def test_handles_null_policy_gracefully(self):
        rc = ResourceChange(
            address="aws_iam_policy.null", type="aws_iam_policy",
            name="null", change_action="create",
            values={"policy": None}
        )
        iam_policies, _ = self.extractor.extract([rc])
        assert len(iam_policies) == 0

    def test_handles_missing_policy_key(self):
        rc = ResourceChange(
            address="aws_iam_policy.missing", type="aws_iam_policy",
            name="missing", change_action="create", values={}
        )
        iam_policies, _ = self.extractor.extract([rc])
        assert len(iam_policies) == 0

    def test_handles_invalid_policy_json_string(self):
        rc = ResourceChange(
            address="aws_iam_policy.bad", type="aws_iam_policy",
            name="bad", change_action="create",
            values={"policy": "{not valid json"}
        )
        iam_policies, _ = self.extractor.extract([rc])
        assert len(iam_policies) == 0

    def test_extracts_multiple_resources(self):
        resources = [
            _make_rc("aws_iam_policy.a", "aws_iam_policy", SIMPLE_POLICY),
            _make_rc("aws_iam_policy.b", "aws_iam_policy", ADMIN_POLICY),
            _make_rc("aws_iam_role.c", "aws_iam_role", assume_role_policy=TRUST_POLICY_LAMBDA),
        ]
        iam_policies, trust_policies = self.extractor.extract(resources)
        assert len(iam_policies) == 2
        assert len(trust_policies) == 1

    def test_extracts_from_real_vulnerable_plan(self, vulnerable_plan_path):
        parser = PlanParser()
        plan = parser.parse_file(vulnerable_plan_path)
        iam_policies, trust_policies = self.extractor.extract(plan.iam_resources)
        assert len(iam_policies) >= 1
        assert len(trust_policies) >= 1
