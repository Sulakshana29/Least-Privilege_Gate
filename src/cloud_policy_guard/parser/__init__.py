"""Parser package — loads and extracts data from Terraform plan JSON."""

from cloud_policy_guard.parser.plan_parser import PlanParser, PlanParseError
from cloud_policy_guard.parser.iam_extractor import IAMExtractor
from cloud_policy_guard.parser.policy_normalizer import PolicyNormalizer

__all__ = ["PlanParser", "PlanParseError", "IAMExtractor", "PolicyNormalizer"]
