"""
IAM Resource Extractor
======================
Identifies IAM-related resources in a Terraform plan and extracts
their policy documents into normalized IAMPolicy / TrustPolicy objects.

Why this is its own module:
- Each Terraform resource type stores IAM policy data differently
  (different attribute names, different nesting, sometimes double-encoded JSON)
- Centralizing extraction logic keeps the rule engine clean and focused

Supported resource types:
    aws_iam_policy              → values.policy (JSON string)
    aws_iam_role_policy         → values.policy (JSON string)
    aws_iam_user_policy         → values.policy (JSON string)
    aws_iam_group_policy        → values.policy (JSON string)
    aws_iam_role                → values.assume_role_policy (trust policy, JSON string)
    aws_iam_role_policy_attachment  → values.policy_arn (detect dangerous managed policies)
    aws_iam_policy_attachment   → values.policy_arn (detect dangerous managed policies)
"""

from __future__ import annotations

import json
import logging
from typing import Any

from cloud_policy_guard.models.iam import IAMPolicy, TrustPolicy
from cloud_policy_guard.models.terraform import ResourceChange
from cloud_policy_guard.parser.policy_normalizer import PolicyNormalizer

logger = logging.getLogger(__name__)

# Terraform resource types that contain inline IAM policy JSON
POLICY_RESOURCE_TYPES = frozenset(
    {
        "aws_iam_policy",
        "aws_iam_role_policy",
        "aws_iam_user_policy",
        "aws_iam_group_policy",
    }
)

# Terraform resource types that attach a managed policy by ARN
ATTACHMENT_RESOURCE_TYPES = frozenset(
    {
        "aws_iam_role_policy_attachment",
        "aws_iam_policy_attachment",
        "aws_iam_user_policy_attachment",
    }
)

# Known dangerous AWS managed policy ARNs
# These are real ARNs for AWS-managed policies granting broad permissions
DANGEROUS_MANAGED_POLICY_ARNS = {
    "arn:aws:iam::aws:policy/AdministratorAccess": "Grants full access to all AWS services",
    "arn:aws:iam::aws:policy/IAMFullAccess": "Grants full access to IAM — can create admin users",
    "arn:aws:iam::aws:policy/PowerUserAccess": "Grants broad access excluding IAM user management",
    "arn:aws:iam::aws:policy/SecurityAudit": "Read-only security metadata access (generally acceptable)",
}


class IAMExtractor:
    """
    Extracts IAM policy documents from Terraform plan resource changes.

    Usage:
        extractor = IAMExtractor()
        iam_policies, trust_policies = extractor.extract(plan.iam_resources)
    """

    def __init__(self) -> None:
        self._normalizer = PolicyNormalizer()

    def extract(
        self, resource_changes: list[ResourceChange]
    ) -> tuple[list[IAMPolicy], list[TrustPolicy]]:
        """
        Extract all IAM policies and trust policies from a list of resource changes.

        Args:
            resource_changes: IAM-related resource changes from the Terraform plan.

        Returns:
            A tuple of (iam_policies, trust_policies).
            - iam_policies: Identity-based policies (for LP001–LP005)
            - trust_policies: Trust relationships (for LP006)
        """
        iam_policies: list[IAMPolicy] = []
        trust_policies: list[TrustPolicy] = []

        for resource in resource_changes:
            if resource.type in POLICY_RESOURCE_TYPES:
                policy = self._extract_identity_policy(resource)
                if policy is not None:
                    iam_policies.append(policy)

            elif resource.type == "aws_iam_role":
                # Roles have TWO relevant parts:
                # 1. The trust policy (assume_role_policy) — who can assume it
                # 2. Inline policies can be in aws_iam_role_policy resources (handled separately)
                trust_policy = self._extract_trust_policy(resource)
                if trust_policy is not None:
                    trust_policies.append(trust_policy)

            elif resource.type in ATTACHMENT_RESOURCE_TYPES:
                # For attachments we synthesize a minimal IAMPolicy containing just
                # the policy ARN so LP003 can flag dangerous managed policy attachments
                synthetic_policy = self._extract_attachment_policy(resource)
                if synthetic_policy is not None:
                    iam_policies.append(synthetic_policy)

        logger.info(
            "Extracted %d IAM policies and %d trust policies from %d resources",
            len(iam_policies),
            len(trust_policies),
            len(resource_changes),
        )
        return iam_policies, trust_policies

    # ──────────────────────────────────────────────────────────────────────────

    def _extract_identity_policy(self, resource: ResourceChange) -> IAMPolicy | None:
        """Extract an identity-based policy from aws_iam_policy / aws_iam_role_policy etc."""
        raw_policy = resource.values.get("policy")

        if raw_policy is None:
            logger.debug(
                "%s: 'policy' attribute is null or missing (may be known-after-apply). Skipping.",
                resource.address,
            )
            return None

        policy_doc = self._parse_policy_value(raw_policy, resource.address)
        if policy_doc is None:
            return None

        statements = self._normalizer.normalize_statements(policy_doc, resource.address)
        policy_name = resource.values.get("name", "")

        return IAMPolicy(
            statements=statements,
            resource_address=resource.address,
            resource_type=resource.type,
            policy_name=policy_name,
        )

    def _extract_trust_policy(self, resource: ResourceChange) -> TrustPolicy | None:
        """Extract a trust policy (assume_role_policy) from aws_iam_role."""
        raw_trust = resource.values.get("assume_role_policy")

        if raw_trust is None:
            logger.debug(
                "%s: 'assume_role_policy' is null or missing. Skipping.", resource.address
            )
            return None

        trust_doc = self._parse_policy_value(raw_trust, resource.address)
        if trust_doc is None:
            return None

        statements = self._normalizer.normalize_statements(trust_doc, resource.address)
        role_name = resource.values.get("name", "")

        return TrustPolicy(
            statements=statements,
            resource_address=resource.address,
            resource_type=resource.type,
            role_name=role_name,
        )

    def _extract_attachment_policy(self, resource: ResourceChange) -> IAMPolicy | None:
        """
        Create a synthetic IAMPolicy for managed policy attachments.

        When a resource attaches a managed policy by ARN (e.g., AdministratorAccess),
        there is no inline policy JSON to parse. Instead we create a placeholder
        statement with the ARN in the evidence, so LP003 can flag it.
        """
        policy_arn = resource.values.get("policy_arn", "")

        if not policy_arn:
            return None

        # We don't create actual IAMStatement objects here —
        # LP003 handles attachment detection separately via the resource values.
        # We store the ARN in the policy_name field so the rule can access it.
        return IAMPolicy(
            statements=[],
            resource_address=resource.address,
            resource_type=resource.type,
            policy_name=policy_arn,  # ARN stored here for LP003 to inspect
        )

    def _parse_policy_value(
        self, raw_policy: Any, resource_address: str
    ) -> dict[str, Any] | None:
        """
        Parse a policy value that may be a JSON string or already a dict.

        Terraform plan JSON often double-encodes IAM policies:
        the Terraform resource attribute is a string, and inside that string
        is more JSON. So the plan contains:

            "policy": "{\"Version\": \"2012-10-17\", \"Statement\": [...]}"

        We handle both the double-encoded string case and the (rarer) case
        where the policy is already a parsed object.
        """
        if isinstance(raw_policy, dict):
            # Already parsed — use directly
            return raw_policy

        if isinstance(raw_policy, str):
            raw_policy = raw_policy.strip()
            if not raw_policy:
                logger.debug("%s: Empty policy string. Skipping.", resource_address)
                return None
            try:
                parsed = json.loads(raw_policy)
                if not isinstance(parsed, dict):
                    logger.warning(
                        "%s: Policy JSON is not an object (got %s). Skipping.",
                        resource_address,
                        type(parsed).__name__,
                    )
                    return None
                return parsed
            except json.JSONDecodeError as e:
                logger.warning(
                    "%s: Cannot parse policy JSON: %s. Skipping.", resource_address, e
                )
                return None

        logger.warning(
            "%s: Unexpected policy type %s. Skipping.", resource_address, type(raw_policy).__name__
        )
        return None
