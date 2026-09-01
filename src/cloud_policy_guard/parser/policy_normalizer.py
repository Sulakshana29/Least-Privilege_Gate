"""
Policy Normalizer
=================
Converts raw IAM policy JSON into a list of normalized IAMStatement objects.

The AWS IAM policy language is flexible in ways that complicate analysis:

1. Action can be a string or a list:
       "Action": "s3:GetObject"          ← valid
       "Action": ["s3:GetObject", "s3:PutObject"]  ← also valid

2. Resource can be a string or a list:
       "Resource": "*"                   ← valid
       "Resource": ["arn:aws:s3:::bucket", "*"]    ← also valid

3. Principal (in trust policies) can be:
       "Principal": "*"                  ← anyone
       "Principal": {"AWS": "arn:..."}   ← single ARN as string
       "Principal": {"AWS": ["arn:...", "arn:..."]}  ← multiple ARNs as list
       "Principal": {"Service": "lambda.amazonaws.com"}

4. NotAction / NotResource are the inverse of Action / Resource.
   "NotAction": ["s3:DeleteObject"] means "all actions EXCEPT s3:DeleteObject"
   These can grant extremely broad permissions and should be flagged.

This normalizer converts everything to consistent list form so that
rule code can simply do:
    if "*" in statement.actions:   # always works, never need to check for string
"""

from __future__ import annotations

import logging
from typing import Any

from cloud_policy_guard.models.iam import IAMStatement

logger = logging.getLogger(__name__)


class PolicyNormalizer:
    """
    Normalizes raw IAM policy Statement arrays into IAMStatement objects.

    This class is stateless — it can be reused across many policies.
    """

    def normalize_statements(
        self, policy_doc: dict[str, Any], resource_address: str = ""
    ) -> list[IAMStatement]:
        """
        Parse and normalize all statements from an IAM policy document.

        Args:
            policy_doc:       Parsed IAM policy dict (must have a 'Statement' key).
            resource_address: Used only for log messages.

        Returns:
            List of normalized IAMStatement objects.
            Returns empty list if Statement is missing or malformed.
        """
        raw_statements = policy_doc.get("Statement", [])

        if not isinstance(raw_statements, list):
            # Some policies have a single statement object instead of a list
            if isinstance(raw_statements, dict):
                raw_statements = [raw_statements]
            else:
                logger.warning(
                    "%s: 'Statement' is not an array (got %s). No statements extracted.",
                    resource_address,
                    type(raw_statements).__name__,
                )
                return []

        statements = []
        for i, raw_stmt in enumerate(raw_statements):
            if not isinstance(raw_stmt, dict):
                logger.warning(
                    "%s: Statement[%d] is not an object. Skipping.", resource_address, i
                )
                continue
            stmt = self._normalize_statement(raw_stmt, resource_address, i)
            statements.append(stmt)

        return statements

    # ──────────────────────────────────────────────────────────────────────────

    def _normalize_statement(
        self, raw: dict[str, Any], resource_address: str, index: int
    ) -> IAMStatement:
        """Normalize a single raw IAM statement dict into an IAMStatement."""

        effect = raw.get("Effect", "Allow")  # Default is Allow per AWS spec
        if not isinstance(effect, str):
            effect = "Allow"

        actions = self._to_list(raw.get("Action", []))
        not_actions = self._to_list(raw.get("NotAction", []))
        resources = self._to_list(raw.get("Resource", []))
        not_resources = self._to_list(raw.get("NotResource", []))
        conditions = raw.get("Condition") or {}
        principals = raw.get("Principal")  # Keep raw — LP006 handles normalization

        if not_actions:
            logger.debug(
                "%s: Statement[%d] uses NotAction — grants all actions EXCEPT listed ones. "
                "This can be very broad.",
                resource_address,
                index,
            )

        if not_resources:
            logger.debug(
                "%s: Statement[%d] uses NotResource — applies to all resources EXCEPT listed ones.",
                resource_address,
                index,
            )

        return IAMStatement(
            effect=effect,
            actions=actions,
            not_actions=not_actions,
            resources=resources,
            not_resources=not_resources,
            principals=principals,
            conditions=conditions if isinstance(conditions, dict) else {},
            raw=raw,
        )

    @staticmethod
    def _to_list(value: Any) -> list[str]:
        """
        Normalize a string-or-list IAM field to always be a list of strings.

        Handles:
            None           → []
            "*"            → ["*"]
            "s3:GetObject" → ["s3:GetObject"]
            ["s3:*"]       → ["s3:*"]
            []             → []
        """
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [str(v) for v in value if v is not None]
        # Unexpected type — return empty to be safe
        logger.warning("Unexpected IAM field value type: %s (value: %r)", type(value).__name__, value)
        return []
