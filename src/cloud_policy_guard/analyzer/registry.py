"""
Rule Registry
=============
Manages the set of active security rules for a scan.

The registry is the single place that knows about all rules.
To add a new rule, import it here and add it to IDENTITY_RULES or TRUST_RULES.

Design decision: explicit registration over auto-discovery
----------------------------------------------------------
We deliberately use explicit imports rather than dynamic discovery (e.g.,
scanning the rules/ directory for subclasses). This is intentional:

1. It's immediately clear which rules are active by reading this file.
2. Adding a rule requires a conscious code change — no accidental activation.
3. It works correctly with all packaging and bundling scenarios.
4. Static analysis tools can see all imports.

The tradeoff is that you must add a line here when creating a new rule.
For a security tool, this is the right tradeoff.
"""

from __future__ import annotations

import logging

from cloud_policy_guard.rules.base import BaseRule, BaseTrustRule
from cloud_policy_guard.rules.lp001_wildcard_action import LP001WildcardAction
from cloud_policy_guard.rules.lp002_wildcard_resource import LP002WildcardResource
from cloud_policy_guard.rules.lp003_admin_permissions import LP003AdminPermissions
from cloud_policy_guard.rules.lp004_sensitive_iam_actions import LP004SensitiveIAMActions
from cloud_policy_guard.rules.lp005_excessive_service_perms import LP005ExcessiveServicePerms
from cloud_policy_guard.rules.lp006_broad_trust_policy import LP006BroadTrustPolicy

logger = logging.getLogger(__name__)

# Rules applied to identity-based policies (aws_iam_policy, aws_iam_role_policy, etc.)
_IDENTITY_RULES: list[type[BaseRule]] = [
    LP001WildcardAction,
    LP002WildcardResource,
    LP003AdminPermissions,
    LP004SensitiveIAMActions,
    LP005ExcessiveServicePerms,
]

# Rules applied to trust policies (aws_iam_role assume_role_policy)
_TRUST_RULES: list[type[BaseTrustRule]] = [
    LP006BroadTrustPolicy,
]


class RuleRegistry:
    """
    Manages the set of active rules for a scan, respecting exclusions.

    Usage:
        registry = RuleRegistry(exclude_rules=["LP005"])
        identity_rules = registry.get_identity_rules()
        trust_rules = registry.get_trust_rules()
    """

    def __init__(self, exclude_rules: list[str] | None = None) -> None:
        """
        Initialize the registry.

        Args:
            exclude_rules: List of rule IDs to disable (e.g., ["LP005", "LP002"]).
        """
        self._excluded = set(exclude_rules or [])

        if self._excluded:
            logger.info("Excluding rules: %s", ", ".join(sorted(self._excluded)))

    def get_identity_rules(self) -> list[BaseRule]:
        """Return instantiated identity-policy rules (for LP001–LP005)."""
        return [
            rule_cls()
            for rule_cls in _IDENTITY_RULES
            if rule_cls.rule_id not in self._excluded
        ]

    def get_trust_rules(self) -> list[BaseTrustRule]:
        """Return instantiated trust-policy rules (for LP006)."""
        return [
            rule_cls()
            for rule_cls in _TRUST_RULES
            if rule_cls.rule_id not in self._excluded
        ]

    def all_rule_metadata(self) -> list[dict[str, str]]:
        """
        Return metadata for all registered rules (both identity and trust).
        Used by the `cpg rules` CLI command to list available rules.
        """
        all_rules: list[type[BaseRule] | type[BaseTrustRule]] = (
            _IDENTITY_RULES + _TRUST_RULES  # type: ignore[operator]
        )
        return [
            {
                "rule_id": rule_cls.rule_id,
                "title": rule_cls.title,
                "severity": rule_cls.default_severity.value,
                "description": rule_cls.description,
                "excluded": str(rule_cls.rule_id in self._excluded),
            }
            for rule_cls in all_rules
        ]
