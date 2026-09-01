"""Rules package — all security rule classes."""

from cloud_policy_guard.rules.base import BaseRule, BaseTrustRule
from cloud_policy_guard.rules.lp001_wildcard_action import LP001WildcardAction
from cloud_policy_guard.rules.lp002_wildcard_resource import LP002WildcardResource
from cloud_policy_guard.rules.lp003_admin_permissions import LP003AdminPermissions
from cloud_policy_guard.rules.lp004_sensitive_iam_actions import LP004SensitiveIAMActions
from cloud_policy_guard.rules.lp005_excessive_service_perms import LP005ExcessiveServicePerms
from cloud_policy_guard.rules.lp006_broad_trust_policy import LP006BroadTrustPolicy

__all__ = [
    "BaseRule",
    "BaseTrustRule",
    "LP001WildcardAction",
    "LP002WildcardResource",
    "LP003AdminPermissions",
    "LP004SensitiveIAMActions",
    "LP005ExcessiveServicePerms",
    "LP006BroadTrustPolicy",
]
