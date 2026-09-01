"""
Terraform Plan Parser
=====================
Loads and validates a Terraform plan JSON file produced by:

    terraform plan -out=tfplan
    terraform show -json tfplan > plan.json

The parser is intentionally strict about structure validation so that
downstream components can assume the data is well-formed. All errors
are wrapped in PlanParseError with clear messages.

Key design decisions:
- We only analyse resources with change action "create" or "update".
  Deleted resources are leaving, not arriving — no new risk introduced.
- We tolerate missing optional fields (module_address, after_unknown)
  because Terraform's plan format has evolved over versions.
- format_version is checked but we warn rather than hard-fail on unknown
  versions, since newer Terraform minor releases are backward-compatible.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from cloud_policy_guard.models.terraform import (
    RELEVANT_CHANGE_ACTIONS,
    ResourceChange,
    TerraformPlan,
)

logger = logging.getLogger(__name__)

# Minimum supported plan format version
MIN_FORMAT_VERSION = "1.0"
# Warn (but don't fail) if version is above this
MAX_KNOWN_FORMAT_VERSION = "1.2"


class PlanParseError(Exception):
    """
    Raised when the Terraform plan JSON cannot be parsed.

    This is distinct from a security finding — it means the input
    file itself is invalid, not that it contains policy violations.
    """

    pass


class PlanParser:
    """
    Parses a Terraform plan JSON file into a structured TerraformPlan object.

    Usage:
        parser = PlanParser()
        plan = parser.parse_file("plan.json")
        # plan.resource_changes → list of ResourceChange
        # plan.iam_resources    → list of IAM-related ResourceChange
    """

    def parse_file(self, path: str | Path) -> TerraformPlan:
        """
        Load and parse a Terraform plan JSON file.

        Args:
            path: Path to the plan.json file.

        Returns:
            A TerraformPlan object with all resource changes populated.

        Raises:
            PlanParseError: If the file does not exist, is not valid JSON,
                            or is missing required structure.
        """
        plan_path = Path(path)

        if not plan_path.exists():
            raise PlanParseError(f"Plan file not found: {plan_path}")

        if not plan_path.is_file():
            raise PlanParseError(f"Path is not a file: {plan_path}")

        try:
            raw_text = plan_path.read_text(encoding="utf-8")
        except OSError as e:
            raise PlanParseError(f"Cannot read plan file: {e}") from e

        return self.parse_json(raw_text, source_path=str(plan_path))

    def parse_json(self, json_text: str, source_path: str = "<stdin>") -> TerraformPlan:
        """
        Parse a Terraform plan from a JSON string.

        This method exists separately from parse_file so that tests can
        pass JSON strings directly without needing files on disk.

        Args:
            json_text:   Raw JSON string of the plan.
            source_path: Label for error messages (file path or "<stdin>").

        Returns:
            A TerraformPlan object.

        Raises:
            PlanParseError: On any structural or parsing error.
        """
        if not json_text or not json_text.strip():
            raise PlanParseError("Plan file is empty.")

        try:
            raw: dict[str, Any] = json.loads(json_text)
        except json.JSONDecodeError as e:
            raise PlanParseError(
                f"Plan file contains invalid JSON: {e.msg} (line {e.lineno}, col {e.colno})"
            ) from e

        if not isinstance(raw, dict):
            raise PlanParseError("Plan file must be a JSON object, not an array or scalar.")

        return self._build_plan(raw, source_path)

    # ──────────────────────────────────────────────────────────────────────────
    # Private helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _build_plan(self, raw: dict[str, Any], source_path: str) -> TerraformPlan:
        """Validate structure and assemble the TerraformPlan object."""

        format_version = self._extract_format_version(raw)
        terraform_version = raw.get("terraform_version", "unknown")

        if "resource_changes" not in raw:
            # A plan with no resources at all is valid (empty module)
            logger.warning(
                "%s: Plan has no 'resource_changes' key — no resources to scan.", source_path
            )
            return TerraformPlan(
                format_version=format_version,
                terraform_version=terraform_version,
                resource_changes=[],
                raw=raw,
            )

        raw_changes = raw["resource_changes"]

        if not isinstance(raw_changes, list):
            raise PlanParseError("'resource_changes' must be a JSON array.")

        resource_changes = []
        for i, item in enumerate(raw_changes):
            try:
                rc = self._parse_resource_change(item)
                if rc is not None:
                    resource_changes.append(rc)
            except (KeyError, TypeError, ValueError) as e:
                # Log and skip malformed individual entries rather than failing the whole scan
                logger.warning(
                    "%s: Skipping malformed resource_changes[%d]: %s", source_path, i, e
                )

        logger.info(
            "Parsed %d resource changes from %s (Terraform %s)",
            len(resource_changes),
            source_path,
            terraform_version,
        )

        return TerraformPlan(
            format_version=format_version,
            terraform_version=terraform_version,
            resource_changes=resource_changes,
            raw=raw,
        )

    def _extract_format_version(self, raw: dict[str, Any]) -> str:
        """Validate the plan format_version for compatibility."""
        format_version = raw.get("format_version", "")

        if not format_version:
            logger.warning(
                "Plan is missing 'format_version'. This may not be a valid Terraform plan JSON. "
                "Generate one with: terraform show -json tfplan > plan.json"
            )
            return "unknown"

        try:
            major = int(format_version.split(".")[0])
            if major < 1:
                raise PlanParseError(
                    f"Unsupported plan format_version '{format_version}'. "
                    f"Cloud Policy Guard requires Terraform >= 0.13 (format >= 1.0)."
                )
        except (IndexError, ValueError):
            logger.warning("Unexpected format_version value: '%s'", format_version)

        if format_version > MAX_KNOWN_FORMAT_VERSION:
            logger.warning(
                "Plan format_version '%s' is newer than tested maximum '%s'. "
                "Results may be incomplete.",
                format_version,
                MAX_KNOWN_FORMAT_VERSION,
            )

        return format_version

    def _parse_resource_change(self, item: Any) -> ResourceChange | None:
        """
        Parse a single entry from the resource_changes array.

        Returns None if the change action means we should skip it
        (e.g., 'delete' — removing a resource doesn't introduce new risk).
        """
        if not isinstance(item, dict):
            raise TypeError(f"resource_changes entry must be an object, got {type(item).__name__}")

        address = item.get("address", "")
        resource_type = item.get("type", "")
        name = item.get("name", "")
        module_address = item.get("module_address", "")

        change = item.get("change", {})
        if not isinstance(change, dict):
            raise ValueError(f"'change' field for {address!r} must be an object")

        # Determine the primary action
        # actions is a list like ["create"], ["update"], ["delete"], ["no-op"]
        actions = change.get("actions", [])
        if not actions:
            return None

        primary_action = actions[0] if isinstance(actions, list) else str(actions)

        # Skip deletes — we only care about what will exist, not what's leaving
        if primary_action not in RELEVANT_CHANGE_ACTIONS:
            logger.debug("Skipping %s (action: %s)", address, primary_action)
            return None

        # Extract the planned final state
        # 'after' is null for destroys; for creates/updates it's the full resource attributes
        after_values: dict[str, Any] = change.get("after") or {}
        if not isinstance(after_values, dict):
            after_values = {}

        return ResourceChange(
            address=address,
            type=resource_type,
            name=name,
            change_action=primary_action,
            values=after_values,
            module_address=module_address,
        )
