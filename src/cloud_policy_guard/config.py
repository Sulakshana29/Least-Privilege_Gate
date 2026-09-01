"""
Configuration management for Cloud Policy Guard.

Configuration is loaded in this priority order (highest wins):
    1. CLI flags (--fail-on, --format, etc.)
    2. Config file (.cpg.yaml in current directory, or --config flag)
    3. Built-in defaults

Config file schema (.cpg.yaml):
    fail_on: critical          # Severity threshold: critical|high|medium|low
    max_risk_score: null       # Optional integer cap on total risk score
    exclude_rules: []          # List of rule IDs to skip, e.g. ["LP005"]
    format: text               # Output format: text|json

CLI flags always override the config file.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_FILENAME = ".cpg.yaml"

# Built-in defaults
DEFAULTS: dict[str, Any] = {
    "fail_on": "critical",
    "max_risk_score": None,
    "exclude_rules": [],
    "format": "text",
}


@dataclass
class Config:
    """
    Resolved configuration for a Cloud Policy Guard scan.

    All values are already merged from defaults + config file + CLI flags.
    """

    fail_on: str = "critical"
    max_risk_score: int | None = None
    exclude_rules: list[str] = field(default_factory=list)
    output_format: str = "text"

    def __post_init__(self) -> None:
        """Validate configuration values."""
        valid_fail_on = {"critical", "high", "medium", "low", "info"}
        if self.fail_on.lower() not in valid_fail_on:
            raise ValueError(
                f"Invalid fail_on value '{self.fail_on}'. "
                f"Must be one of: {sorted(valid_fail_on)}"
            )

        valid_formats = {"text", "json"}
        if self.output_format.lower() not in valid_formats:
            raise ValueError(
                f"Invalid format '{self.output_format}'. Must be one of: {sorted(valid_formats)}"
            )

        if self.max_risk_score is not None and self.max_risk_score < 0:
            raise ValueError("max_risk_score must be a non-negative integer.")


def load_config(
    config_path: str | None = None,
    # CLI override values (None means "not provided")
    cli_fail_on: str | None = None,
    cli_max_risk_score: int | None = None,
    cli_format: str | None = None,
    cli_exclude_rules: list[str] | None = None,
) -> Config:
    """
    Load and merge configuration from file and CLI overrides.

    Args:
        config_path:        Explicit path to config file (from --config flag).
        cli_fail_on:        --fail-on CLI value.
        cli_max_risk_score: --max-risk-score CLI value.
        cli_format:         --format CLI value.
        cli_exclude_rules:  --exclude-rules CLI values.

    Returns:
        Resolved Config with all sources merged.
    """
    # Start with defaults
    merged = dict(DEFAULTS)

    # Load config file
    file_config = _load_config_file(config_path)
    merged.update({k: v for k, v in file_config.items() if v is not None})

    # Apply CLI overrides (highest priority)
    if cli_fail_on is not None:
        merged["fail_on"] = cli_fail_on
    if cli_max_risk_score is not None:
        merged["max_risk_score"] = cli_max_risk_score
    if cli_format is not None:
        merged["format"] = cli_format
    if cli_exclude_rules:
        merged["exclude_rules"] = cli_exclude_rules

    return Config(
        fail_on=merged["fail_on"],
        max_risk_score=merged.get("max_risk_score"),
        exclude_rules=merged.get("exclude_rules", []),
        output_format=merged["format"],
    )


def _load_config_file(config_path: str | None) -> dict[str, Any]:
    """Load YAML config file, returning empty dict if not found."""
    if config_path:
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")
    else:
        # Auto-discover in current directory
        path = Path.cwd() / DEFAULT_CONFIG_FILENAME
        if not path.exists():
            return {}

    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        logger.debug("Loaded config from %s", path)
        return data
    except yaml.YAMLError as e:
        logger.warning("Could not parse config file %s: %s. Using defaults.", path, e)
        return {}
