"""
JSON Reporter
=============
Serializes a scan result to the stable JSON schema documented in
docs/risk-model.md. Used when --format json is specified.

The JSON output is designed to be consumed by CI/CD systems, dashboards,
and other tooling. The schema is versioned and must not change without
a version bump in pyproject.toml.

Schema version: 0.1.0
"""

from __future__ import annotations

import json
import sys

from cloud_policy_guard.models.scan_result import ScanResult


class JsonReporter:
    """Renders scan results as structured JSON to stdout."""

    def render(self, result: ScanResult) -> None:
        """
        Print the scan result as pretty-printed JSON to stdout.

        The JSON is printed with 2-space indentation for readability while
        remaining machine-parseable. CI/CD systems can pipe this to jq or
        store it as an artifact.
        """
        data = result.to_dict()
        print(json.dumps(data, indent=2))
