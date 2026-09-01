"""
Console Reporter
================
Renders a Cloud Policy Guard scan result to the terminal with color
and structure. Uses ANSI escape codes directly — no external dependencies.

Output structure:
  1. Banner
  2. Scan summary (resources, IAM resources, policies)
  3. Findings (grouped/sorted by severity, highest first)
  4. Risk score summary
  5. Gate decision (PASS in green, FAIL in red)
"""

from __future__ import annotations

import sys

from cloud_policy_guard.models.finding import Finding, Severity
from cloud_policy_guard.models.scan_result import GateDecision, ScanResult

# ANSI color codes
class _C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    ORANGE = "\033[38;5;214m"

    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"


def _severity_color(severity: Severity) -> str:
    return {
        Severity.CRITICAL: _C.RED + _C.BOLD,
        Severity.HIGH: _C.ORANGE,
        Severity.MEDIUM: _C.YELLOW,
        Severity.LOW: _C.BLUE,
        Severity.INFO: _C.DIM,
    }.get(severity, _C.RESET)


def _severity_badge(severity: Severity) -> str:
    color = _severity_color(severity)
    return f"{color}[{severity.value.upper()}]{_C.RESET}"


class ConsoleReporter:
    """Renders scan results to stdout in human-readable, colored format."""

    def __init__(self, use_color: bool = True) -> None:
        # Disable color when stdout is not a TTY (e.g., piped to a file)
        self._color = use_color and sys.stdout.isatty()

    def render(self, result: ScanResult) -> None:
        """Print the complete scan report to stdout."""
        self._banner()
        self._summary(result)

        if result.findings:
            self._findings_section(result)
        else:
            self._print(f"\n  {_C.GREEN}✓ No security findings detected.{_C.RESET}\n")

        self._risk_summary(result)
        self._gate_decision(result)

    # ──────────────────────────────────────────────────────────────────────────

    def _banner(self) -> None:
        self._print()
        self._print(f"{_C.CYAN}{_C.BOLD}{'=' * 62}{_C.RESET}")
        self._print(f"{_C.CYAN}{_C.BOLD}  CLOUD POLICY GUARD{_C.RESET}")
        self._print(f"{_C.DIM}  AWS IAM Least Privilege Security Gate{_C.RESET}")
        self._print(f"{_C.CYAN}{_C.BOLD}{'=' * 62}{_C.RESET}")
        self._print()

    def _summary(self, result: ScanResult) -> None:
        self._print(f"  {_C.BOLD}Scan Summary{_C.RESET}")
        self._print(f"  {'─' * 40}")
        if result.terraform_plan_path:
            self._print(f"  Plan:              {_C.WHITE}{result.terraform_plan_path}{_C.RESET}")
        self._print(f"  Resources scanned: {_C.WHITE}{result.resources_scanned}{_C.RESET}")
        self._print(f"  IAM resources:     {_C.WHITE}{result.iam_resources_found}{_C.RESET}")
        self._print(f"  Policies analyzed: {_C.WHITE}{result.policies_analyzed}{_C.RESET}")
        self._print()

    def _findings_section(self, result: ScanResult) -> None:
        findings = result.findings_by_severity
        self._print(
            f"  {_C.BOLD}Findings  "
            f"{_C.DIM}({len(findings)} total){_C.RESET}"
        )
        self._print(f"  {'─' * 40}")
        self._print()

        for finding in findings:
            self._render_finding(finding)

    def _render_finding(self, finding: Finding) -> None:
        badge = _severity_badge(finding.severity)
        color = _severity_color(finding.severity)

        self._print(f"  {badge} {color}{_C.BOLD}{finding.rule_id}{_C.RESET}  {_C.WHITE}{finding.title}{_C.RESET}")
        self._print(f"  {_C.DIM}Resource: {finding.resource_address}  ({finding.resource_type}){_C.RESET}")
        self._print()

        # Description — word-wrap at 70 chars
        self._print(f"  {_C.BOLD}Problem:{_C.RESET}")
        for line in self._wrap(finding.description, 70):
            self._print(f"    {line}")
        self._print()

        # Evidence — show as a code block
        self._print(f"  {_C.BOLD}Evidence:{_C.RESET}")
        for line in finding.evidence.splitlines():
            self._print(f"    {_C.CYAN}{line}{_C.RESET}")
        self._print()

        # Remediation
        self._print(f"  {_C.BOLD}Remediation:{_C.RESET}")
        for line in self._wrap(finding.remediation, 70):
            self._print(f"    {_C.GREEN}{line}{_C.RESET}")

        self._print()
        self._print(f"  {'- ' * 29}")
        self._print()

    def _risk_summary(self, result: ScanResult) -> None:
        s = result.severity_summary
        self._print(f"  {_C.BOLD}Risk Summary{_C.RESET}")
        self._print(f"  {'─' * 40}")

        if s.critical:
            self._print(f"  Critical:  {_C.RED}{_C.BOLD}{s.critical}{_C.RESET}")
        if s.high:
            self._print(f"  High:      {_C.ORANGE}{s.high}{_C.RESET}")
        if s.medium:
            self._print(f"  Medium:    {_C.YELLOW}{s.medium}{_C.RESET}")
        if s.low:
            self._print(f"  Low:       {_C.BLUE}{s.low}{_C.RESET}")
        if s.info:
            self._print(f"  Info:      {_C.DIM}{s.info}{_C.RESET}")

        if not result.findings:
            self._print(f"  Findings:  {_C.GREEN}0{_C.RESET}")

        self._print()
        self._print(
            f"  {_C.BOLD}Risk Score:{_C.RESET}  "
            f"{_C.WHITE}{_C.BOLD}{result.risk_score}{_C.RESET}"
            f"  {_C.DIM}(Cloud Policy Guard risk model — see docs/risk-model.md){_C.RESET}"
        )
        self._print()

    def _gate_decision(self, result: ScanResult) -> None:
        self._print(f"  {'=' * 58}")

        if result.gate_decision == GateDecision.PASS:
            self._print(
                f"\n  {_C.GREEN}{_C.BOLD}✓  SECURITY GATE: PASSED{_C.RESET}\n"
            )
            self._print(f"  {_C.GREEN}{result.gate_reason}{_C.RESET}")
            self._print(f"\n  {_C.DIM}Deployment may proceed.{_C.RESET}\n")
        else:
            self._print(
                f"\n  {_C.RED}{_C.BOLD}✗  SECURITY GATE: FAILED{_C.RESET}\n"
            )
            self._print(f"  {_C.RED}{result.gate_reason}{_C.RESET}")
            self._print(f"\n  {_C.RED}{_C.BOLD}Deployment should not proceed.{_C.RESET}\n")

        self._print(f"  {'=' * 58}")
        self._print()

    # ──────────────────────────────────────────────────────────────────────────

    def _print(self, text: str = "") -> None:
        """Print to stdout, stripping ANSI codes if color is disabled."""
        import re
        if not self._color:
            text = re.sub(r"\033\[[0-9;]*m", "", text)
        # Write as UTF-8 bytes to avoid Windows cp1252 codec errors
        try:
            sys.stdout.buffer.write((text + "\n").encode("utf-8"))
            sys.stdout.buffer.flush()
        except AttributeError:
            # Fallback for environments without buffer (e.g., StringIO in tests)
            print(text)


    @staticmethod
    def _wrap(text: str, width: int) -> list[str]:
        """Simple word-wrap at given width."""
        words = text.split()
        lines = []
        current = ""
        for word in words:
            if current and len(current) + 1 + len(word) > width:
                lines.append(current)
                current = word
            else:
                current = f"{current} {word}" if current else word
        if current:
            lines.append(current)
        return lines
