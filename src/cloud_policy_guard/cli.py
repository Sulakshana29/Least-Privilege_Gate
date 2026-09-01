"""
Cloud Policy Guard CLI
======================
Entry point for the `cloud-policy-guard` and `cpg` commands.

Commands:
    scan    Analyze a Terraform plan for IAM security violations.
    rules   List all available security rules.
    version Print the version.

Exit codes:
    0 → PASS (no violations above threshold)
    1 → FAIL (violations detected above threshold)
    2 → ERROR (invalid input, config error, file not found, etc.)
"""

from __future__ import annotations

import logging
import sys

import click

from cloud_policy_guard import __version__
from cloud_policy_guard.analyzer.engine import AnalysisEngine
from cloud_policy_guard.analyzer.registry import RuleRegistry
from cloud_policy_guard.config import load_config
from cloud_policy_guard.gate.security_gate import SecurityGate
from cloud_policy_guard.parser.iam_extractor import IAMExtractor
from cloud_policy_guard.parser.plan_parser import PlanParseError, PlanParser
from cloud_policy_guard.reporting.console import ConsoleReporter
from cloud_policy_guard.reporting.json_report import JsonReporter
from cloud_policy_guard.risk.scorer import RiskScorer


# ── Logging setup ─────────────────────────────────────────────────────────────

def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(levelname)s [%(name)s] %(message)s",
        stream=sys.stderr,  # Logging to stderr so JSON stdout stays clean
    )


# ── CLI group ─────────────────────────────────────────────────────────────────

@click.group()
@click.option("--verbose", "-v", is_flag=True, default=False, help="Enable debug logging.")
@click.pass_context
def main(ctx: click.Context, verbose: bool) -> None:
    """
    Cloud Policy Guard — AWS IAM Least Privilege Security Gate.

    Analyzes Terraform plans for IAM policy violations and blocks
    insecure infrastructure from progressing through CI/CD.

    \b
    Quick start:
        terraform plan -out=tfplan
        terraform show -json tfplan > plan.json
        cloud-policy-guard scan --terraform-plan plan.json
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    _configure_logging(verbose)


# ── scan command ──────────────────────────────────────────────────────────────

@main.command()
@click.option(
    "--terraform-plan",
    "-p",
    required=True,
    type=click.Path(exists=False),  # We do our own existence check for better errors
    help="Path to Terraform plan JSON file (from: terraform show -json tfplan > plan.json).",
)
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default=None,
    help="Output format. text=human-readable (default), json=machine-readable.",
)
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low", "info"], case_sensitive=False),
    default=None,
    help="Minimum severity that causes exit code 1. Default: critical.",
)
@click.option(
    "--max-risk-score",
    type=int,
    default=None,
    help="Maximum allowed risk score before FAIL (optional, in addition to --fail-on).",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(),
    default=None,
    help="Path to .cpg.yaml config file (default: .cpg.yaml in current directory).",
)
@click.option(
    "--exclude-rule",
    "exclude_rules",
    multiple=True,
    help="Rule ID to exclude (repeatable, e.g. --exclude-rule LP005).",
)
@click.pass_context
def scan(
    ctx: click.Context,
    terraform_plan: str,
    output_format: str | None,
    fail_on: str | None,
    max_risk_score: int | None,
    config_path: str | None,
    exclude_rules: tuple[str, ...],
) -> None:
    """
    Scan a Terraform plan for AWS IAM least-privilege violations.

    \b
    Workflow:
        1. Parse the Terraform plan JSON.
        2. Extract IAM resources.
        3. Normalize IAM policies.
        4. Run security rules (LP001–LP006).
        5. Calculate risk score.
        6. Evaluate security gate.
        7. Output findings.

    \b
    Exit codes:
        0 → PASS (pipeline may continue)
        1 → FAIL (pipeline should stop)
        2 → ERROR (invalid input or config)
    """
    try:
        config = load_config(
            config_path=config_path,
            cli_fail_on=fail_on,
            cli_max_risk_score=max_risk_score,
            cli_format=output_format,
            cli_exclude_rules=list(exclude_rules) if exclude_rules else None,
        )
    except (FileNotFoundError, ValueError) as e:
        click.echo(f"Configuration error: {e}", err=True)
        sys.exit(2)

    # ── Parse plan ────────────────────────────────────────────────────────────
    parser = PlanParser()
    try:
        plan = parser.parse_file(terraform_plan)
    except PlanParseError as e:
        click.echo(f"Error reading Terraform plan: {e}", err=True)
        sys.exit(2)

    iam_resource_changes = plan.iam_resources

    # ── Extract IAM policies ──────────────────────────────────────────────────
    extractor = IAMExtractor()
    iam_policies, trust_policies = extractor.extract(iam_resource_changes)

    # ── Run rule engine ───────────────────────────────────────────────────────
    registry = RuleRegistry(exclude_rules=config.exclude_rules)
    engine = AnalysisEngine(registry)
    findings = engine.analyze(iam_policies, trust_policies)

    # ── Score risk ────────────────────────────────────────────────────────────
    scorer = RiskScorer()
    risk_score = scorer.calculate(findings)

    # ── Evaluate gate ─────────────────────────────────────────────────────────
    gate = SecurityGate(
        fail_on=config.fail_on,
        max_risk_score=config.max_risk_score,
    )
    result = gate.evaluate(
        findings=findings,
        risk_score=risk_score,
        resources_scanned=plan.total_resources,
        iam_resources_found=len(iam_resource_changes),
        policies_analyzed=len(iam_policies) + len(trust_policies),
        terraform_plan_path=terraform_plan,
    )

    # ── Report ────────────────────────────────────────────────────────────────
    fmt = config.output_format.lower()
    if fmt == "json":
        JsonReporter().render(result)
    else:
        ConsoleReporter().render(result)

    # ── Exit code ─────────────────────────────────────────────────────────────
    sys.exit(0 if result.passed else 1)


# ── rules command ─────────────────────────────────────────────────────────────

@main.command()
@click.option(
    "--exclude-rule",
    "exclude_rules",
    multiple=True,
    help="Show excluded status for these rule IDs.",
)
def rules(exclude_rules: tuple[str, ...]) -> None:
    """List all available security rules with their severity and description."""
    registry = RuleRegistry(exclude_rules=list(exclude_rules))
    all_rules = registry.all_rule_metadata()

    click.echo()
    click.echo("  Cloud Policy Guard — Available Rules")
    click.echo("  " + "─" * 60)
    click.echo()

    for rule in all_rules:
        excluded_label = "  [EXCLUDED]" if rule["excluded"] == "True" else ""
        click.echo(
            f"  {rule['rule_id']:8}  {rule['severity'].upper():10}  "
            f"{rule['title']}{excluded_label}"
        )
        # Word-wrap description at 65 chars
        desc = rule["description"]
        words = desc.split()
        line = ""
        for word in words:
            if line and len(line) + len(word) + 1 > 65:
                click.echo(f"            {line}")
                line = word
            else:
                line = f"{line} {word}" if line else word
        if line:
            click.echo(f"            {line}")
        click.echo()


# ── version command ───────────────────────────────────────────────────────────

@main.command()
def version() -> None:
    """Print the Cloud Policy Guard version."""
    click.echo(f"cloud-policy-guard {__version__}")


if __name__ == "__main__":
    main()
