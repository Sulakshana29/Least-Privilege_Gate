# Cloud Policy Guard

**Cloud Policy Guard** is a CLI-first, Policy-as-Code security gate that analyzes Terraform plans for AWS IAM least-privilege violations.

By shifting security left, Cloud Policy Guard blocks overly permissive IAM configurations before they are deployed to your AWS accounts.

## Features

- **Pre-deployment Analysis:** Analyzes Terraform plans (`terraform show -json`) *before* applying.
- **Context-Aware Rules:** Evaluates combinations of Actions and Resources to accurately determine the risk severity.
- **Risk Scoring:** Deterministic risk scoring model that calculates an aggregate security risk score.
- **CI/CD Ready:** Returns proper exit codes (0 for PASS, 1 for FAIL) to block deployment pipelines.
- **Human & Machine Friendly:** Beautiful colored terminal output for developers, and structured JSON output for CI pipelines.
- **Zero Dependencies (on AWS):** Operates entirely offline on the Terraform plan JSON without needing AWS credentials.

## Installation

Requires Python 3.10 or newer.

```bash
# Clone the repository
git clone https://github.com/yourusername/cloud-policy-guard.git
cd cloud-policy-guard

# Install in development mode
pip install -e .
```

## Quick Start

1. Generate a Terraform plan in JSON format:
```bash
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
```

2. Scan the plan using Cloud Policy Guard:
```bash
cloud-policy-guard scan --terraform-plan plan.json
```

## Security Rules

Cloud Policy Guard currently enforces the following rules (use `cloud-policy-guard rules` to see all):

| ID | Title | Severity | Description |
|:---|:---|:---|:---|
| **LP001** | Wildcard Action | **CRITICAL** | Detects policies granting `Action: "*"` (all possible actions). |
| **LP002** | Wildcard Resource | **HIGH/MED** | Detects policies granting actions on `Resource: "*"` (context-aware). |
| **LP003** | Administrative Permissions | **CRITICAL** | Detects inline `Action: "*"` + `Resource: "*"` or Admin managed policies. |
| **LP004** | Sensitive IAM Action | **HIGH** | Detects specific dangerous actions (e.g. `iam:PassRole`, `iam:PutRolePolicy`). |
| **LP005** | Excessive Service Perms | **HIGH/MED** | Detects service-level wildcards (e.g. `s3:*`, `iam:*`, `secretsmanager:*`). |
| **LP006** | Broad Trust Policy | **CRITICAL** | Detects `Principal: "*"` or insecure cross-account trust policies. |

## Configuration

You can configure Cloud Policy Guard using a `.cpg.yaml` file in your repository root, or via CLI arguments:

```yaml
# .cpg.yaml
fail_on: critical       # Pipeline fails if finding >= critical (options: critical, high, medium, low)
max_risk_score: 50      # Pipeline fails if aggregate risk score exceeds 50
exclude_rules:
  - LP005               # Disable specific rules if needed
format: text            # Output format (options: text, json)
```

CLI arguments take precedence over the config file:
```bash
cloud-policy-guard scan --terraform-plan plan.json --fail-on high --max-risk-score 20 --format json
```

## Example Vulnerable vs. Secure

The repository contains examples of vulnerable and secure Terraform configurations.

### Test the Vulnerable Plan (Expected to FAIL)
```bash
cloud-policy-guard scan --terraform-plan examples/vulnerable/plan.json
```

### Test the Secure Plan (Expected to PASS)
```bash
cloud-policy-guard scan --terraform-plan examples/secure/plan.json
```

## Development

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest -v
```

## Risk Scoring Model

Cloud Policy Guard uses a deterministic risk model:
- **CRITICAL** → 10 points
- **HIGH** → 7 points
- **MEDIUM** → 4 points
- **LOW** → 1 point
- **INFO** → 0 points

You can enforce a hard ceiling on the maximum allowable risk using the `--max-risk-score` parameter.

---
*Built as a portfolio project showcasing AWS IAM Least Privilege, Policy-as-Code, Terraform Security Gates, and DevSecOps.*
