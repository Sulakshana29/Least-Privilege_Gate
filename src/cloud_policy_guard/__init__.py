"""
Cloud Policy Guard
==================
AWS IAM Least Privilege security gate for Terraform plans.

Analyzes Terraform plan JSON for IAM policy violations,
calculates a risk score, and enforces a configurable
pass/fail security gate for CI/CD pipelines.
"""

__version__ = "0.1.0"
__author__ = "Cloud Policy Guard"
__license__ = "MIT"
