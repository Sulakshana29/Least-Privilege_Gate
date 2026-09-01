# ============================================================================
# VULNERABLE EXAMPLE — Cloud Policy Guard
# ============================================================================
# This Terraform configuration intentionally contains IAM security violations.
# It is used to demonstrate how Cloud Policy Guard detects and blocks
# insecure infrastructure in a CI/CD pipeline.
#
# DO NOT deploy this to a real AWS environment.
# ============================================================================

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# ─────────────────────────────────────────────────────────────────────────────
# VIOLATION: LP001 + LP003
# Wildcard action + wildcard resource = full administrator access
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_iam_policy" "overpermissive_app" {
  name        = "overpermissive-application-policy"
  description = "INSECURE: Grants full AWS access — for demo purposes only"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "FullAccess"
        Effect   = "Allow"
        Action   = "*"       # LP001: Wildcard action (CRITICAL)
        Resource = "*"       # LP003: Combined with Action:* = Admin access (CRITICAL)
      }
    ]
  })
}

# ─────────────────────────────────────────────────────────────────────────────
# VIOLATION: LP005 (HIGH) + LP004
# Service-level wildcards on sensitive services + dangerous IAM actions
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_iam_role" "application_role" {
  name = "vulnerable-application-role"

  # VIOLATION: LP006 — Principal: "*" means ANYONE can assume this role
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = "*"   # LP006: Anyone on the internet can assume this role (CRITICAL)
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "application_inline" {
  name = "vulnerable-inline-policy"
  role = aws_iam_role.application_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DangerousIAMActions"
        Effect = "Allow"
        Action = [
          "iam:PassRole",         # LP004: Privilege escalation vector (HIGH)
          "iam:CreateAccessKey",  # LP004: Can create backdoor credentials (HIGH)
          "iam:AttachRolePolicy", # LP004: Can attach AdministratorAccess (HIGH)
          "iam:PutRolePolicy",    # LP004: Can write arbitrary policies (HIGH)
          "iam:UpdateAssumeRolePolicy" # LP004: Can modify trust relationships (HIGH)
        ]
        Resource = "*"
      },
      {
        Sid    = "ExcessiveServiceAccess"
        Effect = "Allow"
        Action = [
          "s3:*",           # LP005: All S3 actions including DeleteBucket (MEDIUM)
          "ec2:*",          # LP005: All EC2 actions including TerminateInstances (MEDIUM)
          "iam:*",          # LP005: Full IAM control (HIGH)
          "secretsmanager:*" # LP005: Full Secrets access (HIGH)
        ]
        Resource = "*"
      }
    ]
  })
}

# ─────────────────────────────────────────────────────────────────────────────
# VIOLATION: LP003 — Attaching AdministratorAccess managed policy
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_iam_role_policy_attachment" "admin_attachment" {
  role       = aws_iam_role.application_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
  # LP003: Attaching the broadest possible AWS managed policy (CRITICAL)
}

# ─────────────────────────────────────────────────────────────────────────────
# VIOLATION: LP002 (HIGH) — Wildcard resource with sensitive actions
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_iam_policy" "kms_overpermissive" {
  name = "overpermissive-kms-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:DeleteAlias",   # Dangerous — can delete KMS key aliases
          "kms:DisableKey"     # Dangerous — can make data permanently inaccessible
        ]
        Resource = "*"  # LP002: HIGH severity — KMS actions with wildcard resource
      }
    ]
  })
}
