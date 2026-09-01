# ============================================================================
# SECURE EXAMPLE — Cloud Policy Guard
# ============================================================================
# This Terraform configuration demonstrates properly scoped IAM permissions
# following AWS least-privilege best practices.
#
# This is the "fixed" version compared to examples/vulnerable/main.tf.
# Cloud Policy Guard should PASS this configuration with no critical findings.
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

locals {
  app_name   = "my-app"
  account_id = "123456789012"
  bucket_name = "my-app-documents"
}

# ─────────────────────────────────────────────────────────────────────────────
# SECURE: Tightly scoped S3 read/write policy for a specific bucket
# Actions: only what the application needs
# Resource: scoped to a specific bucket ARN
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_iam_policy" "app_s3_policy" {
  name        = "${local.app_name}-s3-access"
  description = "Allows the application to read and write to its document bucket only"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3ObjectAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        # Scoped to specific bucket and prefix — not "*"
        Resource = "arn:aws:s3:::${local.bucket_name}/${local.app_name}/*"
      },
      {
        Sid    = "S3ListBucket"
        Effect = "Allow"
        Action = [
          "s3:ListBucket"
        ]
        # ListBucket requires the bucket ARN, not the object ARN
        Resource = "arn:aws:s3:::${local.bucket_name}"
        Condition = {
          StringLike = {
            "s3:prefix" = ["${local.app_name}/*"]
          }
        }
      }
    ]
  })
}

# ─────────────────────────────────────────────────────────────────────────────
# SECURE: KMS policy scoped to a specific key
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_iam_policy" "app_kms_policy" {
  name        = "${local.app_name}-kms-access"
  description = "Allows the application to use a specific KMS key for encryption"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "KMSEncryptDecrypt"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
          # Note: No kms:DeleteKey, kms:DisableKey, kms:DeleteAlias
        ]
        # Scoped to a specific key ARN — not "*"
        Resource = "arn:aws:kms:us-east-1:${local.account_id}:key/mrk-1234abcd12ab34cd56ef1234567890ab"
      }
    ]
  })
}

# ─────────────────────────────────────────────────────────────────────────────
# SECURE: Lambda execution role with least-privilege trust policy
# Trust: Only the Lambda service can assume this role (not "*")
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_iam_role" "lambda_execution_role" {
  name        = "${local.app_name}-lambda-execution"
  description = "Execution role for the application Lambda function"

  # Trust policy: only Lambda service can assume this role
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "LambdaAssumeRole"
        Effect    = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"  # Specific service, not "*"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Attach our scoped policies to the role
resource "aws_iam_role_policy_attachment" "lambda_s3" {
  role       = aws_iam_role.lambda_execution_role.name
  policy_arn = aws_iam_policy.app_s3_policy.arn
}

resource "aws_iam_role_policy_attachment" "lambda_kms" {
  role       = aws_iam_role.lambda_execution_role.name
  policy_arn = aws_iam_policy.app_kms_policy.arn
}

# Attach the AWS managed policy for basic Lambda logging (read-only CloudWatch Logs)
# AWSLambdaBasicExecutionRole only grants: logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents
resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.lambda_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  # This is a safe managed policy — only grants CloudWatch Logs write access
}

# ─────────────────────────────────────────────────────────────────────────────
# SECURE: CloudWatch logs write policy (no destructive actions)
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_iam_policy" "app_logging_policy" {
  name        = "${local.app_name}-logging"
  description = "Allows the application to write to its CloudWatch log group only"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchLogsWrite"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
          # Note: No logs:DeleteLogGroup, logs:DeleteLogStream
        ]
        # Scoped to the application's log group
        Resource = "arn:aws:logs:us-east-1:${local.account_id}:log-group:/aws/lambda/${local.app_name}:*"
      }
    ]
  })
}
