####################################
# Reusable Terraform module: enrichment_lambda
#
# Deploys a Lambda function pre-configured with the shared
# utilities layer and common CloudWatch / CloudTrail IAM
# permissions.  Use this module to add new enrichment steps
# to the incident-response workflow without repeating
# boilerplate Terraform.
#
# Example usage:
#
#   module "custom_enrichment" {
#     source = "./modules/enrichment_lambda"
#
#     project_name      = var.project_name
#     function_name     = "custom-enrichment"
#     description       = "Runs a custom enrichment query"
#     source_dir        = "${path.module}/../lambdas/custom_enrichment"
#     shared_layer_arn  = aws_lambda_layer_version.shared.arn
#     environment_variables = {
#       ARTIFACTS_BUCKET = aws_s3_bucket.artifacts.id
#     }
#   }
####################################

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

# ---------------------------------------------------------------------------
# Packaging
# ---------------------------------------------------------------------------

data "archive_file" "function" {
  type        = "zip"
  source_dir  = var.source_dir
  output_path = "${path.module}/../../../dist/${var.function_name}.zip"
}

# ---------------------------------------------------------------------------
# CloudWatch Log Group
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "function" {
  name              = "/aws/lambda/${var.project_name}-${var.function_name}"
  retention_in_days = var.log_retention_days
}

# ---------------------------------------------------------------------------
# IAM Role
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "function" {
  name               = "${var.project_name}-${var.function_name}"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

resource "aws_iam_role_policy_attachment" "basic_execution" {
  role       = aws_iam_role.function.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "enrichment_permissions" {
  name = "${var.project_name}-${var.function_name}-permissions"
  role = aws_iam_role.function.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        # CloudTrail – look up events
        {
          Sid    = "CloudTrailLookup"
          Effect = "Allow"
          Action = [
            "cloudtrail:LookupEvents",
            "cloudtrail:GetTrail",
            "cloudtrail:DescribeTrails",
            "cloudtrail:GetTrailStatus",
          ]
          Resource = "*"
        },
        # CloudWatch Logs – Insights queries
        {
          Sid    = "CloudWatchLogsQuery"
          Effect = "Allow"
          Action = [
            "logs:StartQuery",
            "logs:StopQuery",
            "logs:GetQueryResults",
            "logs:DescribeLogGroups",
            "logs:DescribeLogStreams",
            "logs:FilterLogEvents",
            "logs:GetLogEvents",
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
          ]
          Resource = "*"
        },
      ],
      var.additional_iam_statements,
    )
  })
}

# ---------------------------------------------------------------------------
# Lambda Function
# ---------------------------------------------------------------------------

resource "aws_lambda_function" "function" {
  function_name    = "${var.project_name}-${var.function_name}"
  description      = var.description
  filename         = data.archive_file.function.output_path
  source_code_hash = data.archive_file.function.output_base64sha256
  runtime          = "python3.12"
  handler          = var.handler
  role             = aws_iam_role.function.arn
  timeout          = var.timeout
  memory_size      = var.memory_size

  layers = var.shared_layer_arn != "" ? [var.shared_layer_arn] : []

  environment {
    variables = var.environment_variables
  }

  depends_on = [aws_cloudwatch_log_group.function]
}
