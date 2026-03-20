####################################
# Lambda packaging (zip archives)
####################################

data "archive_file" "enrich_alert" {
  type        = "zip"
  source_dir  = "${path.module}/../lambdas/enrich_alert"
  output_path = "${path.module}/../dist/enrich_alert.zip"
}

data "archive_file" "collect_artifacts" {
  type        = "zip"
  source_dir  = "${path.module}/../lambdas/collect_artifacts"
  output_path = "${path.module}/../dist/collect_artifacts.zip"
}

data "archive_file" "ai_analysis" {
  type        = "zip"
  source_dir  = "${path.module}/../lambdas/ai_analysis"
  output_path = "${path.module}/../dist/ai_analysis.zip"
}

data "archive_file" "store_artifacts" {
  type        = "zip"
  source_dir  = "${path.module}/../lambdas/store_artifacts"
  output_path = "${path.module}/../dist/store_artifacts.zip"
}

data "archive_file" "notify_siem" {
  type        = "zip"
  source_dir  = "${path.module}/../lambdas/notify_siem"
  output_path = "${path.module}/../dist/notify_siem.zip"
}

####################################
# CloudWatch Log Groups for Lambdas
####################################

resource "aws_cloudwatch_log_group" "enrich_alert" {
  name              = "/aws/lambda/${var.project_name}-enrich-alert"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "collect_artifacts" {
  name              = "/aws/lambda/${var.project_name}-collect-artifacts"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "ai_analysis" {
  name              = "/aws/lambda/${var.project_name}-ai-analysis"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "store_artifacts" {
  name              = "/aws/lambda/${var.project_name}-store-artifacts"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "notify_siem" {
  name              = "/aws/lambda/${var.project_name}-notify-siem"
  retention_in_days = var.log_retention_days
}

####################################
# Common Lambda environment variables
####################################

locals {
  lambda_common_env = {
    ARTIFACTS_BUCKET                     = aws_s3_bucket.artifacts.id
    BEDROCK_MODEL_ID                     = var.bedrock_model_id
    GOOGLE_SECOPS_API_ENDPOINT           = var.google_secops_api_endpoint
    GOOGLE_SECOPS_CUSTOMER_ID            = var.google_secops_customer_id
    GOOGLE_SECOPS_CREDENTIALS_SECRET_ARN = var.google_secops_credentials_secret_arn
    AWS_ACCOUNT_ID                       = data.aws_caller_identity.current.account_id
    ENABLE_VPC_FLOW_LOG_COLLECTION       = tostring(var.enable_vpc_flow_log_collection)
    ENABLE_CLOUDTRAIL_COLLECTION         = tostring(var.enable_cloudtrail_collection)
  }
}

####################################
# Lambda – enrich_alert
####################################

resource "aws_lambda_function" "enrich_alert" {
  function_name    = "${var.project_name}-enrich-alert"
  description      = "Enriches a GuardDuty finding with CloudTrail events, EC2 metadata, and IAM context"
  filename         = data.archive_file.enrich_alert.output_path
  source_code_hash = data.archive_file.enrich_alert.output_base64sha256
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  role             = aws_iam_role.lambda_exec.arn
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory_mb
  layers           = [aws_lambda_layer_version.shared.arn]

  environment {
    variables = local.lambda_common_env
  }

  depends_on = [aws_cloudwatch_log_group.enrich_alert]
}

####################################
# Lambda – collect_artifacts
####################################

resource "aws_lambda_function" "collect_artifacts" {
  function_name    = "${var.project_name}-collect-artifacts"
  description      = "Downloads GuardDuty findings, VPC flow logs, and CloudTrail log segments into S3"
  filename         = data.archive_file.collect_artifacts.output_path
  source_code_hash = data.archive_file.collect_artifacts.output_base64sha256
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  role             = aws_iam_role.lambda_exec.arn
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory_mb
  layers           = [aws_lambda_layer_version.shared.arn]

  environment {
    variables = local.lambda_common_env
  }

  depends_on = [aws_cloudwatch_log_group.collect_artifacts]
}

####################################
# Lambda – ai_analysis
####################################

resource "aws_lambda_function" "ai_analysis" {
  function_name    = "${var.project_name}-ai-analysis"
  description      = "Uses Amazon Bedrock to reason over collected evidence and produce a true/false/inconclusive verdict"
  filename         = data.archive_file.ai_analysis.output_path
  source_code_hash = data.archive_file.ai_analysis.output_base64sha256
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  role             = aws_iam_role.lambda_exec.arn
  timeout          = var.lambda_timeout
  memory_size      = 512
  layers           = [aws_lambda_layer_version.shared.arn]

  environment {
    variables = local.lambda_common_env
  }

  depends_on = [aws_cloudwatch_log_group.ai_analysis]
}

####################################
# Lambda – store_artifacts
####################################

resource "aws_lambda_function" "store_artifacts" {
  function_name    = "${var.project_name}-store-artifacts"
  description      = "Stores all collected artifacts and the AI recommendation into the S3 artifacts bucket under the ticket number prefix"
  filename         = data.archive_file.store_artifacts.output_path
  source_code_hash = data.archive_file.store_artifacts.output_base64sha256
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  role             = aws_iam_role.lambda_exec.arn
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory_mb
  layers           = [aws_lambda_layer_version.shared.arn]

  environment {
    variables = local.lambda_common_env
  }

  depends_on = [aws_cloudwatch_log_group.store_artifacts]
}

####################################
# Lambda – notify_siem
####################################

resource "aws_lambda_function" "notify_siem" {
  function_name    = "${var.project_name}-notify-siem"
  description      = "Sends the AI recommendation back to Google SecOps (Chronicle) as a case comment/finding update"
  filename         = data.archive_file.notify_siem.output_path
  source_code_hash = data.archive_file.notify_siem.output_base64sha256
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  role             = aws_iam_role.lambda_exec.arn
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory_mb
  layers           = [aws_lambda_layer_version.shared.arn]

  environment {
    variables = local.lambda_common_env
  }

  depends_on = [aws_cloudwatch_log_group.notify_siem]
}
