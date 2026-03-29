####################################
# Lambda packaging (zip archives)
####################################

data "archive_file" "api_authorizer" {
  type        = "zip"
  source_dir  = "${path.module}/../lambdas/api_authorizer"
  output_path = "${path.module}/../dist/api_authorizer.zip"
}

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

data "archive_file" "approve_actions" {
  type        = "zip"
  source_dir  = "${path.module}/../lambdas/approve_actions"
  output_path = "${path.module}/../dist/approve_actions.zip"
}

data "archive_file" "execute_actions" {
  type        = "zip"
  source_dir  = "${path.module}/../lambdas/execute_actions"
  output_path = "${path.module}/../dist/execute_actions.zip"
}

data "archive_file" "list_investigations" {
  type        = "zip"
  source_dir  = "${path.module}/../lambdas/list_investigations"
  output_path = "${path.module}/../dist/list_investigations.zip"
}

data "archive_file" "get_investigation" {
  type        = "zip"
  source_dir  = "${path.module}/../lambdas/get_investigation"
  output_path = "${path.module}/../dist/get_investigation.zip"
}

data "archive_file" "rerun_analysis" {
  type        = "zip"
  source_dir  = "${path.module}/../lambdas/rerun_analysis"
  output_path = "${path.module}/../dist/rerun_analysis.zip"
}

####################################
# CloudWatch Log Groups for Lambdas
####################################

resource "aws_cloudwatch_log_group" "api_authorizer" {
  name              = "/aws/lambda/${var.project_name}-api-authorizer"
  retention_in_days = var.log_retention_days
}

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

resource "aws_cloudwatch_log_group" "approve_actions" {
  name              = "/aws/lambda/${var.project_name}-approve-actions"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "execute_actions" {
  name              = "/aws/lambda/${var.project_name}-execute-actions"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "list_investigations" {
  name              = "/aws/lambda/${var.project_name}-list-investigations"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "get_investigation" {
  name              = "/aws/lambda/${var.project_name}-get-investigation"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "rerun_analysis" {
  name              = "/aws/lambda/${var.project_name}-rerun-analysis"
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
    AGENTCORE_AGENT_RUNTIME_ARN          = aws_bedrockagentcore_agent_runtime.incident_response.agent_runtime_arn
    AGENTCORE_MEMORY_STORE_ID            = aws_bedrockagentcore_memory.incident_memory.id
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

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
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

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
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

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
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

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
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

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  depends_on = [aws_cloudwatch_log_group.notify_siem]
}

####################################
# Lambda – approve_actions
####################################

resource "aws_lambda_function" "approve_actions" {
  function_name    = "${var.project_name}-approve-actions"
  description      = "Human-in-the-loop callback: validates analyst approval and resumes the Step Functions workflow via send_task_success"
  filename         = data.archive_file.approve_actions.output_path
  source_code_hash = data.archive_file.approve_actions.output_base64sha256
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  role             = aws_iam_role.lambda_exec.arn
  timeout          = 60
  memory_size      = var.lambda_memory_mb

  environment {
    variables = {
      AWS_DEFAULT_REGION = var.aws_region
    }
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  depends_on = [aws_cloudwatch_log_group.approve_actions]
}

####################################
# Lambda – execute_actions
####################################

resource "aws_lambda_function" "execute_actions" {
  function_name    = "${var.project_name}-execute-actions"
  description      = "Executes analyst-approved remediation actions (EC2 isolation, IAM key deactivation, etc.) — only invoked after explicit human approval"
  filename         = data.archive_file.execute_actions.output_path
  source_code_hash = data.archive_file.execute_actions.output_base64sha256
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  role             = aws_iam_role.execute_actions.arn
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory_mb

  environment {
    variables = {
      AWS_DEFAULT_REGION = var.aws_region
      ARTIFACTS_BUCKET   = aws_s3_bucket.artifacts.id
    }
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  depends_on = [aws_cloudwatch_log_group.execute_actions]
}

####################################
# Lambda – list_investigations (web UI)
####################################

resource "aws_lambda_function" "list_investigations" {
  function_name    = "${var.project_name}-list-investigations"
  description      = "Returns a list of recent incident-response executions for the Cohort web UI dashboard"
  filename         = data.archive_file.list_investigations.output_path
  source_code_hash = data.archive_file.list_investigations.output_base64sha256
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  role             = aws_iam_role.lambda_exec.arn
  timeout          = 30
  memory_size      = var.lambda_memory_mb

  environment {
    variables = {
      AWS_DEFAULT_REGION    = var.aws_region
      SFN_STATE_MACHINE_ARN = aws_sfn_state_machine.incident_response.arn
      ARTIFACTS_BUCKET      = aws_s3_bucket.artifacts.id
    }
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  depends_on = [aws_cloudwatch_log_group.list_investigations]
}

####################################
# Lambda – get_investigation (web UI)
####################################

resource "aws_lambda_function" "get_investigation" {
  function_name    = "${var.project_name}-get-investigation"
  description      = "Returns full details for a single investigation from S3 + Step Functions for the Cohort web UI"
  filename         = data.archive_file.get_investigation.output_path
  source_code_hash = data.archive_file.get_investigation.output_base64sha256
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  role             = aws_iam_role.lambda_exec.arn
  timeout          = 30
  memory_size      = var.lambda_memory_mb

  environment {
    variables = {
      AWS_DEFAULT_REGION    = var.aws_region
      ARTIFACTS_BUCKET      = aws_s3_bucket.artifacts.id
      SFN_STATE_MACHINE_ARN = aws_sfn_state_machine.incident_response.arn
    }
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  depends_on = [aws_cloudwatch_log_group.get_investigation]
}

####################################
# Lambda – rerun_analysis (web UI)
####################################

resource "aws_lambda_function" "rerun_analysis" {
  function_name    = "${var.project_name}-rerun-analysis"
  description      = "Aborts an active investigation and starts a fresh Step Functions execution for the same ticket"
  filename         = data.archive_file.rerun_analysis.output_path
  source_code_hash = data.archive_file.rerun_analysis.output_base64sha256
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  role             = aws_iam_role.lambda_exec.arn
  timeout          = 30
  memory_size      = var.lambda_memory_mb

  environment {
    variables = {
      AWS_DEFAULT_REGION    = var.aws_region
      SFN_STATE_MACHINE_ARN = aws_sfn_state_machine.incident_response.arn
    }
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  depends_on = [aws_cloudwatch_log_group.rerun_analysis]
}

####################################
# Lambda – api_authorizer
#
# REQUEST-type Lambda authorizer for API Gateway.
# Validates the X-Api-Key header against the value stored in Secrets Manager.
# Returns a simple boolean: true = allow, false = deny.
####################################

resource "aws_lambda_function" "api_authorizer" {
  function_name    = "${var.project_name}-api-authorizer"
  description      = "Validates the X-Api-Key header against the Cohort API key stored in Secrets Manager"
  filename         = data.archive_file.api_authorizer.output_path
  source_code_hash = data.archive_file.api_authorizer.output_base64sha256
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  role             = aws_iam_role.lambda_exec.arn
  timeout          = 10
  memory_size      = 128

  environment {
    variables = {
      AWS_DEFAULT_REGION   = var.aws_region
      API_KEY_SECRET_ARN   = aws_secretsmanager_secret.api_key.arn
    }
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  depends_on = [aws_cloudwatch_log_group.api_authorizer]
}
