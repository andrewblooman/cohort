####################################
# API Gateway – Analyst Approval Endpoint
#
# Provides an HTTP endpoint that the analyst (or Google SecOps SOAR) calls to
# approve or reject proposed incident-response actions.  The API forwards the
# request to the approve_actions Lambda, which calls sfn.send_task_success to
# resume the paused Step Functions workflow.
#
# All routes are protected by a Lambda request authorizer that validates the
# X-Api-Key header against a value stored in AWS Secrets Manager.
#
# Endpoint:  POST <approval_api_endpoint>/approve
#
# Request body (approve):
#   {
#     "task_token":      "<token from SIEM comment>",
#     "analyst_id":      "<analyst email>",
#     "approval_notes":  "<optional notes>",
#     "approved_actions": [ { "action_id": "...", "type": "...", "parameters": {...} } ]
#   }
#
# Request body (reject):
#   {
#     "action":           "reject",
#     "task_token":       "<token>",
#     "analyst_id":       "<analyst email>",
#     "rejection_reason": "<optional>"
#   }
####################################

####################################
# Secrets Manager – API key
####################################

resource "aws_secretsmanager_secret" "api_key" {
  name                    = "${var.project_name}-api-key"
  description             = "API key for the Cohort incident-response HTTP API (X-Api-Key header)"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "api_key" {
  secret_id     = aws_secretsmanager_secret.api_key.id
  secret_string = var.api_key
}

####################################
# Lambda authorizer
####################################

resource "aws_apigatewayv2_authorizer" "api_key" {
  api_id                            = aws_apigatewayv2_api.approval.id
  authorizer_type                   = "REQUEST"
  authorizer_uri                    = aws_lambda_function.api_authorizer.invoke_arn
  identity_sources                  = ["$request.header.X-Api-Key"]
  name                              = "${var.project_name}-api-key-authorizer"
  authorizer_payload_format_version = "2.0"
  enable_simple_responses           = true
  # Cache the auth result for 5 minutes to avoid hitting Secrets Manager on every request
  authorizer_result_ttl_in_seconds  = 300
}

resource "aws_lambda_permission" "api_authorizer_invoke" {
  statement_id  = "AllowAPIGatewayInvokeAuthorizer"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.api_authorizer.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.approval.execution_arn}/authorizers/${aws_apigatewayv2_authorizer.api_key.id}"
}

resource "aws_apigatewayv2_api" "approval" {
  name          = "${var.project_name}-approval"
  protocol_type = "HTTP"
  description   = "Analyst approval endpoint for the Cohort incident-response HITL workflow"

  cors_configuration {
    allow_methods = ["GET", "POST", "OPTIONS"]
    allow_headers = ["content-type", "authorization", "x-api-key"]
    allow_origins = ["*"]
    max_age       = 300
  }
}

resource "aws_apigatewayv2_integration" "approve" {
  api_id                 = aws_apigatewayv2_api.approval.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.approve_actions.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "approve" {
  api_id             = aws_apigatewayv2_api.approval.id
  route_key          = "POST /approve"
  target             = "integrations/${aws_apigatewayv2_integration.approve.id}"
  authorization_type = "CUSTOM"
  authorizer_id      = aws_apigatewayv2_authorizer.api_key.id
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.approval.id
  name        = "$default"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.approval_api.arn
    format          = jsonencode({
      requestId      = "$context.requestId"
      ip             = "$context.identity.sourceIp"
      httpMethod     = "$context.httpMethod"
      routeKey       = "$context.routeKey"
      status         = "$context.status"
      protocol       = "$context.protocol"
      responseLength = "$context.responseLength"
      integrationError = "$context.integrationErrorMessage"
    })
  }
}

resource "aws_cloudwatch_log_group" "approval_api" {
  name              = "/aws/apigateway/${var.project_name}-approval"
  retention_in_days = var.log_retention_days
}

resource "aws_lambda_permission" "allow_api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.approve_actions.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.approval.execution_arn}/*/*"
}

####################################
# API Gateway – Web UI read endpoints
####################################

resource "aws_apigatewayv2_integration" "list_investigations" {
  api_id                 = aws_apigatewayv2_api.approval.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.list_investigations.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "list_investigations" {
  api_id             = aws_apigatewayv2_api.approval.id
  route_key          = "GET /investigations"
  target             = "integrations/${aws_apigatewayv2_integration.list_investigations.id}"
  authorization_type = "CUSTOM"
  authorizer_id      = aws_apigatewayv2_authorizer.api_key.id
}

resource "aws_lambda_permission" "allow_api_gateway_list_investigations" {
  statement_id  = "AllowAPIGatewayInvokeListInvestigations"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.list_investigations.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.approval.execution_arn}/*/*"
}

resource "aws_apigatewayv2_integration" "get_investigation" {
  api_id                 = aws_apigatewayv2_api.approval.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.get_investigation.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "get_investigation" {
  api_id             = aws_apigatewayv2_api.approval.id
  route_key          = "GET /investigations/{ticket_number}"
  target             = "integrations/${aws_apigatewayv2_integration.get_investigation.id}"
  authorization_type = "CUSTOM"
  authorizer_id      = aws_apigatewayv2_authorizer.api_key.id
}

resource "aws_lambda_permission" "allow_api_gateway_get_investigation" {
  statement_id  = "AllowAPIGatewayInvokeGetInvestigation"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.get_investigation.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.approval.execution_arn}/*/*"
}

resource "aws_apigatewayv2_integration" "rerun_analysis" {
  api_id                 = aws_apigatewayv2_api.approval.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.rerun_analysis.invoke_arn
  integration_method     = "POST"
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "rerun_analysis" {
  api_id             = aws_apigatewayv2_api.approval.id
  route_key          = "POST /investigations/{ticket_number}/rerun"
  target             = "integrations/${aws_apigatewayv2_integration.rerun_analysis.id}"
  authorization_type = "CUSTOM"
  authorizer_id      = aws_apigatewayv2_authorizer.api_key.id
}

resource "aws_lambda_permission" "allow_api_gateway_rerun_analysis" {
  statement_id  = "AllowAPIGatewayInvokeRerunAnalysis"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.rerun_analysis.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.approval.execution_arn}/*/*"
}
