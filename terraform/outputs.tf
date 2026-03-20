output "artifacts_bucket_name" {
  description = "Name of the S3 bucket used to store incident-response artifacts"
  value       = aws_s3_bucket.artifacts.id
}

output "artifacts_bucket_arn" {
  description = "ARN of the S3 bucket used to store incident-response artifacts"
  value       = aws_s3_bucket.artifacts.arn
}

output "eventbridge_bus_name" {
  description = "Name of the custom EventBridge bus that receives SIEM events"
  value       = aws_cloudwatch_event_bus.incident_response.name
}

output "eventbridge_bus_arn" {
  description = "ARN of the custom EventBridge bus"
  value       = aws_cloudwatch_event_bus.incident_response.arn
}

output "step_functions_state_machine_arn" {
  description = "ARN of the Step Functions state machine that orchestrates incident response"
  value       = aws_sfn_state_machine.incident_response.arn
}

output "step_functions_state_machine_name" {
  description = "Name of the Step Functions state machine"
  value       = aws_sfn_state_machine.incident_response.name
}

output "enrich_alert_lambda_arn" {
  description = "ARN of the enrich-alert Lambda function"
  value       = aws_lambda_function.enrich_alert.arn
}

output "collect_artifacts_lambda_arn" {
  description = "ARN of the collect-artifacts Lambda function"
  value       = aws_lambda_function.collect_artifacts.arn
}

output "ai_analysis_lambda_arn" {
  description = "ARN of the AI-analysis Lambda function"
  value       = aws_lambda_function.ai_analysis.arn
}

output "store_artifacts_lambda_arn" {
  description = "ARN of the store-artifacts Lambda function"
  value       = aws_lambda_function.store_artifacts.arn
}

output "notify_siem_lambda_arn" {
  description = "ARN of the notify-SIEM Lambda function"
  value       = aws_lambda_function.notify_siem.arn
}

output "account_id" {
  description = "AWS account ID where resources are deployed"
  value       = data.aws_caller_identity.current.account_id
}

output "shared_layer_arn" {
  description = "ARN of the shared utilities Lambda Layer"
  value       = aws_lambda_layer_version.shared.arn
}

output "shared_layer_version" {
  description = "Version number of the shared utilities Lambda Layer"
  value       = aws_lambda_layer_version.shared.version
}

####################################
# Bedrock AgentCore outputs
####################################

output "agentcore_agent_runtime_id" {
  description = "ID of the Bedrock AgentCore runtime"
  value       = aws_bedrockagentcore_agent_runtime.incident_response.id
}

output "agentcore_agent_runtime_arn" {
  description = "ARN of the Bedrock AgentCore runtime"
  value       = aws_bedrockagentcore_agent_runtime.incident_response.arn
}

output "agentcore_memory_store_id" {
  description = "ID of the Bedrock AgentCore memory store"
  value       = aws_bedrockagentcore_memory_store.incident_memory.id
}
