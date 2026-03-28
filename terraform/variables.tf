variable "aws_region" {
  description = "AWS region to deploy resources into"
  type        = string
  default     = "eu-west-1"
}

variable "environment" {
  description = "Deployment environment (e.g. dev, staging, prod)"
  type        = string
  default     = "prod"
}

variable "project_name" {
  description = "Short name used as a prefix for all resource names"
  type        = string
  default     = "ir"
}

variable "artifacts_bucket_name" {
  description = "Name of the S3 bucket used to store incident-response artifacts. Must be globally unique."
  type        = string
  default     = ""
}

variable "artifacts_bucket_retention_days" {
  description = "Number of days to retain objects in the artifacts bucket before expiration"
  type        = number
  default     = 365
}

variable "lambda_timeout" {
  description = "Default timeout in seconds for Lambda functions"
  type        = number
  default     = 300
}

variable "lambda_memory_mb" {
  description = "Default memory in MB allocated to each Lambda function"
  type        = number
  default     = 256
}

variable "bedrock_model_id" {
  description = "Amazon Bedrock model ID (or cross-region inference profile) used for AI incident analysis. Newer Claude models require the 'us.' cross-region prefix."
  type        = string
  default     = "us.anthropic.claude-sonnet-4-5-20250514-v1:0"
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention period in days"
  type        = number
  default     = 30
}

variable "slack_webhook_secret_arn" {
  description = "ARN of the Secrets Manager secret containing the Slack Incoming Webhook URL. Leave empty to disable Slack notifications."
  type        = string
  default     = ""
}

variable "enable_vpc_flow_log_collection" {
  description = "When true, the collect-artifacts Lambda will also query VPC Flow Logs"
  type        = bool
  default     = true
}

variable "enable_cloudtrail_collection" {
  description = "When true, the collect-artifacts Lambda will query CloudTrail via CloudWatch Logs Insights"
  type        = bool
  default     = true
}

####################################
# Bedrock AgentCore variables
####################################

variable "agentcore_memory_retention_days" {
  description = "Number of days to retain events in the AgentCore memory store before expiry"
  type        = number
  default     = 90
}

variable "agentcore_idle_session_ttl_seconds" {
  description = "Number of seconds an AgentCore session can be idle before it is automatically closed"
  type        = number
  default     = 3600
}

variable "api_key" {
  description = "API key value that callers must supply in the X-Api-Key header. Stored in Secrets Manager."
  type        = string
  sensitive   = true
  default     = ""
}

variable "agentcore_container_tag" {
  description = "Tag of the public.ecr.aws/bedrockagentcore/python-runtime image used by the AgentCore runtime. Pin to a specific digest or dated tag in production rather than 'latest'."
  type        = string
  default     = "latest"
}
