variable "aws_region" {
  description = "AWS region to deploy resources into"
  type        = string
  default     = "us-east-1"
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
  description = "Amazon Bedrock model ID used for AI incident analysis"
  type        = string
  default     = "anthropic.claude-3-5-sonnet-20240620-v1:0"
}

variable "google_secops_api_endpoint" {
  description = "Google SecOps (Chronicle) API base endpoint for sending back recommendations"
  type        = string
  default     = ""
}

variable "google_secops_customer_id" {
  description = "Google SecOps customer ID (used when sending findings back to the SIEM)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "google_secops_credentials_secret_arn" {
  description = "ARN of the AWS Secrets Manager secret containing Google SecOps service-account credentials JSON"
  type        = string
  default     = ""
}

variable "eventbridge_source_filter" {
  description = "EventBridge event source pattern used to match events forwarded from the SIEM"
  type        = string
  default     = "com.google.secops"
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention period in days"
  type        = number
  default     = 30
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
