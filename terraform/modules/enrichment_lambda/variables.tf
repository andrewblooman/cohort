variable "project_name" {
  description = "Short name used as a prefix for resource names"
  type        = string
}

variable "function_name" {
  description = "Unique suffix for the Lambda function (e.g. 'custom-enrichment')"
  type        = string
}

variable "description" {
  description = "Human-readable description of the Lambda function"
  type        = string
  default     = "Enrichment Lambda deployed via the enrichment_lambda module"
}

variable "source_dir" {
  description = "Path to the directory containing the Lambda handler source code"
  type        = string
}

variable "handler" {
  description = "Lambda handler entry point"
  type        = string
  default     = "handler.lambda_handler"
}

variable "timeout" {
  description = "Lambda function timeout in seconds"
  type        = number
  default     = 300
}

variable "memory_size" {
  description = "Lambda function memory in MB"
  type        = number
  default     = 256
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention period in days"
  type        = number
  default     = 30
}

variable "shared_layer_arn" {
  description = "ARN of the shared utilities Lambda Layer. When provided the layer is attached to the function."
  type        = string
  default     = ""
}

variable "environment_variables" {
  description = "Map of environment variables to set on the Lambda function"
  type        = map(string)
  default     = {}
}

variable "additional_iam_statements" {
  description = "Extra IAM policy statements to append to the enrichment role (e.g. S3, GuardDuty, Bedrock permissions)"
  type = list(object({
    Sid      = string
    Effect   = string
    Action   = list(string)
    Resource = any
  }))
  default = []
}
