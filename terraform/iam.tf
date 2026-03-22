####################################
# IAM Role – Lambda execution
####################################

data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda_exec" {
  name               = "${var.project_name}-lambda-exec"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "lambda_permissions" {
  name = "${var.project_name}-lambda-permissions"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # S3 – read and write artifacts
      {
        Sid    = "S3ArtifactAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket",
        ]
        Resource = [
          aws_s3_bucket.artifacts.arn,
          "${aws_s3_bucket.artifacts.arn}/*",
        ]
      },
      # GuardDuty – read findings
      {
        Sid    = "GuardDutyReadFindings"
        Effect = "Allow"
        Action = [
          "guardduty:GetFindings",
          "guardduty:ListFindings",
          "guardduty:GetDetector",
          "guardduty:ListDetectors",
        ]
        Resource = "*"
      },
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
      # CloudWatch Logs – query VPC flow logs and CloudTrail log groups
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
      # EC2 – describe resources for enrichment
      {
        Sid    = "EC2Describe"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeVpcs",
          "ec2:DescribeSubnets",
          "ec2:DescribeFlowLogs",
          "ec2:DescribeRegions",
          "ec2:DescribeTags",
        ]
        Resource = "*"
      },
      # IAM – describe entities for enrichment
      {
        Sid    = "IAMReadOnly"
        Effect = "Allow"
        Action = [
          "iam:GetUser",
          "iam:GetRole",
          "iam:ListAttachedUserPolicies",
          "iam:ListAttachedRolePolicies",
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
        ]
        Resource = "*"
      },
      # Amazon Bedrock – invoke foundation model directly (fallback) and via AgentCore
      {
        Sid    = "BedrockInvokeModel"
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream",
        ]
        Resource = "arn:aws:bedrock:*::foundation-model/*"
      },
      # Amazon Bedrock AgentCore – invoke agent and manage sessions
      {
        Sid    = "AgentCoreInvokeAgent"
        Effect = "Allow"
        Action = [
          "bedrock-agent-runtime:InvokeAgent",
          "bedrock-agent-runtime:InvokeInlineAgent",
          "bedrock-agent-runtime:CreateSession",
          "bedrock-agent-runtime:GetSession",
          "bedrock-agent-runtime:DeleteSession",
          "bedrock-agent-runtime:ListSessions",
        ]
        Resource = "*"
      },
      # Amazon Bedrock AgentCore – read and write incident memory
      {
        Sid    = "AgentCoreMemory"
        Effect = "Allow"
        Action = [
          "bedrockagentcore:GetMemory",
          "bedrockagentcore:PutMemory",
          "bedrockagentcore:DeleteMemory",
          "bedrockagentcore:ListMemories",
        ]
        Resource = "*"
      },
      # Secrets Manager – retrieve Google SecOps credentials
      {
        Sid    = "SecretsManagerRead"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
        ]
        Resource = var.google_secops_credentials_secret_arn != "" ? var.google_secops_credentials_secret_arn : "arn:aws:secretsmanager:*:*:secret:${var.project_name}/*"
      },
      # Step Functions – used by notify_siem to report state
      {
        Sid    = "StepFunctionsSendTaskResult"
        Effect = "Allow"
        Action = [
          "states:SendTaskSuccess",
          "states:SendTaskFailure",
          "states:SendTaskHeartbeat",
        ]
        Resource = "*"
      },
      # Step Functions – used by the web UI Lambdas to list/describe/start/stop executions
      {
        Sid    = "StepFunctionsWebUI"
        Effect = "Allow"
        Action = [
          "states:ListExecutions",
          "states:DescribeExecution",
          "states:StopExecution",
          "states:StartExecution",
        ]
        Resource = "*"
      },
    ]
  })
}

####################################
# IAM Role – execute_actions Lambda
#
# Separate dedicated role with only the mutating permissions required for
# remediation.  Kept intentionally narrower than the shared lambda_exec role
# to enforce least-privilege for the only Lambda that makes write API calls.
####################################

resource "aws_iam_role" "execute_actions" {
  name               = "${var.project_name}-execute-actions"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

resource "aws_iam_role_policy_attachment" "execute_actions_basic_execution" {
  role       = aws_iam_role.execute_actions.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "execute_actions_permissions" {
  name = "${var.project_name}-execute-actions-permissions"
  role = aws_iam_role.execute_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # EC2 – remediation actions (isolation, stop, snapshot)
      {
        Sid    = "EC2Remediation"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:ModifyInstanceAttribute",
          "ec2:StopInstances",
          "ec2:CreateSnapshot",
          "ec2:CreateSecurityGroup",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:CreateTags",
        ]
        Resource = "*"
      },
      # IAM – remediation actions (key deactivation, session revocation)
      {
        Sid    = "IAMRemediation"
        Effect = "Allow"
        Action = [
          "iam:UpdateAccessKey",
          "iam:PutRolePolicy",
        ]
        Resource = "*"
      },
      # GuardDuty – archive resolved findings
      {
        Sid    = "GuardDutyArchive"
        Effect = "Allow"
        Action = [
          "guardduty:ArchiveFindings",
        ]
        Resource = "*"
      },
      # S3 – block public access on buckets
      {
        Sid    = "S3BlockPublicAccess"
        Effect = "Allow"
        Action = [
          "s3:PutBucketPublicAccessBlock",
        ]
        Resource = "*"
      },
    ]
  })
}

####################################
# IAM Role – Step Functions execution
####################################

data "aws_iam_policy_document" "sfn_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["states.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "step_functions" {
  name               = "${var.project_name}-step-functions"
  assume_role_policy = data.aws_iam_policy_document.sfn_assume_role.json
}

resource "aws_iam_role_policy" "sfn_permissions" {
  name = "${var.project_name}-sfn-permissions"
  role = aws_iam_role.step_functions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "InvokeLambda"
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction",
        ]
        Resource = [
          aws_lambda_function.enrich_alert.arn,
          aws_lambda_function.collect_artifacts.arn,
          aws_lambda_function.ai_analysis.arn,
          aws_lambda_function.store_artifacts.arn,
          aws_lambda_function.notify_siem.arn,
          aws_lambda_function.execute_actions.arn,
        ]
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogDelivery",
          "logs:GetLogDelivery",
          "logs:UpdateLogDelivery",
          "logs:DeleteLogDelivery",
          "logs:ListLogDeliveries",
          "logs:PutResourcePolicy",
          "logs:DescribeResourcePolicies",
          "logs:DescribeLogGroups",
        ]
        Resource = "*"
      },
      {
        Sid    = "XRayAccess"
        Effect = "Allow"
        Action = [
          "xray:PutTraceSegments",
          "xray:PutTelemetryRecords",
          "xray:GetSamplingRules",
          "xray:GetSamplingTargets",
        ]
        Resource = "*"
      },
    ]
  })
}

####################################
# IAM Role – EventBridge → Step Functions
####################################

data "aws_iam_policy_document" "eventbridge_sfn_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "eventbridge_sfn" {
  name               = "${var.project_name}-eventbridge-sfn"
  assume_role_policy = data.aws_iam_policy_document.eventbridge_sfn_assume_role.json
}

resource "aws_iam_role_policy" "eventbridge_sfn_permissions" {
  name = "${var.project_name}-eventbridge-sfn-permissions"
  role = aws_iam_role.eventbridge_sfn.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "StartStateMachineExecution"
        Effect = "Allow"
        Action = ["states:StartExecution"]
        Resource = [
          aws_sfn_state_machine.incident_response.arn,
        ]
      },
    ]
  })
}

####################################
# IAM Role – Bedrock AgentCore Runtime
#
# Assumed by the AgentCore managed runtime when executing the
# incident-response agent.  Grants access to the Bedrock
# foundation model, CloudWatch logging, and the memory store.
####################################

data "aws_iam_policy_document" "agentcore_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["bedrockagentcore.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role" "agentcore_runtime" {
  name               = "${var.project_name}-agentcore-runtime"
  assume_role_policy = data.aws_iam_policy_document.agentcore_assume_role.json
}

resource "aws_iam_role_policy" "agentcore_runtime_permissions" {
  name = "${var.project_name}-agentcore-runtime-permissions"
  role = aws_iam_role.agentcore_runtime.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Bedrock – invoke the configured foundation model
      {
        Sid    = "BedrockInvokeModel"
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream",
        ]
        Resource = "arn:aws:bedrock:*::foundation-model/*"
      },
      # AgentCore Memory – read and write cross-session incident memory
      {
        Sid    = "AgentCoreMemoryAccess"
        Effect = "Allow"
        Action = [
          "bedrockagentcore:GetMemory",
          "bedrockagentcore:PutMemory",
          "bedrockagentcore:DeleteMemory",
          "bedrockagentcore:ListMemories",
        ]
        Resource = "*"
      },
      # CloudWatch Logs – write runtime execution logs
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams",
        ]
        Resource = "arn:aws:logs:*:${data.aws_caller_identity.current.account_id}:log-group:/aws/bedrockagentcore/*"
      },
    ]
  })
}
