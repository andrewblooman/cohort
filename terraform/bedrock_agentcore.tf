####################################
# Amazon Bedrock AgentCore
#
# Provides a managed agent runtime and cross-session memory store
# used by the ai_analysis Lambda.  The runtime replaces the direct
# bedrock-runtime:InvokeModel call with a fully-orchestrated agent
# invocation (bedrock-agent-runtime:InvokeAgent) that handles
# session lifecycle, tool use, and memory lookups automatically.
####################################

####################################
# CloudWatch Log Group – AgentCore runtime logs
####################################

resource "aws_cloudwatch_log_group" "agentcore_runtime" {
  name              = "/aws/bedrockagentcore/${var.project_name}-incident-response"
  retention_in_days = var.log_retention_days
}

####################################
# Bedrock AgentCore Runtime
####################################

resource "aws_bedrockagentcore_agent_runtime" "incident_response" {
  agent_runtime_name = "${replace(var.project_name, "-", "_")}_incident_response"
  description        = "AI incident-response agent. Analyses GuardDuty findings using enrichment data and returns a TRUE_POSITIVE / FALSE_POSITIVE / INCONCLUSIVE verdict."

  agent_runtime_artifact {
    container_configuration {
      container_uri = "public.ecr.aws/bedrockagentcore/python-runtime:latest"
    }
  }

  network_configuration {
    network_mode = "PUBLIC"
  }

  # Pass the configured foundation model ID to the container so the agent
  # runtime code uses the same model as the direct InvokeModel fallback.
  environment_variables = {
    BEDROCK_MODEL_ID = var.bedrock_model_id
  }

  role_arn = aws_iam_role.agentcore_runtime.arn

  depends_on = [aws_cloudwatch_log_group.agentcore_runtime]
}

####################################
# Bedrock AgentCore Memory Store
#
# Provides cross-session, cross-incident memory so the agent can
# recall previously seen benign patterns, past verdicts, and
# investigator notes across separate Step Functions executions.
####################################

resource "aws_bedrockagentcore_memory" "incident_memory" {
  name                      = "${replace(var.project_name, "-", "_")}_incident_memory"
  description               = "Cross-session incident-response memory. Stores verdicts, IoCs, and false-positive patterns to improve future triage accuracy."
  event_expiry_duration     = var.agentcore_memory_retention_days # days (7–365)
  memory_execution_role_arn = aws_iam_role.agentcore_runtime.arn
  # encryption_key_arn omitted – uses AWS-managed key; replace with a CMK ARN for stricter compliance
}
