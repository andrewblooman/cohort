####################################
# EventBridge Rule – triggers Step Functions
# when GuardDuty publishes a finding to the
# default event bus (aws.guardduty source).
####################################

resource "aws_cloudwatch_event_rule" "guardduty_trigger" {
  name        = "${var.project_name}-guardduty-trigger"
  description = "Triggers the incident-response Step Functions workflow for every GuardDuty finding"
  state       = "ENABLED"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
  })
}

resource "aws_cloudwatch_event_target" "step_functions" {
  rule      = aws_cloudwatch_event_rule.guardduty_trigger.name
  target_id = "IncidentResponseStateMachine"
  arn       = aws_sfn_state_machine.incident_response.arn
  role_arn  = aws_iam_role.eventbridge_sfn.arn

  # Pass the GuardDuty finding detail and envelope fields to the
  # GenerateIncidentId Lambda (first Step Functions state).
  input_transformer {
    input_paths = {
      finding_detail = "$.detail"
      account_id     = "$.account"
      event_region   = "$.region"
    }
    input_template = <<-EOT
    {
      "finding_detail": <finding_detail>,
      "account_id": "<account_id>",
      "event_region": "<event_region>"
    }
    EOT
  }
}

####################################
# CloudWatch Log Group for EventBridge
####################################

resource "aws_cloudwatch_log_group" "eventbridge" {
  name              = "/aws/events/${var.project_name}-incident-response"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_event_target" "log_group" {
  rule      = aws_cloudwatch_event_rule.guardduty_trigger.name
  target_id = "CloudWatchLogs"
  arn       = aws_cloudwatch_log_group.eventbridge.arn
}
