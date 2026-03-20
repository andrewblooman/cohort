####################################
# Custom EventBridge Bus
####################################

resource "aws_cloudwatch_event_bus" "incident_response" {
  name = "${var.project_name}-incident-response"
}

####################################
# EventBridge Rule – triggers Step Functions
# when the SIEM (Google SecOps) publishes
# an incident-response event.
####################################

resource "aws_cloudwatch_event_rule" "siem_trigger" {
  name           = "${var.project_name}-siem-trigger"
  description    = "Triggers the incident-response Step Functions workflow when the SIEM forwards a GuardDuty alert"
  event_bus_name = aws_cloudwatch_event_bus.incident_response.name
  state          = "ENABLED"

  event_pattern = jsonencode({
    source      = [var.eventbridge_source_filter]
    detail-type = ["IncidentResponse"]
    detail = {
      ticket_number = [{ exists = true }]
    }
  })
}

resource "aws_cloudwatch_event_target" "step_functions" {
  rule           = aws_cloudwatch_event_rule.siem_trigger.name
  event_bus_name = aws_cloudwatch_event_bus.incident_response.name
  target_id      = "IncidentResponseStateMachine"
  arn            = aws_sfn_state_machine.incident_response.arn
  role_arn       = aws_iam_role.eventbridge_sfn.arn

  # Pass the entire event detail as the state machine input
  input_transformer {
    input_paths = {
      ticket_number    = "$.detail.ticket_number"
      alert_type       = "$.detail.alert_type"
      severity         = "$.detail.severity"
      finding_id       = "$.detail.finding_id"
      account_id       = "$.detail.account_id"
      region           = "$.detail.region"
      resource_type    = "$.detail.resource_type"
      resource_id      = "$.detail.resource_id"
      description      = "$.detail.description"
      secops_case_id   = "$.detail.secops_case_id"
    }
    input_template = <<-EOT
    {
      "ticket_number": "<ticket_number>",
      "alert_type": "<alert_type>",
      "severity": "<severity>",
      "finding_id": "<finding_id>",
      "account_id": "<account_id>",
      "region": "<region>",
      "resource_type": "<resource_type>",
      "resource_id": "<resource_id>",
      "description": "<description>",
      "secops_case_id": "<secops_case_id>"
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
  rule           = aws_cloudwatch_event_rule.siem_trigger.name
  event_bus_name = aws_cloudwatch_event_bus.incident_response.name
  target_id      = "CloudWatchLogs"
  arn            = aws_cloudwatch_log_group.eventbridge.arn
}
