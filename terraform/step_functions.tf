####################################
# CloudWatch Log Group for Step Functions
####################################

resource "aws_cloudwatch_log_group" "step_functions" {
  name              = "/aws/states/${var.project_name}-incident-response"
  retention_in_days = var.log_retention_days
}

####################################
# Step Functions State Machine
####################################

resource "aws_sfn_state_machine" "incident_response" {
  name     = "${var.project_name}-incident-response"
  role_arn = aws_iam_role.step_functions.arn
  type     = "STANDARD"

  definition = jsonencode({
    Comment = "AI-assisted cloud incident response workflow. Triggered by Google SecOps via EventBridge."
    StartAt = "EnrichAlert"

    States = {
      EnrichAlert = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.enrich_alert.arn
          "Payload.$"  = "$"
        }
        ResultSelector = {
          "enrichment.$" = "$.Payload"
        }
        ResultPath = "$.enrichment_result"
        Retry = [
          {
            ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException", "Lambda.TooManyRequestsException"]
            IntervalSeconds = 2
            MaxAttempts     = 3
            BackoffRate     = 2
          }
        ]
        Catch = [
          {
            ErrorEquals = ["States.ALL"]
            Next        = "HandleEnrichmentFailure"
            ResultPath  = "$.error"
          }
        ]
        Next = "CollectArtifacts"
      }

      HandleEnrichmentFailure = {
        Type = "Pass"
        Parameters = {
          "ticket_number.$"  = "$.ticket_number"
          "finding_id.$"     = "$.finding_id"
          "alert_type.$"     = "$.alert_type"
          "severity.$"       = "$.severity"
          "secops_case_id.$" = "$.secops_case_id"
          enrichment_result = {
            enrichment = {
              finding      = {}
              cloudtrail   = []
              ec2_metadata = {}
              error        = "Enrichment step failed – proceeding with raw data only"
            }
          }
        }
        Next = "CollectArtifacts"
      }

      CollectArtifacts = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.collect_artifacts.arn
          Payload = {
            "ticket_number.$"     = "$.ticket_number"
            "finding_id.$"        = "$.finding_id"
            "alert_type.$"        = "$.alert_type"
            "severity.$"          = "$.severity"
            "resource_type.$"     = "$.resource_type"
            "resource_id.$"       = "$.resource_id"
            "account_id.$"        = "$.account_id"
            "region.$"            = "$.region"
            "secops_case_id.$"    = "$.secops_case_id"
            "enrichment_result.$" = "$.enrichment_result"
          }
        }
        ResultSelector = {
          "artifacts.$" = "$.Payload"
        }
        ResultPath = "$.artifacts_result"
        Retry = [
          {
            ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException", "Lambda.TooManyRequestsException"]
            IntervalSeconds = 2
            MaxAttempts     = 3
            BackoffRate     = 2
          }
        ]
        Catch = [
          {
            ErrorEquals = ["States.ALL"]
            Next        = "HandleArtifactFailure"
            ResultPath  = "$.error"
          }
        ]
        Next = "AIAnalysis"
      }

      HandleArtifactFailure = {
        Type = "Pass"
        Parameters = {
          "ticket_number.$"      = "$.ticket_number"
          "finding_id.$"         = "$.finding_id"
          "alert_type.$"         = "$.alert_type"
          "severity.$"           = "$.severity"
          "secops_case_id.$"     = "$.secops_case_id"
          "enrichment_result.$"  = "$.enrichment_result"
          artifacts_result = {
            artifacts = {
              s3_keys   = []
              vpc_flows = []
              error     = "Artifact collection failed – proceeding with enrichment data only"
            }
          }
        }
        Next = "AIAnalysis"
      }

      AIAnalysis = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.ai_analysis.arn
          Payload = {
            "ticket_number.$"     = "$.ticket_number"
            "finding_id.$"        = "$.finding_id"
            "alert_type.$"        = "$.alert_type"
            "severity.$"          = "$.severity"
            "account_id.$"        = "$.account_id"
            "region.$"            = "$.region"
            "resource_type.$"     = "$.resource_type"
            "resource_id.$"       = "$.resource_id"
            "description.$"       = "$.description"
            "secops_case_id.$"    = "$.secops_case_id"
            "enrichment_result.$" = "$.enrichment_result"
            "artifacts_result.$"  = "$.artifacts_result"
          }
        }
        ResultSelector = {
          "analysis.$" = "$.Payload"
        }
        ResultPath = "$.analysis_result"
        Retry = [
          {
            ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException", "Lambda.TooManyRequestsException"]
            IntervalSeconds = 5
            MaxAttempts     = 2
            BackoffRate     = 2
          }
        ]
        Catch = [
          {
            ErrorEquals = ["States.ALL"]
            Next        = "HandleAnalysisFailure"
            ResultPath  = "$.error"
          }
        ]
        Next = "StoreArtifacts"
      }

      HandleAnalysisFailure = {
        Type = "Pass"
        Parameters = {
          "ticket_number.$"      = "$.ticket_number"
          "finding_id.$"         = "$.finding_id"
          "alert_type.$"         = "$.alert_type"
          "severity.$"           = "$.severity"
          "secops_case_id.$"     = "$.secops_case_id"
          "enrichment_result.$"  = "$.enrichment_result"
          "artifacts_result.$"   = "$.artifacts_result"
          analysis_result = {
            analysis = {
              verdict           = "INCONCLUSIVE"
              confidence        = "LOW"
              reasoning         = "AI analysis failed. Manual investigation required."
              proposed_actions  = ["Review GuardDuty finding manually"]
              approval_required = true
              approval_status   = "PENDING_HUMAN_APPROVAL"
              actions_taken     = []
              error             = "AI analysis step encountered an error"
            }
          }
        }
        Next = "StoreArtifacts"
      }

      StoreArtifacts = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.store_artifacts.arn
          Payload = {
            "ticket_number.$"     = "$.ticket_number"
            "finding_id.$"        = "$.finding_id"
            "alert_type.$"        = "$.alert_type"
            "severity.$"          = "$.severity"
            "account_id.$"        = "$.account_id"
            "region.$"            = "$.region"
            "resource_type.$"     = "$.resource_type"
            "resource_id.$"       = "$.resource_id"
            "description.$"       = "$.description"
            "secops_case_id.$"    = "$.secops_case_id"
            "enrichment_result.$" = "$.enrichment_result"
            "artifacts_result.$"  = "$.artifacts_result"
            "analysis_result.$"   = "$.analysis_result"
          }
        }
        ResultSelector = {
          "store.$" = "$.Payload"
        }
        ResultPath = "$.store_result"
        Retry = [
          {
            ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException", "Lambda.TooManyRequestsException"]
            IntervalSeconds = 2
            MaxAttempts     = 3
            BackoffRate     = 2
          }
        ]
        Next = "NotifySIEM"
      }

      NotifySIEM = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke.waitForTaskToken"
        Parameters = {
          FunctionName = aws_lambda_function.notify_siem.arn
          Payload = {
            "ticket_number.$"     = "$.ticket_number"
            "finding_id.$"        = "$.finding_id"
            "secops_case_id.$"    = "$.secops_case_id"
            "analysis_result.$"   = "$.analysis_result"
            "store_result.$"      = "$.store_result"
            "task_token.$"        = "$$.Task.Token"
            notify_mode           = "investigation"
          }
        }
        # Workflow pauses here until the analyst calls approve_actions with this task token.
        # The 7-day window gives analysts time to review; after expiry it fails gracefully.
        TimeoutSeconds = 604800
        ResultPath     = "$.approval_result"
        Retry = [
          {
            ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException", "Lambda.TooManyRequestsException"]
            IntervalSeconds = 2
            MaxAttempts     = 2
            BackoffRate     = 2
          }
        ]
        Catch = [
          {
            ErrorEquals = ["States.Timeout", "States.HeartbeatTimeout"]
            Next        = "HandleApprovalTimeout"
            ResultPath  = "$.approval_error"
          },
          {
            ErrorEquals = ["AnalystRejected"]
            Next        = "HandleAnalystRejection"
            ResultPath  = "$.approval_error"
          },
          {
            ErrorEquals = ["States.ALL"]
            Next        = "WorkflowComplete"
            ResultPath  = "$.notify_error"
          }
        ]
        Next = "ExecuteApprovedActions"
      }

      HandleApprovalTimeout = {
        Type = "Pass"
        Parameters = {
          "ticket_number.$"  = "$.ticket_number"
          "secops_case_id.$" = "$.secops_case_id"
          timeout_reason     = "Analyst approval window expired after 7 days. No actions were executed."
        }
        Next = "WorkflowComplete"
      }

      HandleAnalystRejection = {
        Type = "Pass"
        Parameters = {
          "ticket_number.$"  = "$.ticket_number"
          "secops_case_id.$" = "$.secops_case_id"
          rejection_reason   = "Analyst declined to authorise proposed actions. No actions were executed."
        }
        Next = "WorkflowComplete"
      }

      ExecuteApprovedActions = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.execute_actions.arn
          Payload = {
            "ticket_number.$"   = "$.ticket_number"
            "secops_case_id.$"  = "$.secops_case_id"
            "approval_result.$" = "$.approval_result"
          }
        }
        ResultSelector = {
          "execution.$" = "$.Payload"
        }
        ResultPath = "$.execution_result"
        Retry = [
          {
            ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException", "Lambda.TooManyRequestsException"]
            IntervalSeconds = 5
            MaxAttempts     = 2
            BackoffRate     = 2
          }
        ]
        Catch = [
          {
            ErrorEquals = ["States.ALL"]
            Next        = "HandleExecutionFailure"
            ResultPath  = "$.execution_error"
          }
        ]
        Next = "NotifyExecution"
      }

      HandleExecutionFailure = {
        Type = "Pass"
        Parameters = {
          "ticket_number.$"  = "$.ticket_number"
          "secops_case_id.$" = "$.secops_case_id"
          execution_result = {
            execution = {
              total_actions = 0
              succeeded     = 0
              failed        = 0
              results       = []
              error         = "Execution step failed — manual remediation may be required"
            }
          }
        }
        Next = "NotifyExecution"
      }

      NotifyExecution = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.notify_siem.arn
          Payload = {
            "ticket_number.$"    = "$.ticket_number"
            "secops_case_id.$"   = "$.secops_case_id"
            "execution_result.$" = "$.execution_result"
            notify_mode          = "execution_results"
          }
        }
        ResultPath = null
        Retry = [
          {
            ErrorEquals     = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException", "Lambda.TooManyRequestsException"]
            IntervalSeconds = 2
            MaxAttempts     = 2
            BackoffRate     = 2
          }
        ]
        Catch = [
          {
            ErrorEquals = ["States.ALL"]
            Next        = "WorkflowComplete"
            ResultPath  = "$.execution_notify_error"
          }
        ]
        Next = "WorkflowComplete"
      }

      WorkflowComplete = {
        Type = "Succeed"
      }
    }
  })

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.step_functions.arn}:*"
    include_execution_data = true
    level                  = "ALL"
  }

  tracing_configuration {
    enabled = true
  }

  depends_on = [aws_cloudwatch_log_group.step_functions]
}
