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
              recommendations   = ["Review GuardDuty finding manually"]
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
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.notify_siem.arn
          Payload = {
            "ticket_number.$"     = "$.ticket_number"
            "finding_id.$"        = "$.finding_id"
            "secops_case_id.$"    = "$.secops_case_id"
            "analysis_result.$"   = "$.analysis_result"
            "store_result.$"      = "$.store_result"
          }
        }
        ResultSelector = {
          "notify.$" = "$.Payload"
        }
        ResultPath = "$.notify_result"
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
            ResultPath  = "$.notify_error"
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
