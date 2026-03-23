####################################
# SQS – Lambda Dead Letter Queues
#
# A single shared DLQ captures failed async Lambda invocations across
# the entire pipeline.  Alarm on ApproximateNumberOfMessagesVisible to
# get alerted when any Lambda drops an event.
####################################

resource "aws_sqs_queue" "lambda_dlq" {
  name                       = "${var.project_name}-lambda-dlq"
  message_retention_seconds  = 1209600 # 14 days
  visibility_timeout_seconds = 300

  tags = {
    Name = "${var.project_name}-lambda-dlq"
  }
}

# Deny non-SSL access to the DLQ
resource "aws_sqs_queue_policy" "lambda_dlq" {
  queue_url = aws_sqs_queue.lambda_dlq.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = { AWS = "*" }
        Action    = "sqs:*"
        Resource  = aws_sqs_queue.lambda_dlq.arn
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
    ]
  })
}
