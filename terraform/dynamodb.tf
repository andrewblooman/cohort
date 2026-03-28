resource "aws_dynamodb_table" "incident_counter" {
  name         = "${var.project_name}-incident-counter"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "counter_id"

  attribute {
    name = "counter_id"
    type = "S"
  }

  tags = {
    Project     = var.project_name
    Environment = var.environment
    Purpose     = "Sequential incident ID counter"
  }
}

output "incident_counter_table_name" {
  description = "Name of the DynamoDB table used for sequential incident ID generation"
  value       = aws_dynamodb_table.incident_counter.name
}
