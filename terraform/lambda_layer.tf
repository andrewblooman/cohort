####################################
# Lambda Layer – shared Python utilities
#
# Packages the shared/ module as a Lambda Layer so that all
# incident-response Lambda functions can import the reusable
# CloudWatch and CloudTrail query helpers without bundling
# them into each function zip.
####################################

data "archive_file" "shared_layer" {
  type        = "zip"
  output_path = "${path.module}/../dist/shared_layer.zip"

  source {
    content  = file("${path.module}/../shared/__init__.py")
    filename = "python/shared/__init__.py"
  }

  source {
    content  = file("${path.module}/../shared/cloudwatch_queries.py")
    filename = "python/shared/cloudwatch_queries.py"
  }

  source {
    content  = file("${path.module}/../shared/cloudtrail_queries.py")
    filename = "python/shared/cloudtrail_queries.py"
  }
}

resource "aws_lambda_layer_version" "shared" {
  layer_name          = "${var.project_name}-shared-utils"
  description         = "Reusable CloudWatch and CloudTrail query utilities for incident-response Lambdas"
  filename            = data.archive_file.shared_layer.output_path
  source_code_hash    = data.archive_file.shared_layer.output_base64sha256
  compatible_runtimes = ["python3.12"]
}
