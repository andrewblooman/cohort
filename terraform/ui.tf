####################################
# Web UI – Private S3 bucket (VPC endpoint access only)
#
# Hosts the Cohort analyst dashboard as static files in a private S3 bucket.
# Access is restricted to requests arriving via a corporate VPC Interface
# Endpoint for S3 (var.ui_vpc_endpoint_id).  No public internet path exists.
#
# Assets are uploaded from ui/ at Terraform apply time.  The config.js
# asset is rendered as a Terraform template so it contains the correct
# API Gateway endpoint URL automatically.
#
# Access pattern:
#   Corporate VPN / Direct Connect → VPC Interface Endpoint for S3
#   → s3://<bucket>/index.html (private, no CloudFront)
####################################

####################################
# S3 bucket – private, no public access
####################################

resource "aws_s3_bucket" "ui" {
  bucket = "${var.project_name}-ui-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name = "${var.project_name}-ui"
  }
}

resource "aws_s3_bucket_public_access_block" "ui" {
  bucket                  = aws_s3_bucket.ui.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "ui" {
  bucket = aws_s3_bucket.ui.id
  versioning_configuration {
    status = "Enabled"
  }
}

####################################
# S3 bucket policy – VPC endpoint only
#
# AWS does not classify an aws:SourceVpce-conditioned policy as "public",
# so block_public_policy above does not conflict with this grant.
####################################

data "aws_iam_policy_document" "ui_bucket" {
  statement {
    sid     = "AllowVpcEndpointGetObject"
    effect  = "Allow"
    actions = ["s3:GetObject"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    resources = ["${aws_s3_bucket.ui.arn}/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceVpce"
      values   = [var.ui_vpc_endpoint_id]
    }
  }
}

resource "aws_s3_bucket_policy" "ui" {
  bucket = aws_s3_bucket.ui.id
  policy = data.aws_iam_policy_document.ui_bucket.json

  depends_on = [aws_s3_bucket_public_access_block.ui]
}

####################################
# S3 objects – static UI assets
####################################

# config.js is generated from a template so it contains the real API endpoint.
resource "aws_s3_object" "ui_config_js" {
  bucket       = aws_s3_bucket.ui.id
  key          = "config.js"
  content      = "window.COHORT_API_BASE = \"${aws_apigatewayv2_api.approval.api_endpoint}\";\n"
  content_type = "application/javascript"
  etag         = md5("window.COHORT_API_BASE = \"${aws_apigatewayv2_api.approval.api_endpoint}\";\n")
}

resource "aws_s3_object" "ui_index_html" {
  bucket       = aws_s3_bucket.ui.id
  key          = "index.html"
  source       = "${path.module}/../ui/index.html"
  content_type = "text/html"
  etag         = filemd5("${path.module}/../ui/index.html")
}

resource "aws_s3_object" "ui_investigation_html" {
  bucket       = aws_s3_bucket.ui.id
  key          = "investigation.html"
  source       = "${path.module}/../ui/investigation.html"
  content_type = "text/html"
  etag         = filemd5("${path.module}/../ui/investigation.html")
}

resource "aws_s3_object" "ui_logo" {
  bucket       = aws_s3_bucket.ui.id
  key          = "assets/repo_image.jpg"
  source       = "${path.module}/../assets/repo_image.jpg"
  content_type = "image/jpeg"
  etag         = filemd5("${path.module}/../assets/repo_image.jpg")
}
