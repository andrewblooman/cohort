####################################
# Web UI – S3 static site + CloudFront
#
# Hosts the Cohort analyst dashboard.
#
# Assets are uploaded from ui/ at Terraform apply time.  The config.js
# asset is rendered as a Terraform template so it contains the correct
# API Gateway endpoint URL automatically.
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
# CloudFront Origin Access Control
####################################

resource "aws_cloudfront_origin_access_control" "ui" {
  name                              = "${var.project_name}-ui-oac"
  description                       = "OAC for Cohort web UI S3 bucket"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

####################################
# S3 bucket policy – CloudFront OAC only
####################################

data "aws_iam_policy_document" "ui_bucket" {
  statement {
    sid     = "AllowCloudFrontOAC"
    effect  = "Allow"
    actions = ["s3:GetObject"]
    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }
    resources = ["${aws_s3_bucket.ui.arn}/*"]
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.ui.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "ui" {
  bucket = aws_s3_bucket.ui.id
  policy = data.aws_iam_policy_document.ui_bucket.json

  depends_on = [aws_s3_bucket_public_access_block.ui]
}

####################################
# CloudFront distribution
####################################

resource "aws_cloudfront_distribution" "ui" {
  enabled             = true
  default_root_object = "index.html"
  comment             = "Cohort analyst dashboard"
  price_class         = "PriceClass_100"

  origin {
    domain_name              = aws_s3_bucket.ui.bucket_regional_domain_name
    origin_id                = "cohort-ui-s3"
    origin_access_control_id = aws_cloudfront_origin_access_control.ui.id
  }

  default_cache_behavior {
    target_origin_id       = "cohort-ui-s3"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true

    forwarded_values {
      query_string = false
      cookies { forward = "none" }
    }

    min_ttl     = 0
    default_ttl = 300
    max_ttl     = 3600
  }

  # config.js: short TTL so API endpoint updates propagate quickly
  ordered_cache_behavior {
    path_pattern           = "/config.js"
    target_origin_id       = "cohort-ui-s3"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true

    forwarded_values {
      query_string = false
      cookies { forward = "none" }
    }

    min_ttl     = 0
    default_ttl = 60
    max_ttl     = 60
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  tags = {
    Name = "${var.project_name}-cloudfront-ui"
  }
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
