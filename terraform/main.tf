####################################
# terraform/main.tf
#
# Top-level data source lookups used across multiple resources.
# Provider and version constraints → providers.tf
# Remote state backend configuration → backend.tf
####################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
