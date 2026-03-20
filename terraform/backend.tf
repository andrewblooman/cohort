terraform {
  backend "s3" {
    bucket = "PLACEHOLDER_YOUR_TERRAFORM_STATE_BUCKET"
    key    = "cohort/terraform.tfstate"
    region = "eu-west-1"
    encrypt = true
    use_lockfile = true
  }
}
