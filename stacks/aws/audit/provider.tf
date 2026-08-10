terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Credentials and region are taken from the environment on purpose - nothing
# about an account belongs in a compliance repository.
#
#   export AWS_ACCESS_KEY_ID=...
#   export AWS_SECRET_ACCESS_KEY=...
#   export AWS_DEFAULT_REGION=us-east-1
#
# A shared credentials file or an assumed role also works; see the AWS provider
# documentation. For CIS 4.x/5.x controls that are multi-region by definition
# (CloudTrail, Config, KMS) the provider only reads the configured region, so
# run the audit once per region you care about.
provider "aws" {
}
