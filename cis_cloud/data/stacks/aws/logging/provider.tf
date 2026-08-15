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
provider "aws" {
}
