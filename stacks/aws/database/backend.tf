terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
}

# For team use, switch to a dedicated S3 backend bucket with versioning,
# encryption and a DynamoDB lock table - see stacks/aws/audit/backend.tf for
# the recommended setup.
