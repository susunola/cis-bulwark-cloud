terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
}

# For team use, switch to a dedicated S3 backend bucket. Recommended setup:
#
#   - Create a separate bucket just for Terraform state; do not reuse an
#     application log or data bucket.
#   - Enable versioning on the state bucket so a corrupt state can be rolled back.
#   - Enable default server-side encryption (SSE-S3 or SSE-KMS) on the bucket.
#   - Restrict the bucket ACL/policy to the operators / CI role that runs
#     Terraform, and enable bucket-level public access block.
#   - The S3 backend supports state locking via DynamoDB; create a lock table
#     and pass its name as the `dynamodb_table` argument.
#
# terraform {
#   backend "s3" {
#     bucket         = "tfstate-123456789012"
#     key            = "cis/aws/audit/terraform.tfstate"
#     region         = "us-east-1"
#     encrypt        = true
#     dynamodb_table = "terraform-locks"
#   }
# }
