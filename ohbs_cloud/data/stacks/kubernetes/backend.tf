terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
}

# For team use, switch to a dedicated COS backend bucket. Recommended setup:
#
#   - Create a separate bucket just for Terraform state; do not reuse an
#     application log or data bucket.
#   - Enable versioning on the state bucket so a corrupt state can be rolled back.
#   - Enable default server-side encryption (SSE-KMS or SSE-COS) on the bucket.
#   - Restrict the bucket ACL to private and attach a bucket policy that only
#     allows the operators / CI role that run Terraform.
#   - The COS backend supports state locking; confirm your Terraform version
#     enables it by default or configure the appropriate lock option.
#
# terraform {
#   backend "cos" {
#     region  = "ap-guangzhou"
#     bucket  = "tfstate-1250000000"
#     prefix  = "cis/kubernetes"
#     encrypt = true
#   }
# }
