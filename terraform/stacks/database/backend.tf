terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
}
# For team use, switch to a COS backend:
#
# terraform {
#   backend "cos" {
#     region = "ap-guangzhou"
#     bucket = "tfstate-1250000000"
#     prefix = "cis/storage"
#   }
# }
#
