terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
}

# For team use, switch to an OSS backend bucket with versioning + encryption.
