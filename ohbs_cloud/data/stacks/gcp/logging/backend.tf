terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
}

# For team use, switch to a GCS backend bucket with versioning + encryption -
# see the audit stack backend notes in the README.
