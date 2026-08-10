terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
}

# For team use, switch to a dedicated backend (azurerm storage account with
# versioning + encryption, or terraform cloud) - see the audit stack backend
# notes in the README.
