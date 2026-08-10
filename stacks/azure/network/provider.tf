terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

# Credentials come from the environment (ARM_* variables: ARM_CLIENT_ID,
# ARM_CLIENT_SECRET, ARM_SUBSCRIPTION_ID, ARM_TENANT_ID) or Azure CLI login -
# nothing about an account belongs in a compliance repository.
provider "azurerm" {
  features {}
}
