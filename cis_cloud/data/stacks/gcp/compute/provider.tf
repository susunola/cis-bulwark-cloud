terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

# Credentials come from the environment (GOOGLE_APPLICATION_CREDENTIALS or
# gcloud auth application-default login) - nothing about a project belongs in
# this repository.
provider "google" {
}
