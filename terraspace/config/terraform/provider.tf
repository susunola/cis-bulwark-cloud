terraform {
  required_version = ">= 1.5.0"

  required_providers {
    tencentcloud = {
      source  = "tencentcloudstack/tencentcloud"
      version = "~> 1.81"
    }
  }
}

# Credentials and region are taken from the environment on purpose - nothing
# about an account belongs in a compliance repository.
#
#   export TENCENTCLOUD_SECRET_ID=...
#   export TENCENTCLOUD_SECRET_KEY=...
#   export TENCENTCLOUD_REGION=ap-guangzhou
#
# A shared credentials file or an assumed role also works; see the provider
# documentation. This file is copied into every built stack by Terraspace.
provider "tencentcloud" {
}
