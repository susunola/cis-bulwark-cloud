terraform {
  required_version = ">= 1.5.0"

  required_providers {
    tencentcloud = {
      source  = "tencentcloudstack/tencentcloud"
      version = "~> 1.81"
    }
  }
}

# Credentials and region are taken from the environment.
#   export TENCENTCLOUD_SECRET_ID=...
#   export TENCENTCLOUD_SECRET_KEY=...
#   export TENCENTCLOUD_REGION=ap-guangzhou
provider "tencentcloud" {
}
