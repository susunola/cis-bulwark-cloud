terraform {
  required_version = ">= 1.5.0"

  required_providers {
    alicloud = {
      source  = "aliyun/alicloud"
      version = "~> 1.0"
    }
  }
}

# Credentials come from the environment (ALICLOUD_ACCESS_KEY,
# ALICLOUD_SECRET_KEY, ALICLOUD_REGION) - nothing about an account belongs
# in this repository.
provider "alicloud" {
}
