variable "enabled_controls" {
  description = "CIS ids this run may enforce (injected by bin/cis)."
  type        = list(string)
  default     = []
}

# ---- 9.x storage accounts -----------------------------------------------------

variable "storage_accounts" {
  description = <<-EOT
    Storage accounts to harden. Import each one before apply (see main.tf).
    location / account_tier / account_replication_type must match the live
    account; the *_enabled flags are the account's current values, kept when
    the paired control is not selected in this run.
  EOT
  type = list(object({
    name                             = string
    resource_group_name              = string
    location                         = string
    account_tier                     = string
    account_replication_type         = string
    https_traffic_only_enabled       = optional(bool, true)
    min_tls_version                  = optional(string, "TLS1_2")
    cross_tenant_replication_enabled = optional(bool, false)
    allow_nested_items_to_be_public  = optional(bool, false)
    blob_delete_retention_days       = optional(number, 0)
    container_delete_retention_days  = optional(number, 0)
    share_retention_days             = optional(number, 0)
  }))
  default = []
}

variable "soft_delete_retention_days" {
  description = "CIS 9.1.1 / 9.2.1 / 9.2.2 - retention days applied when soft delete is enforced."
  type        = number
  default     = 7
}

variable "tags" {
  description = "Tags applied to resources this stack manages."
  type        = map(string)
  default     = {}
}
