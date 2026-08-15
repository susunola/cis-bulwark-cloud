variable "enabled_controls" {
  description = <<-EOT
    Control ids this run should assess. Rendered by bin/cis from the operator's
    filters and the controls the provider can actually observe.
  EOT
  type        = list(string)
  default     = []
}

variable "region" {
  description = "Region reported in the account header (the provider reads its own from the environment)."
  type        = string
  default     = "eastus"
}

# ---- operator-supplied inventory -------------------------------------------
# azurerm data sources are name-based: there is no "list every NSG / storage
# account" enumerator. Every control below is checked against the resources
# you list here. A listed resource must exist, or its data source fails.

variable "databricks_workspaces" {
  description = "CIS 2.1.1 / 2.1.9 - Azure Databricks workspaces to check."
  type = list(object({
    name                = string
    resource_group_name = string
  }))
  default = []
}

variable "network_security_groups" {
  description = "CIS 7.1 - 7.4 - NSGs to check for internet-facing admin ports."
  type = list(object({
    name                = string
    resource_group_name = string
  }))
  default = []
}

variable "application_gateways" {
  description = "CIS 7.10 / 7.12 / 7.14 - Application Gateways to check."
  type = list(object({
    name                = string
    resource_group_name = string
  }))
  default = []
}

variable "key_vaults" {
  description = "CIS 8.3.5 / 8.3.6 / 8.3.7 - Key Vaults to check."
  type = list(object({
    name                = string
    resource_group_name = string
  }))
  default = []
}

variable "storage_accounts" {
  description = "CIS 9.3.4 / 9.3.6 / 9.3.8 / 9.3.11 - Storage Accounts to check."
  type = list(object({
    name                = string
    resource_group_name = string
  }))
  default = []
}
