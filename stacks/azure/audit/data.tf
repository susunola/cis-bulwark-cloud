# Read-only inventory. Every data source is gated on whether any control it
# serves is in var.enabled_controls, so a narrowed `cis scan` only calls the
# APIs it needs. Listed resources must exist - an azurerm data source aborts
# on a 404, which is exactly what an operator wants to notice.

locals {
  wanted = toset(var.enabled_controls)

  needs_databricks = length(setintersection(local.wanted, toset(["2.1.1", "2.1.9"]))) > 0
  needs_nsg        = length(setintersection(local.wanted, toset(["7.1", "7.2", "7.3", "7.4"]))) > 0
  needs_appgw      = length(setintersection(local.wanted, toset(["7.10", "7.12", "7.14"]))) > 0
  needs_keyvault   = length(setintersection(local.wanted, toset(["8.3.5", "8.3.6", "8.3.7"]))) > 0
  needs_storage    = length(setintersection(local.wanted, toset(["9.3.4", "9.3.6", "9.3.8", "9.3.11"]))) > 0
  needs_identity   = length(var.enabled_controls) > 0
}

data "azurerm_databricks_workspace" "this" {
  for_each = (
    local.needs_databricks
    ? { for w in var.databricks_workspaces : w.name => w }
    : {}
  )

  name                = each.key
  resource_group_name = each.value.resource_group_name
}

data "azurerm_network_security_group" "this" {
  for_each = (
    local.needs_nsg
    ? { for g in var.network_security_groups : g.name => g }
    : {}
  )

  name                = each.key
  resource_group_name = each.value.resource_group_name
}

data "azurerm_application_gateway" "this" {
  for_each = (
    local.needs_appgw
    ? { for g in var.application_gateways : g.name => g }
    : {}
  )

  name                = each.key
  resource_group_name = each.value.resource_group_name
}

data "azurerm_key_vault" "this" {
  for_each = (
    local.needs_keyvault
    ? { for v in var.key_vaults : v.name => v }
    : {}
  )

  name                = each.key
  resource_group_name = each.value.resource_group_name
}

data "azurerm_storage_account" "this" {
  for_each = (
    local.needs_storage
    ? { for a in var.storage_accounts : a.name => a }
    : {}
  )

  name                = each.key
  resource_group_name = each.value.resource_group_name
}

# Subscription / tenant identity for the report header.
data "azurerm_client_config" "self" {
  count = local.needs_identity ? 1 : 0
}
