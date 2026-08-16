########################################################################
# Stack: storage
#
# CIS section 9 (Azure Storage). Takes ownership of operator-listed storage
# accounts and writes the flags 9.1.1 / 9.2.1 / 9.2.2 / 9.3.4 / 9.3.6 /
# 9.3.7 / 9.3.8 / 9.3.11 require. Import each account first:
#
#   terraform -chdir=stacks/azure/storage import \
#     'azurerm_storage_account.cis["mystorage"]' \
#     /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/mystorage
#
# The required variables must match the live account or Terraform will try to
# change them; prevent_destroy guards against accidental deletion.
########################################################################

locals {
  # Controls this stack knows how to enforce. Kept in sync with controls.yml by
  # the check block below.
  implemented = ["9.1.1", "9.2.1", "9.2.2", "9.3.4", "9.3.6", "9.3.7", "9.3.8", "9.3.11"]

  on     = { for id in local.implemented : id => contains(var.enabled_controls, id) }
  active = [for id in local.implemented : id if local.on[id]]

  accounts = length(local.active) > 0 ? { for a in var.storage_accounts : a.name => a } : {}
}

# --- 9.x storage hardening -----------------------------------------------------
resource "azurerm_storage_account" "cis" {
  for_each = local.accounts

  name                     = each.key
  resource_group_name      = each.value.resource_group_name
  location                 = each.value.location
  account_tier             = each.value.account_tier
  account_replication_type = local.on["9.3.11"] ? "GRS" : each.value.account_replication_type

  # 9.3.4 - secure transfer required
  https_traffic_only_enabled = local.on["9.3.4"] ? true : each.value.https_traffic_only_enabled
  # 9.3.6 - minimum TLS 1.2
  min_tls_version = local.on["9.3.6"] ? "TLS1_2" : each.value.min_tls_version
  # 9.3.7 - no cross-tenant replication
  cross_tenant_replication_enabled = local.on["9.3.7"] ? false : each.value.cross_tenant_replication_enabled
  # 9.3.8 - no anonymous blob access
  allow_nested_items_to_be_public = local.on["9.3.8"] ? false : each.value.allow_nested_items_to_be_public

  # 9.2.1 / 9.2.2 - blob and container soft delete (7 days)
  blob_properties {
    delete_retention_policy {
      days = local.on["9.2.1"] ? var.soft_delete_retention_days : each.value.blob_delete_retention_days
    }
    container_delete_retention_policy {
      days = local.on["9.2.2"] ? var.soft_delete_retention_days : each.value.container_delete_retention_days
    }
  }

  # 9.1.1 - file share soft delete
  share_properties {
    retention_policy {
      days = local.on["9.1.1"] ? var.soft_delete_retention_days : each.value.share_retention_days
    }
  }

  tags = var.tags

  lifecycle {
    prevent_destroy = true
  }
}

check "cis_registry_alignment" {
  assert {
    condition = length(setsubtract(var.enabled_controls, local.implemented)) == 0
    error_message = format(
      "controls.yml routes %s to the azure storage stack but main.tf does not implement it.",
      join(", ", setsubtract(var.enabled_controls, local.implemented))
    )
  }
}

check "cis_targets_present" {
  assert {
    condition     = length(local.active) == 0 || length(var.storage_accounts) > 0
    error_message = "a selected control needs operator-supplied storage_accounts inventory - nothing was hardened."
  }
}
