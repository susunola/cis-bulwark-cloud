########################################################################
# Stack: network
#
# CIS section 7 (Azure Networking). Only 7.6 is enforceable: a Network
# Watcher per listed region. NSG / Application Gateway controls are
# detect-only (see the audit stack inventory).
########################################################################

locals {
  implemented = ["7.6"]

  on     = { for id in local.implemented : id => contains(var.enabled_controls, id) }
  active = [for id in local.implemented : id if local.on[id]]

  watcher_locations = local.on["7.6"] ? toset(var.watcher_locations) : toset([])
}

# --- 7.6 Network Watcher enabled per region ---------------------------------
resource "azurerm_network_watcher" "cis" {
  for_each = local.watcher_locations

  name                = var.network_watcher_name
  location            = each.value
  resource_group_name = var.watcher_resource_group

  tags = var.tags
}

# Registry drift guard.
check "cis_registry_alignment" {
  assert {
    condition = length(setsubtract(var.enabled_controls, local.implemented)) == 0
    error_message = format(
      "controls.yml routes %s to the azure network stack but main.tf does not implement it.",
      join(", ", setsubtract(var.enabled_controls, local.implemented))
    )
  }
}

check "cis_targets_present" {
  assert {
    condition     = !local.on["7.6"] || length(var.watcher_locations) > 0
    error_message = "CIS 7.6 is selected but watcher_locations is empty - nothing was hardened."
  }
}
