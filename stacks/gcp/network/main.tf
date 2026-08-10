########################################################################
# Stack: network
#
# CIS section 3 (Networking). 2.13 (DNS logging) is enforced here because it
# is a network-adjacent resource. VPC / firewall controls are detect-only or
# Manual (no firewall list, no dnssec fields on the data sources).
########################################################################

locals {
  implemented = ["2.13"]

  on     = { for id in local.implemented : id => contains(var.enabled_controls, id) }
  active = [for id in local.implemented : id if local.on[id]]

  networks = local.on["2.13"] ? toset(var.dns_logging_networks) : toset([])
}

# --- 2.13 Cloud DNS logging for all VPC networks ------------------------------
resource "google_dns_policy" "cis" {
  for_each = local.networks

  name                      = var.dns_policy_name
  enable_inbound_forwarding = false
  enable_logging            = true

  networks {
    network_url = "https://www.googleapis.com/compute/v1/projects/${var.project_id}/global/networks/${each.value}"
  }
}

check "cis_registry_alignment" {
  assert {
    condition = length(setsubtract(var.enabled_controls, local.implemented)) == 0
    error_message = format(
      "controls.yml routes %s to the gcp network stack but main.tf does not implement it.",
      join(", ", setsubtract(var.enabled_controls, local.implemented))
    )
  }
}

check "cis_targets_present" {
  assert {
    condition     = !local.on["2.13"] || length(var.dns_logging_networks) > 0
    error_message = "CIS 2.13 is selected but dns_logging_networks is empty - nothing was hardened."
  }
}
