########################################################################
# Stack: security
#
# CIS section 8 (Microsoft Defender / Key Vault). 8.1.13 creates the
# security contact; the Key Vault controls (8.3.x) are detect-only.
########################################################################

locals {
  implemented = ["8.1.13"]

  on     = { for id in local.implemented : id => contains(var.enabled_controls, id) }
  active = [for id in local.implemented : id if local.on[id]]
}

# --- 8.1.13 Security contact --------------------------------------------------
resource "azurerm_security_center_contact" "cis" {
  count = local.on["8.1.13"] ? 1 : 0

  name                = var.security_contact_name
  email               = var.security_contact_email
  phone               = var.security_contact_phone
  alert_notifications = true
  alerts_to_admins    = true
}

check "cis_registry_alignment" {
  assert {
    condition = length(setsubtract(var.enabled_controls, local.implemented)) == 0
    error_message = format(
      "controls.yml routes %s to the azure security stack but main.tf does not implement it.",
      join(", ", setsubtract(var.enabled_controls, local.implemented))
    )
  }
}

check "cis_targets_present" {
  assert {
    condition     = !local.on["8.1.13"] || var.security_contact_email != ""
    error_message = "CIS 8.1.13 is selected but security_contact_email is blank - nothing was hardened."
  }
}
