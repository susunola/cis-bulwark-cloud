########################################################################
# Stack: iam
#
# CIS section 1 (Identity and Access Management). 1.7 - 1.14 write the RAM
# password policy; only the fields of the selected controls are set, the
# rest keep their current account value.
########################################################################

locals {
  implemented = ["1.7", "1.8", "1.9", "1.10", "1.11", "1.12", "1.13", "1.14"]

  on     = { for id in local.implemented : id => contains(var.enabled_controls, id) }
  active = [for id in local.implemented : id if local.on[id]]
}

# --- 1.7 - 1.14 RAM account password policy ------------------------------------
resource "alicloud_ram_account_password_policy" "cis" {
  count = length(local.active) > 0 ? 1 : 0

  minimum_password_length      = local.on["1.11"] ? var.minimum_password_length : null
  require_lowercase_characters = local.on["1.8"] ? var.require_lowercase_characters : null
  require_uppercase_characters = local.on["1.7"] ? var.require_uppercase_characters : null
  require_numbers              = local.on["1.10"] ? var.require_numbers : null
  require_symbols              = local.on["1.9"] ? var.require_symbols : null
  max_password_age             = local.on["1.13"] ? var.max_password_age : null
  password_reuse_prevention    = local.on["1.12"] ? var.password_reuse_prevention : null
  max_login_attempts           = local.on["1.14"] ? var.max_login_attempts : null
}

check "cis_registry_alignment" {
  assert {
    condition = length(setsubtract(var.enabled_controls, local.implemented)) == 0
    error_message = format(
      "controls.yml routes %s to the alibaba iam stack but main.tf does not implement it.",
      join(", ", setsubtract(var.enabled_controls, local.implemented))
    )
  }
}

check "cis_targets_present" {
  assert {
    condition     = !local.on["1.11"] || var.minimum_password_length >= 14
    error_message = "CIS 1.11 is selected but minimum_password_length is below 14 - nothing was hardened."
  }
}
