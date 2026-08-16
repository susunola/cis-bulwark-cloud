########################################################################
# Stack: iam
#
# CIS section 1, Identity and Access Management.
#
# Only 1.4 is enforceable. The password policy family (1.7 - 1.14), the root
# account rules (1.1 - 1.3) and key rotation (1.5 - 1.6) have no resource in
# tencentcloudstack/tencentcloud, so controls.yml reports them as MANUAL rather
# than letting this stack pretend. 1.15 / 1.16 / 8.1 / 8.2 are detect-only and
# live in the audit stack.
########################################################################

locals {
  # Controls this stack knows how to enforce. Kept in sync with controls.yml by
  # the check block below.
  implemented = ["1.4"]

  on     = { for id in local.implemented : id => contains(var.enabled_controls, id) }
  active = [for id in local.implemented : id if local.on[id]]

  mfa_targets = local.on["1.4"] ? toset([for uin in var.cam_console_user_uins : tostring(uin)]) : toset([])
}

# --- 1.4 Ensure MFA is enabled for all CAM users with a console password ---
resource "tencentcloud_cam_mfa_flag" "console_user" {
  for_each = local.mfa_targets

  op_uin = tonumber(each.value)

  login_flag {
    phone  = var.mfa_login_flag.phone
    stoken = var.mfa_login_flag.stoken
    wechat = var.mfa_login_flag.wechat
  }

  action_flag {
    phone  = var.mfa_action_flag.phone
    stoken = var.mfa_action_flag.stoken
    wechat = var.mfa_action_flag.wechat
  }
}

# Registry drift guard: if controls.yml starts routing a control to this stack
# that main.tf does not implement, fail the plan instead of silently skipping.
check "cis_registry_alignment" {
  assert {
    condition = length(setsubtract(var.enabled_controls, local.implemented)) == 0
    error_message = format(
      "controls.yml routes %s to the iam stack but main.tf does not implement it.",
      join(", ", setsubtract(var.enabled_controls, local.implemented))
    )
  }
}

check "cis_targets_present" {
  assert {
    condition     = !local.on["1.4"] || length(var.cam_console_user_uins) > 0
    error_message = "CIS 1.4 is selected but cam_console_user_uins is empty - nothing was hardened."
  }
}
