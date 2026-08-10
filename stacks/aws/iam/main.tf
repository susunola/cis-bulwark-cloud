########################################################################
# Stack: iam
#
# CIS section 2, Identity and Access Management (AWS).
#
# 2.8 / 2.9 (password policy) share one account-level resource; only the
# fields of the selected controls are set, everything else stays untouched.
# 2.18 creates an IAM External Access Analyzer. Every other 2.x control has
# no writable resource or would mean deleting user-owned credentials, so
# controls.yml reports them as MANUAL rather than letting this stack pretend.
########################################################################

locals {
  # Controls this stack knows how to enforce. Kept in sync with controls.yml by
  # the check block below.
  implemented = ["2.8", "2.9", "2.18"]

  on     = { for id in local.implemented : id => contains(var.enabled_controls, id) }
  active = [for id in local.implemented : id if local.on[id]]

  wants_password_policy = local.on["2.8"] || local.on["2.9"]
}

# --- 2.8 / 2.9 IAM account password policy ---------------------------------
# One account-level resource. A field is only written for the control selected
# in this run; null leaves the account's current value alone.
resource "aws_iam_account_password_policy" "cis" {
  count = local.wants_password_policy ? 1 : 0

  minimum_password_length        = local.on["2.8"] ? var.minimum_password_length : null
  require_lowercase_characters   = local.on["2.8"] ? var.require_lowercase_characters : null
  require_uppercase_characters   = local.on["2.8"] ? var.require_uppercase_characters : null
  require_numbers                = local.on["2.8"] ? var.require_numbers : null
  require_symbols                = local.on["2.8"] ? var.require_symbols : null
  max_password_age               = local.on["2.8"] ? var.max_password_age : null
  allow_users_to_change_password = local.on["2.8"] ? var.allow_users_to_change_password : null
  password_reuse_prevention      = local.on["2.9"] ? var.password_reuse_prevention : null
}

# --- 2.18 IAM External Access Analyzer ---------------------------------------
# Creates an account-type analyzer in the configured region. If an analyzer
# already exists (same name), import it instead of applying:
#   terraform -chdir=stacks/aws/iam import 'aws_accessanalyzer_analyzer.cis[0]' <analyzer-arn>
resource "aws_accessanalyzer_analyzer" "cis" {
  count = local.on["2.18"] ? 1 : 0

  analyzer_name = var.analyzer_name
  type          = "ACCOUNT"

  tags = var.tags
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

# Account-level controls need no inventory; the one operator-supplied knob is
# the analyzer name, which must not be blank when 2.18 is selected.
check "cis_targets_present" {
  assert {
    condition     = !local.on["2.18"] || var.analyzer_name != ""
    error_message = "CIS 2.18 is selected but analyzer_name is blank - nothing was hardened."
  }
}
