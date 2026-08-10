########################################################################
# Stack: logging
#
# CIS section 2 (Logging and Monitoring). 2.1 creates an ActionTrail that
# exports all log entries to an OSS bucket.
########################################################################

locals {
  implemented = ["2.1"]

  on     = { for id in local.implemented : id => contains(var.enabled_controls, id) }
  active = [for id in local.implemented : id if local.on[id]]
}

# --- 2.1 ActionTrail exporting all log entries ----------------------------------
resource "alicloud_actiontrail" "cis" {
  count = local.on["2.1"] ? 1 : 0

  name            = var.trail_name
  oss_bucket_name = var.oss_bucket_name
  event_rw        = "All"
  trail_region    = "All"
  status          = "Enable"
}

check "cis_registry_alignment" {
  assert {
    condition = length(setsubtract(var.enabled_controls, local.implemented)) == 0
    error_message = format(
      "controls.yml routes %s to the alibaba logging stack but main.tf does not implement it.",
      join(", ", setsubtract(var.enabled_controls, local.implemented))
    )
  }
}

check "cis_targets_present" {
  assert {
    condition     = !local.on["2.1"] || var.oss_bucket_name != ""
    error_message = "CIS 2.1 is selected but oss_bucket_name is blank - nothing was hardened."
  }
}
