########################################################################
# Stack: logging
#
# CIS section 4, Logging (AWS).
#
# 4.2 enables log file validation on a CloudTrail trail. The trail must
# already exist (or be created by this resource) and its S3 destination
# bucket must exist. Import an existing trail before apply:
#
#   terraform -chdir=stacks/aws/logging import 'aws_cloudtrail.cis[0]' <trail-name>
#
# The rest of section 4 has no readable/writable provider surface (CloudTrail
# data source, Config recorder, flow logs) and is reported as MANUAL.
########################################################################

locals {
  # Controls this stack knows how to enforce. Kept in sync with controls.yml by
  # the check block below.
  implemented = ["4.2"]

  on     = { for id in local.implemented : id => contains(var.enabled_controls, id) }
  active = [for id in local.implemented : id if local.on[id]]
}

# --- 4.2 CloudTrail log file validation -------------------------------------
resource "aws_cloudtrail" "cis" {
  count = local.on["4.2"] ? 1 : 0

  name                          = var.cloudtrail_name
  s3_bucket_name                = var.cloudtrail_s3_bucket
  enable_log_file_validation    = true
  is_multi_region_trail         = var.is_multi_region_trail
  include_global_service_events = var.include_global_service_events
  kms_key_id                    = var.cloudtrail_kms_key_id

  tags = var.tags

  # The trail predates this tool; protect it from accidental deletion.
  lifecycle {
    prevent_destroy = true
  }
}

# Registry drift guard: if controls.yml starts routing a control to this stack
# that main.tf does not implement, fail the plan instead of silently skipping.
check "cis_registry_alignment" {
  assert {
    condition = length(setsubtract(var.enabled_controls, local.implemented)) == 0
    error_message = format(
      "controls.yml routes %s to the logging stack but main.tf does not implement it.",
      join(", ", setsubtract(var.enabled_controls, local.implemented))
    )
  }
}

check "cis_targets_present" {
  assert {
    condition     = (!local.on["4.2"] || (var.cloudtrail_name != "" && var.cloudtrail_s3_bucket != ""))
    error_message = "a selected control needs operator-supplied inventory (see variables.tf) - nothing was hardened."
  }
}
