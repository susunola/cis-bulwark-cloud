########################################################################
# Stack: compute
#
# CIS section 4 (Compute). 4.4 writes oslogin into the project metadata.
# The other 4.x controls are detect-only against operator inventory.
########################################################################

locals {
  implemented = ["4.4"]

  on     = { for id in local.implemented : id => contains(var.enabled_controls, id) }
  active = [for id in local.implemented : id if local.on[id]]
}

# --- 4.4 Oslogin enabled for the project ----------------------------------------
# Writes the whole project metadata map - keep var.project_metadata in sync
# with everything the project already sets, or Terraform will replace it.
resource "google_compute_project_metadata" "cis" {
  count = local.on["4.4"] ? 1 : 0

  metadata = merge(var.project_metadata, { enable-oslogin = "TRUE" })
}

check "cis_registry_alignment" {
  assert {
    condition = length(setsubtract(var.enabled_controls, local.implemented)) == 0
    error_message = format(
      "controls.yml routes %s to the gcp compute stack but main.tf does not implement it.",
      join(", ", setsubtract(var.enabled_controls, local.implemented))
    )
  }
}

check "cis_targets_present" {
  assert {
    condition     = !local.on["4.4"] || lookup(var.project_metadata, "enable-oslogin", "TRUE") != "FALSE"
    error_message = "CIS 4.4 is selected but project_metadata sets enable-oslogin=FALSE, overriding the hardening."
  }
}
