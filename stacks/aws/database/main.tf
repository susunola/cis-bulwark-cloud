########################################################################
# Stack: database
#
# CIS section 3.2, Relational Database Service (AWS).
#
# 3.2.2 / 3.2.3 take ownership of operator-listed RDS instances and set
# auto_minor_version_upgrade / publicly_accessible. Every instance must be
# imported first, and the required fields below must match the live instance
# or Terraform will try to change them:
#
#   terraform -chdir=stacks/aws/database import 'aws_db_instance.cis["my-db"]' my-db
#
# prevent_destroy guards the instances against accidental deletion.
########################################################################

locals {
  # Controls this stack knows how to enforce. Kept in sync with controls.yml by
  # the check block below.
  implemented = ["3.2.2", "3.2.3"]

  on     = { for id in local.implemented : id => contains(var.enabled_controls, id) }
  active = [for id in local.implemented : id if local.on[id]]

  instances = local.on["3.2.2"] || local.on["3.2.3"] ? toset(var.db_instance_identifiers) : toset([])
}

# --- 3.2.2 / 3.2.3 RDS hardening ---------------------------------------------
resource "aws_db_instance" "cis" {
  for_each = local.instances

  identifier     = each.key
  engine         = var.db_engine
  instance_class = var.db_instance_class

  # Fields 3.2.2 / 3.2.3 write; the rest must mirror the imported instance.
  auto_minor_version_upgrade = local.on["3.2.2"] ? true : var.db_auto_minor_version_upgrade
  publicly_accessible        = local.on["3.2.3"] ? false : var.db_publicly_accessible

  skip_final_snapshot = true

  tags = var.tags

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
      "controls.yml routes %s to the database stack but main.tf does not implement it.",
      join(", ", setsubtract(var.enabled_controls, local.implemented))
    )
  }
}

check "cis_targets_present" {
  assert {
    condition     = ((!local.on["3.2.2"] && !local.on["3.2.3"]) || length(var.db_instance_identifiers) > 0)
    error_message = "a selected control needs operator-supplied inventory (see variables.tf) - nothing was hardened."
  }
}
