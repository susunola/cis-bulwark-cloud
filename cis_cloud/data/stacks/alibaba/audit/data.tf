# Read-only inventory. Every data source is gated on the controls it serves.

locals {
  wanted = toset(var.enabled_controls)

  needs_users    = contains(var.enabled_controls, "1.5")
  needs_trails   = length(setintersection(local.wanted, toset(["2.1", "2.2"]))) > 0
  needs_buckets  = length(setintersection(local.wanted, toset(["2.2", "5.1", "5.3", "5.8"]))) > 0
  needs_disks    = length(setintersection(local.wanted, toset(["4.1", "4.2"]))) > 0
  needs_sg       = length(setintersection(local.wanted, toset(["4.3", "4.4"]))) > 0
  needs_db       = length(setintersection(local.wanted, toset(["6.1", "6.5"]))) > 0
  needs_td       = contains(var.enabled_controls, "8.1")
  needs_identity = length(var.enabled_controls) > 0
}

data "alicloud_ram_users" "all" {
  count = local.needs_users ? 1 : 0
}

data "alicloud_actiontrails" "all" {
  count = local.needs_trails ? 1 : 0
}

data "alicloud_oss_buckets" "all" {
  count = local.needs_buckets ? 1 : 0
}

data "alicloud_disks" "all" {
  count = local.needs_disks ? 1 : 0
}

data "alicloud_security_groups" "all" {
  count = local.needs_sg ? 1 : 0
}

data "alicloud_security_group_rules" "this" {
  for_each = (
    local.needs_sg
    ? { for g in flatten(data.alicloud_security_groups.all[*].groups) : g.id => g.id }
    : {}
  )

  group_id = each.key
}

data "alicloud_db_instances" "all" {
  count = local.needs_db ? 1 : 0
}

data "alicloud_threat_detection_instances" "all" {
  count = local.needs_td ? 1 : 0
}

# Account identity for the report header.
data "alicloud_account" "self" {
  count = local.needs_identity ? 1 : 0
}
