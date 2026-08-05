# Read-only inventory.
#
# Every data source is gated on whether any of the controls it serves is in
# var.enabled_controls. That is not just tidiness: a narrowed `cis scan` should
# not call APIs the operator has no permission for, and one unreadable service
# should not be able to fail the whole assessment.
#
# Results are always consumed through the `[*]` splat so that a count of 0
# yields an empty list instead of an index error.

locals {
  wanted = toset(var.enabled_controls)

  # control id -> data source it needs
  needs_cam_policies = contains(var.enabled_controls, "1.15")
  needs_cam_users    = contains(var.enabled_controls, "1.16")
  needs_audits       = length(setintersection(local.wanted, toset(["2.1", "2.2"]))) > 0
  needs_cos          = length(setintersection(local.wanted, toset(["2.2", "4.1", "4.2"]))) > 0
  needs_cls          = length(setintersection(local.wanted, toset(["2.3", "2.20"]))) > 0
  needs_sg           = length(setintersection(local.wanted, toset(["3.1", "3.4", "3.5", "3.6"]))) > 0
  needs_routes       = contains(var.enabled_controls, "3.3")
  needs_cbs          = length(setintersection(local.wanted, toset(["4.8", "4.9"]))) > 0
  needs_mysql        = contains(var.enabled_controls, "5.2")
  needs_tke          = length(setintersection(local.wanted, toset(["6.8", "6.9"]))) > 0
  needs_cwp          = length(setintersection(local.wanted, toset(["8.1", "8.2"]))) > 0
}

data "tencentcloud_cam_policies" "all" {
  count = local.needs_cam_policies ? 1 : 0
}

data "tencentcloud_cam_users" "all" {
  count = local.needs_cam_users ? 1 : 0
}

# One read per user - CAM has no "all attachments" endpoint. Keys come from a
# data source, which Terraform resolves during plan, so for_each is safe here.
data "tencentcloud_cam_user_policy_attachments" "per_user" {
  for_each = {
    for u in flatten(data.tencentcloud_cam_users.all[*].user_list) : u.user_id => u.name
  }
  user_id = each.key
}

data "tencentcloud_audits" "all" {
  count = local.needs_audits ? 1 : 0
}

data "tencentcloud_cos_buckets" "all" {
  count = local.needs_cos ? 1 : 0
}

data "tencentcloud_cls_topics" "all" {
  count = local.needs_cls ? 1 : 0
}

data "tencentcloud_security_groups" "all" {
  count = local.needs_sg ? 1 : 0
}

data "tencentcloud_vpc_route_tables" "all" {
  count = local.needs_routes ? 1 : 0
}

data "tencentcloud_cbs_storages" "all" {
  count = local.needs_cbs ? 1 : 0
}

data "tencentcloud_mysql_instance" "all" {
  count = local.needs_mysql ? 1 : 0
}

data "tencentcloud_kubernetes_clusters" "all" {
  count = local.needs_tke ? 1 : 0
}

data "tencentcloud_instances" "all" {
  count = local.needs_cwp ? 1 : 0
}

data "tencentcloud_cwp_machines_simple" "cvm" {
  count          = local.needs_cwp ? 1 : 0
  machine_region = var.region
  machine_type   = "CVM"
}
