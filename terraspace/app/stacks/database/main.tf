########################################################################
# Stack: database - TencentDB for MySQL
#
# CIS 5.1, 5.2, 5.3, 5.4, 5.5, 5.6.
#
# Scope note for 5.2. The provider has no standalone resource for the public
# network endpoint; `internet_service` is an attribute of
# tencentcloud_mysql_instance, and importing a whole production database into
# this state file to flip one field is not a trade these stacks make. What is
# enforced instead is the control that actually gates the traffic: a security
# group that permits only private sources. Closing the WAN endpoint itself is
# reported by `cis scan` and left to you:
#
#   tccli cdb CloseWanService --InstanceId cdb-xxxxxxxx
#
# Scope note for 5.5 / 5.6. Enabling TDE is a one-way door - MySQL cannot be
# decrypted afterwards. The resource below therefore has no meaningful destroy,
# and `cis destroy` will drop it from state without changing the instance.
########################################################################

locals {
  implemented = ["5.1", "5.2", "5.3", "5.4", "5.5", "5.6"]

  on     = { for id in local.implemented : id => contains(var.enabled_controls, id) }
  active = [for id in local.implemented : id if local.on[id]]

  any_selected = length(local.active) > 0
  has_targets  = length(var.mysql_instances) > 0

  # ---- 5.2 security groups -------------------------------------------------
  create_sg = local.on["5.2"] && var.db_security_group.create

  # Ingress the generated group is asked for. The section 3 baseline still gets
  # a veto, so an over-broad CIDR here is dropped, not applied.
  generated_ingress = concat(
    [for cidr in var.db_security_group.allowed_cidrs :
    "ACCEPT#${cidr}#${var.db_security_group.port}#TCP"],
    var.db_security_group.extra_ingress,
  )

  created_sg_ids = local.create_sg ? [tencentcloud_security_group.db[0].id] : []
  default_sg_ids = concat(var.default_security_group_ids, local.created_sg_ids)

  sg_of = {
    for id, cfg in var.mysql_instances :
    id => length(cfg.security_group_ids) > 0 ? cfg.security_group_ids : local.default_sg_ids
  }

  # Keys must be known at plan time, so index rather than the (possibly
  # not-yet-created) security group id.
  sg_pairs = flatten([
    for id, sgs in local.sg_of : [
      for idx, sg in sgs : {
        key               = "${id}#${idx}"
        instance_id       = id
        security_group_id = sg
      }
    ]
  ])

  sg_attachments = local.on["5.2"] ? { for p in local.sg_pairs : p.key => p } : {}

  instances_without_sg = [for id, sgs in local.sg_of : id if length(sgs) == 0]

  # ---- 5.3 / 5.4 audit -----------------------------------------------------
  audit_wanted = local.on["5.3"] || local.on["5.4"]

  audit_retention_of = {
    for id, cfg in var.mysql_instances :
    id => cfg.audit_log_expire_day != null ? cfg.audit_log_expire_day : var.audit_log_expire_day
  }

  audit_retention_too_short = [
    for id, days in local.audit_retention_of : id if days <= var.audit_min_retention_days
  ]

  # ---- 5.5 / 5.6 TDE -------------------------------------------------------
  tde_wanted = local.on["5.5"] || local.on["5.6"]

  tde_key_of = {
    for id, cfg in var.mysql_instances :
    id => cfg.kms_key_id != null ? cfg.kms_key_id : var.kms_key_id
  }

  tde_key_region_of = {
    for id, cfg in var.mysql_instances :
    id => coalesce(cfg.kms_key_region, var.kms_key_region, var.region)
  }

  instances_without_cmk = [for id, key in local.tde_key_of : id if key == null]

  # ---- selected but out of reach ------------------------------------------
  unreachable = sort(distinct(concat(
    local.has_targets ? [] : local.active,
    local.on["5.2"] && length(local.instances_without_sg) > 0 ? ["5.2"] : [],
    local.on["5.4"] && length(local.audit_retention_too_short) > 0 ? ["5.4"] : [],
    local.on["5.6"] && length(local.instances_without_cmk) > 0 ? ["5.6"] : [],
  )))
}

# --- 5.1 Require SSL for all incoming connections --------------------------
resource "tencentcloud_mysql_ssl" "this" {
  for_each = local.on["5.1"] ? var.mysql_instances : {}

  instance_id = each.value.ro_group_id == null ? each.key : null
  ro_group_id = each.value.ro_group_id
  status      = "ON"
}

# --- 5.2 Private access only: a security group that says so ----------------
resource "tencentcloud_security_group" "db" {
  count = local.create_sg ? 1 : 0

  name        = var.db_security_group.name
  description = "CIS 5.2 - TencentDB for MySQL, private sources only"
  project_id  = var.db_security_group.project_id
  tags        = var.tags
}

module "db_security_group" {
  source = "../../modules/security_group_baseline"
  count  = local.create_sg ? 1 : 0

  security_group_id = tencentcloud_security_group.db[0].id

  ingress = local.generated_ingress
  egress  = var.db_security_group.egress

  # Borrow the section 3 baseline so an over-broad allowed_cidr is filtered out
  # here rather than quietly becoming the database's new front door.
  enabled_controls = ["3.1", "3.4", "3.5", "3.6"]

  remote_access_ports = [var.db_security_group.port]

  # A database group with no ingress is a deliberate outcome here, not the
  # accident the guard rail exists to prevent.
  allow_empty_ingress = true
}

resource "tencentcloud_mysql_security_groups_attachment" "this" {
  for_each = local.sg_attachments

  instance_id       = each.value.instance_id
  security_group_id = each.value.security_group_id
}

# --- 5.3 audit function enabled / 5.4 retention over six months ------------
resource "tencentcloud_mysql_audit_service" "this" {
  for_each = local.audit_wanted ? var.mysql_instances : {}

  instance_id = each.key

  # 5.3: audit everything rather than a narrow rule template.
  audit_all = each.value.audit_all != null ? each.value.audit_all : var.audit_all

  # 5.4: retention. Required by the API even when only 5.3 was selected.
  log_expire_day      = local.audit_retention_of[each.key]
  high_log_expire_day = each.value.high_log_expire_day != null ? each.value.high_log_expire_day : var.audit_high_log_expire_day

  lifecycle {
    precondition {
      condition     = !contains(var.enabled_controls, "5.4") || local.audit_retention_of[each.key] > var.audit_min_retention_days
      error_message = "CIS 5.4 wants more than ${var.audit_min_retention_days} days of audit log for ${each.key}; audit_log_expire_day is ${local.audit_retention_of[each.key]}."
    }
  }
}

# --- 5.5 TDE enabled / 5.6 TDE protector is a customer managed CMK ---------
resource "tencentcloud_mysql_instance_encryption_operation" "this" {
  for_each = local.tde_wanted ? var.mysql_instances : {}

  instance_id = each.key

  # Null means the Tencent managed key: TDE is on (5.5) but the protector is
  # not customer managed (5.6).
  key_id     = local.on["5.6"] ? local.tde_key_of[each.key] : null
  key_region = local.on["5.6"] && local.tde_key_of[each.key] != null ? local.tde_key_region_of[each.key] : null

  lifecycle {
    precondition {
      condition     = !contains(var.enabled_controls, "5.6") || local.tde_key_of[each.key] != null
      error_message = "CIS 5.6 needs a customer managed CMK for ${each.key}. Set kms_key_id, or exclude 5.6 and keep 5.5 for Tencent managed TDE."
    }
  }
}

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
    condition = !local.any_selected || local.has_targets
    error_message = format(
      "CIS %s selected but var.mysql_instances is empty, so nothing was hardened. See tfvars/base.tfvars.",
      join(", ", local.active)
    )
  }

  assert {
    condition = length(local.unreachable) == 0
    error_message = format(
      "selected but out of reach: %s. No security group for %s; audit retention too short on %s; no CMK for %s.",
      join(", ", local.unreachable),
      length(local.instances_without_sg) > 0 ? join(", ", local.instances_without_sg) : "(none)",
      length(local.audit_retention_too_short) > 0 ? join(", ", local.audit_retention_too_short) : "(none)",
      length(local.instances_without_cmk) > 0 ? join(", ", local.instances_without_cmk) : "(none)"
    )
  }
}

check "cis_5_2_residual_exposure" {
  assert {
    condition = !local.on["5.2"] || !local.has_targets || var.wan_endpoint_reviewed
    error_message = format(
      "CIS 5.2: security groups were attached to %s, but the public network endpoint itself is not managed here. Check WanStatus with 'tccli cdb DescribeDBInstances', close it with 'tccli cdb CloseWanService --InstanceId <id>', then set wan_endpoint_reviewed = true to silence this.",
      join(", ", keys(var.mysql_instances))
    )
  }
}
