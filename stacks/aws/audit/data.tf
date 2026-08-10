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

  needs_instances = length(setintersection(local.wanted, toset(["2.16", "6.7"]))) > 0
  needs_db        = length(setintersection(local.wanted, toset(["3.2.1", "3.2.2", "3.2.3"]))) > 0
  needs_ebs       = contains(var.enabled_controls, "6.1.1")
  needs_sg        = length(setintersection(local.wanted, toset(["6.3", "6.4", "6.5"]))) > 0
  needs_identity  = length(var.enabled_controls) > 0
}

# ---- EC2 ----------------------------------------------------------------

data "aws_instances" "all" {
  count = local.needs_instances ? 1 : 0
}

# One read per instance. Keys come from a data source, which Terraform resolves
# during plan, so for_each is safe here; a count of 0 produces an empty map.
data "aws_instance" "this" {
  for_each    = toset(flatten(data.aws_instances.all[*].ids))
  instance_id = each.key
}

# ---- RDS -----------------------------------------------------------------

data "aws_db_instances" "all" {
  count = local.needs_db ? 1 : 0
}

data "aws_db_instance" "this" {
  for_each               = toset(flatten(data.aws_db_instances.all[*].instance_identifiers))
  db_instance_identifier = each.key
}

# ---- EBS ------------------------------------------------------------------

# Account-level default: whether new volumes are encrypted by default.
data "aws_ebs_encryption_by_default" "this" {
  count = local.needs_ebs ? 1 : 0
}

# ---- Security groups -------------------------------------------------------

# All groups (6.3 / 6.4) plus the per-VPC "default" groups only (6.5).
data "aws_security_groups" "all" {
  count = local.needs_sg ? 1 : 0
}

data "aws_security_groups" "default" {
  count = contains(var.enabled_controls, "6.5") ? 1 : 0

  filter {
    name   = "group-name"
    values = ["default"]
  }
}

# Every rule of every group under assessment. The rules data source is keyed by
# security group id and returns rule ids; each rule is then read individually.
data "aws_vpc_security_group_rules" "for_sg" {
  for_each = {
    for id in distinct(concat(
      flatten(data.aws_security_groups.all[*].ids),
      flatten(data.aws_security_groups.default[*].ids)
    )) : id => id
  }

  filter {
    name   = "security-group-id"
    values = [each.key]
  }
}

locals {
  sg_rule_keys = flatten([
    for sg_id, ds in data.aws_vpc_security_group_rules.for_sg : [
      for rid in ds.ids : { key = "${sg_id}/${rid}", sg = sg_id, rid = rid }
    ]
  ])
}

data "aws_vpc_security_group_rule" "this" {
  for_each = {
    for k in local.sg_rule_keys : k.key => k.rid
  }
  security_group_rule_id = each.value
}

# ---- Account identity ------------------------------------------------------

# Account id / ARN for the report header. Gated on a non-empty selection so a
# `cis list` (nothing to assess) never calls the API.
data "aws_caller_identity" "self" {
  count = local.needs_identity ? 1 : 0
}
