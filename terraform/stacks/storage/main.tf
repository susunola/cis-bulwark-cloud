########################################################################
# Stack: storage
#
# CIS 4.1, 4.3, 4.4, 4.5, 4.6, 4.7.
#
# Not here, on purpose:
#   4.2  "no publicly accessible objects" - object level ACLs are data, not
#        infrastructure. Detectable in the audit stack, never rewritten here;
#        flipping an object ACL can break a live site.
#   4.8  unattached CBS disk encryption - CBS encryption is set at create time,
#        there is no provider resource that encrypts an existing disk.
#   4.9  attached CBS disk encryption - same limitation.
#
# All three are reported as MANUAL by controls.yml, so they never reach this
# stack's enabled_controls.
########################################################################

locals {
  implemented = ["4.1", "4.3", "4.4", "4.5", "4.6", "4.7"]

  on     = { for id in local.implemented : id => contains(var.enabled_controls, id) }
  active = [for id in local.implemented : id if local.on[id]]

  any_selected = length(local.active) > 0
  has_targets  = length(var.buckets) > 0

  # A COS bucket name is always "<name>-<APPID>", so the APPID needed to build
  # the policy ARN is already in the key. var.app_id is only an override for
  # cross-account setups.
  app_id_of = {
    for name, _ in var.buckets :
    name => var.app_id != null ? var.app_id : try(regex("-([0-9]{5,})$", name)[0], "invalid")
  }

  # Buckets that are not in Terraform state can only receive a bucket policy.
  policy_only = [for name, cfg in var.buckets : name if !cfg.managed]

  # Controls selected but out of reach: either nothing to act on at all, or a
  # bucket that is policy-only and therefore cannot carry 4.3 / 4.6 / 4.7.
  from_modules = distinct(flatten([for _, m in module.bucket : m.unreachable_controls]))

  unreachable = sort(distinct(concat(
    local.has_targets ? [] : local.active,
    local.from_modules,
  )))
}

# --- 4.1 / 4.3 / 4.4 / 4.5 / 4.6 / 4.7 -------------------------------------
# One module instance per bucket. The module decides per control whether it can
# act, so adding a bucket never silently changes the meaning of a control.
module "bucket" {
  source   = "../../../modules/cos_secure_bucket"
  for_each = local.any_selected ? var.buckets : {}

  bucket = each.key
  region = var.region
  app_id = local.app_id_of[each.key]

  enabled_controls = var.enabled_controls

  manage_bucket = each.value.managed
  manage_policy = true

  log_target_bucket = each.value.log_target_bucket
  log_prefix        = each.value.log_prefix
  kms_id            = each.value.kms_id
  versioning_enable = each.value.versioning_enable
  force_clean       = each.value.force_clean

  extra_policy_statements = each.value.extra_policy_statements
  policy_override         = each.value.policy_override

  tags = var.tags
}

check "cis_registry_alignment" {
  assert {
    condition = length(setsubtract(var.enabled_controls, local.implemented)) == 0
    error_message = format(
      "controls.yml routes %s to the storage stack but main.tf does not implement it.",
      join(", ", setsubtract(var.enabled_controls, local.implemented))
    )
  }
}

check "cis_targets_present" {
  assert {
    condition = !local.any_selected || local.has_targets
    error_message = format(
      "CIS %s selected but var.buckets is empty, so nothing was hardened. See tfvars/base.tfvars.",
      join(", ", local.active)
    )
  }

  assert {
    condition = length(local.unreachable) == 0
    error_message = format(
      "selected but out of reach: %s. Buckets %s are policy-only; import them and set managed = true to cover 4.3 / 4.6 / 4.7.",
      join(", ", local.unreachable),
      length(local.policy_only) > 0 ? join(", ", local.policy_only) : "(none)"
    )
  }
}
