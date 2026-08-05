########################################################################
# cos_secure_bucket
#
# CIS 4.1 / 4.3 / 4.4 / 4.5 / 4.6 / 4.7.
#
# Two modes, because the provider draws a hard line:
#
#   manage_bucket = true   the bucket resource is ours, so ACL / logging /
#                          server-side encryption are all reachable.
#   manage_bucket = false  the bucket predates us. Only tencentcloud_cos_bucket
#                          _policy works without importing, so 4.3 / 4.6 / 4.7
#                          are reported as out of reach instead of pretended.
########################################################################

locals {
  on = { for id in ["4.1", "4.3", "4.4", "4.5", "4.6", "4.7"] : id => contains(var.enabled_controls, id) }

  # 4.7 (SSE-KMS) is strictly stronger than 4.6 (SSE-COS); if both are selected
  # and a CMK was supplied, KMS wins.
  use_kms = local.on["4.7"] && var.kms_id != null
  encryption_algorithm = (
    local.use_kms ? "KMS" :
    local.on["4.6"] ? "AES256" :
    null
  )

  enable_logging = local.on["4.3"] && var.log_target_bucket != null

  # qcs::cos:<region>:uid/<appid>:<bucket>/*
  resource_arn = "qcs::cos:${var.region}:uid/${var.app_id}:${var.bucket}/*"

  # ---- 4.5 / 4.1: nothing anonymous, ever -------------------------------
  deny_anonymous = {
    Principal = { qcs = ["qcs::cam::anyone:anyone"] }
    Effect    = "Deny"
    Action    = ["name/cos:*"]
    Resource  = [local.resource_arn]
  }

  # ---- 4.4: 'Secure transfer required' ----------------------------------
  deny_insecure_transport = {
    Principal = { qcs = ["qcs::cam::anyone:anyone"] }
    Effect    = "Deny"
    Action    = ["name/cos:*"]
    Resource  = [local.resource_arn]
    Condition = {
      bool = {
        "qcs:secure_transport" = "false"
      }
    }
  }

  generated_statements = concat(
    local.on["4.5"] || local.on["4.1"] ? [local.deny_anonymous] : [],
    local.on["4.4"] ? [local.deny_insecure_transport] : [],
    var.extra_policy_statements,
  )

  generated_policy = jsonencode({
    version   = "2.0"
    Statement = local.generated_statements
  })

  policy_document = var.policy_override != null ? var.policy_override : local.generated_policy

  # Only write a policy when there is something to say.
  attach_policy = var.manage_policy && (var.policy_override != null || length(local.generated_statements) > 0)

  # Controls this invocation genuinely cannot reach, so callers can surface them.
  unreachable = var.manage_bucket ? [] : compact([
    local.on["4.3"] ? "4.3" : "",
    local.on["4.6"] ? "4.6" : "",
    local.on["4.7"] ? "4.7" : "",
  ])
}

resource "tencentcloud_cos_bucket" "this" {
  count = var.manage_bucket ? 1 : 0

  bucket = var.bucket

  # 4.1 - never anonymous
  acl = local.on["4.1"] ? "private" : var.acl

  # 4.3 - access logging
  log_enable        = local.enable_logging
  log_target_bucket = local.enable_logging ? var.log_target_bucket : null
  log_prefix        = local.enable_logging ? var.log_prefix : null

  # 4.6 / 4.7 - server side encryption
  encryption_algorithm = local.encryption_algorithm
  kms_id               = local.use_kms ? var.kms_id : null

  versioning_enable = var.versioning_enable
  force_clean       = var.force_clean
  tags              = var.tags

  lifecycle {
    precondition {
      condition     = !(local.on["4.7"] && var.kms_id == null)
      error_message = "CIS 4.7 (SSE-KMS) is selected for ${var.bucket} but kms_id is null. Supply a CMK or exclude 4.7."
    }
    precondition {
      condition     = !(local.on["4.3"] && var.log_target_bucket == null)
      error_message = "CIS 4.3 (bucket logging) is selected for ${var.bucket} but log_target_bucket is null."
    }
  }
}

resource "tencentcloud_cos_bucket_policy" "this" {
  count = local.attach_policy ? 1 : 0

  bucket = var.bucket
  policy = local.policy_document

  depends_on = [tencentcloud_cos_bucket.this]
}
