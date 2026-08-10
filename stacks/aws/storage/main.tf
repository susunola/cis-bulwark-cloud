########################################################################
# Stack: storage
#
# CIS section 3 (S3) and 6.1.1 (EBS), AWS.
#
# 3.1.1 writes a deny-HTTP bucket policy on operator-listed buckets. The
# policy is additive in intent but *overwrites* whatever policy the bucket
# has - list exactly the buckets you own and review the existing policy
# first.
# 6.1.1 flips the account-level EBS encryption default on.
########################################################################

locals {
  # Controls this stack knows how to enforce. Kept in sync with controls.yml by
  # the check block below.
  implemented = ["3.1.1", "6.1.1"]

  on     = { for id in local.implemented : id => contains(var.enabled_controls, id) }
  active = [for id in local.implemented : id if local.on[id]]

  buckets = local.on["3.1.1"] ? toset(var.buckets) : toset([])
}

# --- 3.1.1 S3 bucket policy denies HTTP --------------------------------------
# Deny s3:* when aws:SecureTransport is false, at bucket and object level.
data "aws_iam_policy_document" "deny_http" {
  for_each = local.buckets

  statement {
    sid       = "CIS3111DenyHTTP"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = ["arn:aws:s3:::${each.key}", "arn:aws:s3:::${each.key}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "deny_http" {
  for_each = data.aws_iam_policy_document.deny_http

  bucket = each.key
  policy = data.aws_iam_policy_document.deny_http[each.key].json
}

# --- 6.1.1 EBS encryption by default -----------------------------------------
# Account-level default for every newly created volume in the region.
resource "aws_ebs_encryption_by_default" "cis" {
  count   = local.on["6.1.1"] ? 1 : 0
  enabled = true
}

# Registry drift guard: if controls.yml starts routing a control to this stack
# that main.tf does not implement, fail the plan instead of silently skipping.
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
    condition     = (!local.on["3.1.1"] || length(var.buckets) > 0)
    error_message = "a selected control needs operator-supplied inventory (see variables.tf) - nothing was hardened."
  }
}
