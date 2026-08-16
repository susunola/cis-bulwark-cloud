variable "enabled_controls" {
  description = "CIS ids this run may enforce, injected from Cis.controls_for_stack(\"storage\")."
  type        = list(string)
  default     = []
}

variable "region" {
  description = "Region used to build COS policy ARNs."
  type        = string
  default     = "ap-guangzhou"
}

variable "app_id" {
  description = <<-EOT
    APPID used to build COS policy ARNs. Leave null: a COS bucket name is always
    "<name>-<APPID>", so it is derived from the bucket key. Set it only when the
    bucket lives under a different APPID than its name suggests.
  EOT
  type        = string
  default     = null
}

variable "buckets" {
  description = <<-EOT
    Bucket name (with APPID suffix) -> hardening settings.

    managed = false (default)
      The bucket is not in Terraform state. Only a bucket policy is written,
      which covers 4.1 (deny anonymous), 4.4 (require TLS) and 4.5 (no public
      network access). 4.3 / 4.6 / 4.7 are reported as unreachable.

    managed = true
      This stack owns the tencentcloud_cos_bucket resource, so ACL, access
      logging and server side encryption are all enforceable. Import the bucket
      first, or let the stack create it:

        terraform -chdir=stacks/storage import 'module.bucket["my-logs-1250000000"].tencentcloud_cos_bucket.this[0]' my-logs-1250000000

    log_target_bucket : required when 4.3 is selected and managed = true
    kms_id            : required when 4.7 is selected and managed = true
  EOT
  type = map(object({
    managed                 = optional(bool, false)
    log_target_bucket       = optional(string)
    log_prefix              = optional(string, "cos-access-logs/")
    kms_id                  = optional(string)
    versioning_enable       = optional(bool, true)
    force_clean             = optional(bool, false)
    extra_policy_statements = optional(list(any), [])
    policy_override         = optional(string)
  }))
  default = {}
}

variable "tags" {
  description = "Tags applied to buckets this stack manages."
  type        = map(string)
  default     = { "managed-by" = "cis" }
}
