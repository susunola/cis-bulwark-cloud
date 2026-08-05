variable "bucket" {
  description = "Bucket name including the APPID suffix, e.g. 'cis-audit-1250000000'."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,58}-[0-9]{5,}$", var.bucket))
    error_message = "bucket must be a COS name ending in '-<APPID>', e.g. 'my-logs-1250000000'."
  }
}

variable "region" {
  description = "Region the bucket lives in. Used to build the policy resource ARN."
  type        = string
}

variable "app_id" {
  description = "Tencent Cloud APPID that owns the bucket (the numeric suffix of `bucket`)."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{5,}$", var.app_id))
    error_message = "app_id must be numeric."
  }
}

variable "enabled_controls" {
  description = "CIS ids selected for this run. Controls 4.1 / 4.3 / 4.4 / 4.5 / 4.6 / 4.7 are honoured."
  type        = list(string)
  default     = []
}

variable "manage_bucket" {
  description = <<-EOT
    true  - this module owns the bucket resource and can enforce ACL, logging
            and server side encryption (4.1, 4.3, 4.6, 4.7).
    false - the bucket already exists and is not in Terraform state; only the
            bucket policy is managed (4.1 partially, 4.4, 4.5). Enforcing
            encryption or logging on an unmanaged bucket would require
            importing it, which this module refuses to do implicitly.
  EOT
  type        = bool
  default     = false
}

variable "manage_policy" {
  description = "Attach the generated bucket policy (needed for 4.4 / 4.5)."
  type        = bool
  default     = true
}

variable "acl" {
  description = "ACL used when manage_bucket is true. CIS 4.1 requires a non-public value."
  type        = string
  default     = "private"

  validation {
    condition     = contains(["private", "public-read", "public-read-write"], var.acl)
    error_message = "acl must be private, public-read or public-read-write."
  }
}

variable "log_target_bucket" {
  description = "Destination bucket for COS access logs (CIS 4.3). Required when 4.3 is selected and manage_bucket is true."
  type        = string
  default     = null
}

variable "log_prefix" {
  description = "Key prefix for delivered access logs (CIS 4.3)."
  type        = string
  default     = "cos-access-logs/"
}

variable "kms_id" {
  description = "KMS CMK id for SSE-KMS (CIS 4.7). Required when 4.7 is selected."
  type        = string
  default     = null
}

variable "versioning_enable" {
  description = "Enable object versioning. Not a CIS control, but it is what makes 4.x recoverable."
  type        = bool
  default     = true
}

variable "extra_policy_statements" {
  description = <<-EOT
    Statements appended to the generated policy, e.g. the ALLOW rules your
    workload actually needs. The generated DENY statements are evaluated first
    by COS, so these cannot re-open what CIS closed.
  EOT
  type        = list(any)
  default     = []
}

variable "policy_override" {
  description = "Raw JSON policy. When set, the generated policy is ignored entirely."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags applied when manage_bucket is true."
  type        = map(string)
  default     = {}
}

variable "force_clean" {
  description = "Allow `cis destroy` to empty the bucket before deleting it."
  type        = bool
  default     = false
}
