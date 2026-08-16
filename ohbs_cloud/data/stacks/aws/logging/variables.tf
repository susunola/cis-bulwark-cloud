variable "enabled_controls" {
  description = "CIS ids this run may enforce (injected by bin/cis)."
  type        = list(string)
  default     = []
}

# ---- 4.2 CloudTrail -----------------------------------------------------------

variable "cloudtrail_name" {
  description = <<-EOT
    CIS 4.2 - name of the CloudTrail trail to harden. Must already exist; this
    resource only takes ownership and turns log file validation on.
  EOT
  type        = string
}

variable "cloudtrail_s3_bucket" {
  description = <<-EOT
    CIS 4.2 - S3 bucket the trail delivers to. Must already exist and match the
    trail's current destination, or Terraform will try to change it.
  EOT
  type        = string
}

variable "is_multi_region_trail" {
  description = "CIS 4.2 - whether the trail applies to all regions."
  type        = bool
  default     = true
}

variable "include_global_service_events" {
  description = "CIS 4.2 - include global service (IAM, STS, CloudFront) events."
  type        = bool
  default     = true
}

variable "cloudtrail_kms_key_id" {
  description = "CIS 4.5 - KMS key id (or alias) encrypting the trail logs; leave unset to keep the current setting."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags applied to resources this stack creates."
  type        = map(string)
  default     = {}
}
