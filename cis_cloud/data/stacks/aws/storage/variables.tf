variable "enabled_controls" {
  description = "CIS ids this run may enforce (injected by bin/cis)."
  type        = list(string)
  default     = []
}

# ---- 3.1.1 S3 bucket policy --------------------------------------------------

variable "buckets" {
  description = <<-EOT
    CIS 3.1.1 - S3 buckets that must reject HTTP requests. The bucket policy is
    replaced with a deny-on-insecure-transport statement - review the current
    policy before listing a bucket here.
  EOT
  type        = list(string)
  default     = []
}
