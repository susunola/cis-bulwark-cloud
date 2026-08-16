variable "enabled_controls" {
  description = "CIS ids this run may enforce (injected by bin/cis)."
  type        = list(string)
  default     = []
}

# ---- 2.1 ActionTrail ------------------------------------------------------------

variable "trail_name" {
  description = "CIS 2.1 - name of the ActionTrail trail."
  type        = string
  default     = "cis-action-trail"
}

variable "oss_bucket_name" {
  description = "CIS 2.1 - OSS bucket that stores the trail logs (must already exist)."
  type        = string
}
