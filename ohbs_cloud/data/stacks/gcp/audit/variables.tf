variable "enabled_controls" {
  description = "Control ids this run should assess (injected by bin/cis)."
  type        = list(string)
  default     = []
}

variable "region" {
  description = "Region reported in the account header (the provider reads its own from the environment)."
  type        = string
  default     = "global"
}

# ---- operator-supplied inventory -------------------------------------------

variable "compute_instances" {
  description = <<-EOT
    CIS 4.x - Compute instances to check. There is no instance list data
    source, so each instance must be listed by name + zone.
  EOT
  type = list(object({
    name = string
    zone = string
  }))
  default = []
}

variable "log_export_buckets" {
  description = "CIS 2.4 - storage buckets used for log exports, to check for bucket-lock retention."
  type        = list(string)
  default     = []
}
