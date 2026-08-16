variable "enabled_controls" {
  description = <<-EOT
    Control ids this run should assess. Rendered by bin/cis from the operator's
    filters and the controls the provider can actually observe.
  EOT
  type        = list(string)
  default     = []
}

variable "region" {
  description = "Region reported in the account header. The provider reads its own region from the environment."
  type        = string
  default     = "us-east-1"
}

# ---- thresholds ------------------------------------------------------------

variable "remote_admin_ports" {
  description = <<-EOT
    CIS 6.3 / 6.4 - ports treated as remote server administration. A rule that
    allows any of these from 0.0.0.0/0 (or ::/0) is a violation.
  EOT
  type        = list(number)
  default     = [22, 3389]
}

variable "world_cidrs" {
  description = "CIDRs treated as 'the internet' when reading security group rules."
  type        = list(string)
  default     = ["0.0.0.0/0", "::/0"]
}
