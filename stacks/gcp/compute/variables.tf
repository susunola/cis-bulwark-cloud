variable "enabled_controls" {
  description = "CIS ids this run may enforce (injected by bin/cis)."
  type        = list(string)
  default     = []
}

# ---- 4.4 oslogin ------------------------------------------------------------------

variable "project_metadata" {
  description = <<-EOT
    CIS 4.4 - the project's existing metadata map. This stack *replaces* the
    whole map with merge(project_metadata, { enable-oslogin = "TRUE" }), so
    keep it in sync with what the project already sets.
  EOT
  type        = map(string)
  default     = {}
}
