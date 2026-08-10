variable "enabled_controls" {
  description = "CIS ids this run may enforce (injected by bin/cis)."
  type        = list(string)
  default     = []
}

# ---- 3.2.2 / 3.2.3 RDS --------------------------------------------------------

variable "db_instance_identifiers" {
  description = <<-EOT
    CIS 3.2.2 / 3.2.3 - identifiers of the RDS instances to harden. Import each
    one before apply (see main.tf) - Terraform refuses to manage an instance it
    does not own, and prevent_destroy protects the ones it does.
  EOT
  type        = list(string)
  default     = []
}

# Required to construct aws_db_instance; must match the imported instances.
variable "db_engine" {
  description = "RDS engine of the imported instances, e.g. mysql, postgres. Must match live state."
  type        = string
}

variable "db_instance_class" {
  description = "Instance class of the imported instances, e.g. db.t3.micro. Must match live state."
  type        = string
}

# Current values, used when the paired control is not selected.
variable "db_auto_minor_version_upgrade" {
  description = "Current auto-minor-version-upgrade value of the imported instances (kept when 3.2.2 is not selected)."
  type        = bool
  default     = true
}

variable "db_publicly_accessible" {
  description = "Current public-access value of the imported instances (kept when 3.2.3 is not selected)."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags applied to resources this stack manages."
  type        = map(string)
  default     = {}
}
