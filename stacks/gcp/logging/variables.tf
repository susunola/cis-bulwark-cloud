variable "enabled_controls" {
  description = "CIS ids this run may enforce (injected by bin/cis)."
  type        = list(string)
  default     = []
}

variable "project_id" {
  description = "GCP project id (defaults to the provider's configured project)."
  type        = string
  default     = ""
}

# ---- 2.1 audit config ---------------------------------------------------------

variable "audit_service" {
  description = "CIS 2.1 - the service to attach the audit config to (e.g. allServices)."
  type        = string
  default     = "allServices"
}

# ---- 2.3 log sink ---------------------------------------------------------------

variable "sink_name" {
  description = "CIS 2.3 - name of the project log sink."
  type        = string
  default     = "cis-audit-sink"
}

variable "sink_destination" {
  description = "CIS 2.3 - destination for all log entries, e.g. storage.googleapis.com/<bucket> or bigquery.googleapis.com/projects/<p>/datasets/<d>."
  type        = string
}
