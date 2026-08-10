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

# ---- 2.13 DNS logging ----------------------------------------------------------

variable "dns_logging_networks" {
  description = "CIS 2.13 - names of VPC networks that must have DNS logging enabled."
  type        = list(string)
  default     = []
}

variable "dns_policy_name" {
  description = "CIS 2.13 - name of the DNS policy created per network."
  type        = string
  default     = "cis-dns-logging"
}
