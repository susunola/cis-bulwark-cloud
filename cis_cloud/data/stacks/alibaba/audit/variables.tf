variable "enabled_controls" {
  description = "Control ids this run should assess (injected by bin/cis)."
  type        = list(string)
  default     = []
}

variable "region" {
  description = "Region reported in the account header (the provider reads its own from the environment)."
  type        = string
  default     = "cn-hangzhou"
}

# Thresholds for controls that need a time judgement.
variable "unused_days" {
  description = "CIS 1.5 - RAM users idle for this many days are considered unused."
  type        = number
  default     = 90
}
