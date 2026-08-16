variable "enabled_controls" {
  description = <<-EOT
    CIS ids this run may enforce. Injected by bin/cis from
    Cis.controls_for_stack("iam"), which is the CLI filter result intersected
    with the controls Terraform can actually remediate.
  EOT
  type        = list(string)
  default     = []
}

# ---- 2.8 password policy ---------------------------------------------------

variable "minimum_password_length" {
  description = "CIS 2.8 - minimum password length required by the account policy."
  type        = number
  default     = 14
}

variable "require_lowercase_characters" {
  description = "CIS 2.8 - require at least one lowercase character."
  type        = bool
  default     = true
}

variable "require_uppercase_characters" {
  description = "CIS 2.8 - require at least one uppercase character."
  type        = bool
  default     = true
}

variable "require_numbers" {
  description = "CIS 2.8 - require at least one number."
  type        = bool
  default     = true
}

variable "require_symbols" {
  description = "CIS 2.8 - require at least one symbol."
  type        = bool
  default     = true
}

variable "max_password_age" {
  description = "CIS 2.8 - passwords expire after this many days."
  type        = number
  default     = 90
}

variable "allow_users_to_change_password" {
  description = "CIS 2.8 - allow users to change their own password."
  type        = bool
  default     = true
}

# ---- 2.9 password reuse -----------------------------------------------------

variable "password_reuse_prevention" {
  description = "CIS 2.9 - number of previous passwords that cannot be reused."
  type        = number
  default     = 24
}

# ---- 2.18 External Access Analyzer -------------------------------------------

variable "analyzer_name" {
  description = "CIS 2.18 - name of the IAM External Access Analyzer."
  type        = string
  default     = "cis-external-access-analyzer"
}

variable "tags" {
  description = "Tags applied to resources this stack creates."
  type        = map(string)
  default     = {}
}
