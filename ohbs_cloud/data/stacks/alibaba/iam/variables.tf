variable "enabled_controls" {
  description = "CIS ids this run may enforce (injected by bin/cis)."
  type        = list(string)
  default     = []
}

variable "minimum_password_length" {
  description = "CIS 1.11 - minimum password length."
  type        = number
  default     = 14
}

variable "require_lowercase_characters" {
  description = "CIS 1.8 - require lowercase characters."
  type        = bool
  default     = true
}

variable "require_uppercase_characters" {
  description = "CIS 1.7 - require uppercase characters."
  type        = bool
  default     = true
}

variable "require_numbers" {
  description = "CIS 1.10 - require numbers."
  type        = bool
  default     = true
}

variable "require_symbols" {
  description = "CIS 1.9 - require symbols."
  type        = bool
  default     = true
}

variable "max_password_age" {
  description = "CIS 1.13 - passwords expire after this many days (>= 365 per CIS)."
  type        = number
  default     = 365
}

variable "password_reuse_prevention" {
  description = "CIS 1.12 - number of previous passwords that cannot be reused."
  type        = number
  default     = 5
}

variable "max_login_attempts" {
  description = "CIS 1.14 - logon blocked after this many failed attempts within an hour."
  type        = number
  default     = 5
}
