variable "enabled_controls" {
  description = "CIS ids this run may enforce (injected by bin/cis)."
  type        = list(string)
  default     = []
}

# ---- 8.1.13 security contact -------------------------------------------------

variable "security_contact_name" {
  description = "CIS 8.1.13 - name of the Microsoft Defender security contact."
  type        = string
  default     = "cis-security-contact"
}

variable "security_contact_email" {
  description = "CIS 8.1.13 - email address that receives Defender alerts."
  type        = string
}

variable "security_contact_phone" {
  description = "CIS 8.1.13 - phone number on the security contact."
  type        = string
  default     = ""
}
