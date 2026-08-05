variable "enabled_controls" {
  description = <<-EOT
    CIS ids this run may enforce. Injected by tfvars/base.tfvars from
    Cis.controls_for_stack("iam"), which is the CLI filter result intersected
    with the controls Terraform can actually remediate.
  EOT
  type        = list(string)
  default     = []
}

variable "cam_console_user_uins" {
  description = <<-EOT
    CIS 1.4 - UINs of CAM sub-users that hold a console password. Every UIN
    listed here gets MFA required at login and at sensitive operations.

    Find them with:
      tccli cam ListUsers --filter-console 1
    or read cis scan output for 1.15 / 1.16, which already enumerates users.

    Left empty the control is a no-op: these stacks do not discover users and
    silently mutate their login flow.
  EOT
  type        = list(number)
  default     = []
}

variable "mfa_login_flag" {
  description = "CIS 1.4 - MFA factors accepted at console login. 1 = required, 0 = not required."
  type = object({
    phone  = optional(number, 0)
    stoken = optional(number, 1)
    wechat = optional(number, 0)
  })
  default = {}

  validation {
    condition     = (var.mfa_login_flag.phone + var.mfa_login_flag.stoken + var.mfa_login_flag.wechat) > 0
    error_message = "mfa_login_flag must enable at least one factor, otherwise CIS 1.4 is not satisfied."
  }
}

variable "mfa_action_flag" {
  description = "CIS 1.4 - MFA factors accepted for sensitive operations."
  type = object({
    phone  = optional(number, 0)
    stoken = optional(number, 1)
    wechat = optional(number, 0)
  })
  default = {}

  validation {
    condition     = (var.mfa_action_flag.phone + var.mfa_action_flag.stoken + var.mfa_action_flag.wechat) > 0
    error_message = "mfa_action_flag must enable at least one factor."
  }
}
