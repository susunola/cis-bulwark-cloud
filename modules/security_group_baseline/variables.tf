variable "security_group_id" {
  description = "Existing security group to bring under CIS control."
  type        = string

  validation {
    condition     = can(regex("^sg-[0-9a-z]+$", var.security_group_id))
    error_message = "security_group_id must look like 'sg-xxxxxxxx'."
  }
}

variable "enabled_controls" {
  description = <<-EOT
    CIS ids that survived the CLI filters. A rule is only stripped when the
    control that condemns it is in this list, so `cis apply --only 3.5` really
    does touch nothing but port 22.
  EOT
  type        = list(string)
  default     = []
}

variable "ingress" {
  description = <<-EOT
    The complete desired ingress rule set, in tencentcloud lite-rule form:
    "<ACTION>#<SOURCE>#<PORT>#<PROTOCOL>", e.g. "ACCEPT#10.0.0.0/8#22#TCP".

    PORT accepts "ALL", "80", "80,443" or "3000-4000".
    SOURCE accepts a CIDR, an ipv6 CIDR or another sg-id.

    This list is authoritative: whatever survives the CIS filters below becomes
    the security group's entire ingress rule set.
  EOT
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for r in var.ingress : length(split("#", r)) >= 4])
    error_message = "every ingress rule needs at least 4 '#'-separated fields: action#source#port#protocol."
  }

  validation {
    condition = alltrue([
      for r in var.ingress :
      length(compact(split("#", r))) == 4 &&
      contains(["ACCEPT", "DROP"], upper(element(split("#", r), 0))) &&
      can(regex("^(ALL|ANY|-1|\\d+(-\\d+)?(\\,\\d+(-\\d+)?)*)$", upper(element(split("#", r), 2)))) &&
      contains(["TCP", "UDP", "ICMP", "ALL", "ANY", "-1"], upper(element(split("#", r), 3)))
    ])
    error_message = "ingress rule must be action#source#port#protocol, e.g. ACCEPT#10.0.0.0/8#22#TCP."
  }
}

variable "egress" {
  description = <<-EOT
    The complete desired egress rule set, same syntax as `ingress`. CIS v1.0.0
    has no egress recommendation that Terraform can enforce, so this list is
    passed through untouched - it exists so the authoritative write does not
    silently erase egress rules.
  EOT
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for r in var.egress : length(split("#", r)) >= 4])
    error_message = "every egress rule needs at least 4 '#'-separated fields: action#source#port#protocol."
  }

  validation {
    condition = alltrue([
      for r in var.egress :
      length(compact(split("#", r))) == 4 &&
      contains(["ACCEPT", "DROP"], upper(element(split("#", r), 0))) &&
      can(regex("^(ALL|ANY|-1|\\d+(-\\d+)?(\\,\\d+(-\\d+)?)*)$", upper(element(split("#", r), 2)))) &&
      contains(["TCP", "UDP", "ICMP", "ALL", "ANY", "-1"], upper(element(split("#", r), 3)))
    ])
    error_message = "egress rule must be action#source#port#protocol, e.g. ACCEPT#10.0.0.0/8#22#TCP."
  }
}

variable "enforce" {
  description = "Write the filtered rule set back. Set false to compute the diff only."
  type        = bool
  default     = true
}

variable "world_cidrs" {
  description = "Source values treated as 'the internet' by 3.1 / 3.5 / 3.6."
  type        = list(string)
  default     = ["0.0.0.0/0", "0.0.0.0", "::/0", "0::0/0", "::0/0"]
}

variable "remote_access_ports" {
  description = <<-EOT
    Ports CIS 3.1 considers remote administration. Reaching any of these from a
    world CIDR is a violation.
  EOT
  type        = list(number)
  default     = [22, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 27017]
}

variable "max_port_range_span" {
  description = <<-EOT
    CIS 3.4 (fine grained rules): the largest number of ports a single ACCEPT
    rule may open. A rule opening 3000-3100 spans 101 ports.
  EOT
  type        = number
  default     = 100

  validation {
    condition     = var.max_port_range_span >= 1 && var.max_port_range_span <= 65535
    error_message = "max_port_range_span must be between 1 and 65535."
  }
}

variable "allow_empty_ingress" {
  description = <<-EOT
    Guard rail. If filtering removes every ingress rule the apply is aborted,
    because an accidental full lockout of a production security group is worse
    than a failed compliance run. Flip this to accept a deny-all posture.
  EOT
  type        = bool
  default     = false
}
