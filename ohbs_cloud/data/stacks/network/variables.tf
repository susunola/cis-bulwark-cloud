variable "enabled_controls" {
  description = "CIS ids this run may enforce, injected from Cis.controls_for_stack(\"network\")."
  type        = list(string)
  default     = []
}

variable "region" {
  description = "Region used for CLS delivery of flow logs."
  type        = string
  default     = "ap-guangzhou"
}

# --- 2.4 / 3.2  virtual network flow logs ----------------------------------

variable "flow_log_targets" {
  description = <<-EOT
    Key -> flow log target. The key becomes part of the flow log name, so keep
    it stable and short ("prod-vpc", "dmz-subnet").

    resource_type: VPC | SUBNET | NETWORKINTERFACE | CCN | NAT
    traffic_type : ACCEPT | REJECT | ALL   (CIS wants ALL)
    vpc_id       : required for SUBNET and NETWORKINTERFACE targets
  EOT
  type = map(object({
    resource_id   = string
    resource_type = optional(string, "VPC")
    traffic_type  = optional(string, "ALL")
    vpc_id        = optional(string)
    description   = optional(string)
  }))
  default = {}

  validation {
    condition = alltrue([
      for k, v in var.flow_log_targets :
      contains(["VPC", "SUBNET", "NETWORKINTERFACE", "CCN", "NAT"], v.resource_type)
    ])
    error_message = "resource_type must be VPC, SUBNET, NETWORKINTERFACE, CCN or NAT."
  }

  validation {
    condition = alltrue([
      for k, v in var.flow_log_targets :
      contains(["ACCEPT", "REJECT", "ALL"], v.traffic_type)
    ])
    error_message = "traffic_type must be ACCEPT, REJECT or ALL."
  }

  validation {
    condition = alltrue([
      for k, v in var.flow_log_targets :
      !contains(["SUBNET", "NETWORKINTERFACE"], v.resource_type) || v.vpc_id != null
    ])
    error_message = "SUBNET and NETWORKINTERFACE flow log targets need a vpc_id."
  }
}

variable "flow_log_cls_topic_id" {
  description = "CLS topic that receives flow logs. Required when flow_log_targets is non-empty."
  type        = string
  default     = null
}

variable "flow_log_name_prefix" {
  description = "Prefix for generated flow log names."
  type        = string
  default     = "cis-flowlog"
}

# --- 3.1 / 3.4 / 3.5 / 3.6  security group baseline ------------------------

variable "security_groups" {
  description = <<-EOT
    Security groups to bring under CIS control.

    `ingress` / `egress` are the COMPLETE desired rule sets in lite-rule form
    ("ACCEPT#10.0.0.0/8#22#TCP"). The stack removes any rule condemned by a
    selected control and writes back what is left, so declaring a rule here is
    a request, not a guarantee.

    Read the current rules first:
      tccli vpc DescribeSecurityGroupPolicies --SecurityGroupId sg-xxxx
  EOT
  type = map(object({
    security_group_id   = string
    ingress             = optional(list(string), [])
    egress              = optional(list(string), [])
    allow_empty_ingress = optional(bool, false)
  }))
  default = {}
}

variable "world_cidrs" {
  description = "Valid CIDRs treated as 'the internet'."
  type        = list(string)
  default     = ["0.0.0.0/0", "::/0"]

  validation {
    condition     = alltrue([for cidr in var.world_cidrs : can(cidrhost(cidr, 0))])
    error_message = "Every world_cidrs entry must be a valid CIDR."
  }
}

variable "remote_access_ports" {
  description = "CIS 3.1 - ports considered remote administration."
  type        = list(number)
  default     = [22, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 27017]
}

variable "max_port_range_span" {
  description = "CIS 3.4 - largest port window a single ACCEPT rule may open."
  type        = number
  default     = 100
}

# --- 3.7  dedicated CLB security group -------------------------------------

variable "clb_instance_ids" {
  description = "CIS 3.7 - public CLB instances to place behind a dedicated security group."
  type        = list(string)
  default     = []
}

variable "clb_security_group_name" {
  description = "Name of the security group created for public CLB traffic."
  type        = string
  default     = "cis-clb-public-edge"
}

variable "clb_ingress" {
  description = <<-EOT
    Ingress the public CLB edge is allowed to accept. These rules go through
    the same CIS filter as everything else, so 0.0.0.0/0 on 443 survives and
    0.0.0.0/0 on 22 does not.
  EOT
  type        = list(string)
  default     = ["ACCEPT#0.0.0.0/0#443#TCP", "ACCEPT#0.0.0.0/0#80#TCP"]
}

variable "clb_egress" {
  description = "Egress for the CLB edge security group. Default is no outbound rules; declare least-privilege destinations explicitly."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags applied to resources created by this stack."
  type        = map(string)
  default     = { "managed-by" = "cis" }
}
