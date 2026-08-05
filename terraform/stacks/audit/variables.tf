variable "enabled_controls" {
  description = <<-EOT
    Control ids this run should assess. Rendered by tfvars/base.tfvars from
    Cis.controls_for_audit, i.e. the intersection of the operator's filters
    and the controls the provider can actually observe.
  EOT
  type        = list(string)
  default     = []
}

variable "region" {
  description = "Region to query for region-scoped services (CWPP)."
  type        = string
  default     = "ap-guangzhou"
}

# ---- thresholds ------------------------------------------------------------

variable "cls_min_retention_days" {
  description = "CIS 2.20 - minimum Logstore retention in days."
  type        = number
  default     = 365
}

variable "max_port_range_span" {
  description = <<-EOT
    CIS 3.4 - an internet-facing ingress rule spanning more ports than this is
    treated as not fine grained.
  EOT
  type        = number
  default     = 100
}

variable "admin_policy_names" {
  description = <<-EOT
    CIS 1.15 - policy names understood to grant *:*. The provider does not
    expose policy documents, so this check is name based; extend the list with
    any in-house policy you know to be full admin.
  EOT
  type        = list(string)
  default     = ["AdministratorAccess", "QcloudResourceFullAccess"]
}

variable "public_acls" {
  description = "COS ACL values treated as public."
  type        = list(string)
  default     = ["public-read", "public-read-write"]
}

variable "peering_next_types" {
  description = <<-EOT
    CIS 3.3 - route next-hop types that leave the VPC. A 0.0.0.0/0 route over
    one of these is the "not least access" condition.
  EOT
  type        = list(string)
  default     = ["PEERCONNECTION", "CCN", "DIRECTCONNECT", "VPN"]
}

variable "world_cidrs" {
  description = "CIDRs treated as 'the internet' when reading security group rules."
  type        = list(string)
  default     = ["0.0.0.0/0", "0.0.0.0", "::/0", "0::0/0", "::0/0"]
}
