variable "enabled_controls" {
  description = "CIS ids this run may enforce, injected from Cis.controls_for_stack(\"database\")."
  type        = list(string)
  default     = []
}

variable "region" {
  description = "Region the instances live in. Used as the default KMS key region for TDE."
  type        = string
  default     = "ap-guangzhou"
}

variable "mysql_instances" {
  description = <<-EOT
    TencentDB for MySQL instance id -> per-instance overrides. Every field is
    optional; anything left null falls back to the stack-level default.

      cdb-xxxxxxxx = {}                                  # all defaults
      cdb-yyyyyyyy = { audit_log_expire_day = 365 }      # keep audit longer

    List your instances with:
      tccli cdb DescribeDBInstances --filter InstanceIds
  EOT
  type = map(object({
    # 5.1
    ro_group_id = optional(string)

    # 5.2
    security_group_ids = optional(list(string), [])

    # 5.3 / 5.4
    audit_all            = optional(bool)
    audit_log_expire_day = optional(number)
    high_log_expire_day  = optional(number)

    # 5.5 / 5.6
    kms_key_id     = optional(string)
    kms_key_region = optional(string)
  }))
  default = {}

  validation {
    condition     = alltrue([for id, _ in var.mysql_instances : can(regex("^cdb-[0-9a-z]+$", id))])
    error_message = "keys of mysql_instances must be TencentDB instance ids like 'cdb-abcd1234'."
  }

  validation {
    condition = alltrue([
      for _, v in var.mysql_instances :
      v.audit_log_expire_day == null || contains([7, 30, 90, 180, 365, 1095, 1825], v.audit_log_expire_day)
    ])
    error_message = "mysql_instances[*].audit_log_expire_day must be one of 7, 30, 90, 180, 365, 1095, 1825."
  }
}

# --- 5.2  private access only ----------------------------------------------

variable "default_security_group_ids" {
  description = <<-EOT
    Security groups attached to every instance that does not name its own.
    Combined with db_security_group.create, which appends a generated one.
  EOT
  type        = list(string)
  default     = []
}

variable "db_security_group" {
  description = <<-EOT
    CIS 5.2. Optionally create one restrictive security group and attach it to
    every instance. `allowed_cidrs` are the only sources permitted to reach the
    MySQL port - they are still run through the section 3 baseline, so putting
    0.0.0.0/0 here gets it dropped rather than applied.

    Leave create = false if you already manage the database security groups
    elsewhere and just want them attached via default_security_group_ids.
  EOT
  type = object({
    create        = optional(bool, false)
    name          = optional(string, "cis-mysql-private")
    project_id    = optional(number)
    allowed_cidrs = optional(list(string), [])
    port          = optional(number, 3306)
    extra_ingress = optional(list(string), [])
    egress        = optional(list(string), [])
  })
  default = {}

  validation {
    condition     = !var.db_security_group.create || length(var.db_security_group.allowed_cidrs) > 0
    error_message = "db_security_group.create is true but allowed_cidrs is empty; that would lock every client out."
  }

  validation {
    condition     = alltrue([for cidr in var.db_security_group.allowed_cidrs : can(cidrhost(cidr, 0))])
    error_message = "db_security_group.allowed_cidrs must contain valid IPv4 CIDR blocks."
  }

  validation {
    condition     = var.db_security_group.port >= 1 && var.db_security_group.port <= 65535
    error_message = "db_security_group.port must be between 1 and 65535."
  }
}

# --- 5.3 / 5.4  audit service ----------------------------------------------

variable "wan_endpoint_reviewed" {
  description = <<-EOT
    CIS 5.2 has a part Terraform cannot reach: the public network endpoint is
    an attribute of tencentcloud_mysql_instance, and importing a live database
    to flip it is not worth the blast radius. Every plan warns about this until
    you confirm the endpoints were reviewed:

      tccli cdb DescribeDBInstances --filter InstanceIds   # look at WanStatus
      tccli cdb CloseWanService --InstanceId cdb-xxxxxxxx

    Set this to true once that is done.
  EOT
  type        = bool
  default     = false
}

variable "audit_all" {
  description = "CIS 5.3 - audit every statement rather than a rule template subset."
  type        = bool
  default     = true
}

variable "audit_log_expire_day" {
  description = <<-EOT
    CIS 5.4 - audit log retention in days. The benchmark asks for more than six
    months. TencentDB accepts 7, 30, 90, 180, 365, 1095 and 1825.
  EOT
  type        = number
  default     = 365

  validation {
    condition     = contains([7, 30, 90, 180, 365, 1095, 1825], var.audit_log_expire_day)
    error_message = "audit_log_expire_day must be one of 7, 30, 90, 180, 365, 1095, 1825."
  }
}

variable "audit_min_retention_days" {
  description = "Threshold used to judge CIS 5.4. 'Greater than 6 months' is read as > 180 days."
  type        = number
  default     = 180
}

variable "audit_high_log_expire_day" {
  description = "Retention for high-frequency audit storage. Null leaves the account default."
  type        = number
  default     = null
}

# --- 5.5 / 5.6  transparent data encryption --------------------------------

variable "kms_key_id" {
  description = <<-EOT
    Customer managed CMK used as the TDE protector (CIS 5.6). Leave null to
    enable TDE with the Tencent managed key, which satisfies 5.5 but not 5.6.
  EOT
  type        = string
  default     = null
}

variable "kms_key_region" {
  description = "Region of the CMK. Defaults to var.region."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags applied to resources created by this stack."
  type        = map(string)
  default     = { "managed-by" = "cis" }
}
