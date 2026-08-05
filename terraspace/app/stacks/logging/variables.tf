variable "enabled_controls" {
  description = "CIS ids this run may enforce, injected from Cis.controls_for_stack(\"logging\")."
  type        = list(string)
  default     = []
}

variable "region" {
  description = "Region for CLS resources and for the CloudAudit COS policy ARN."
  type        = string
  default     = "ap-guangzhou"
}

variable "app_id" {
  description = "Tencent Cloud APPID. Required when CIS 2.2 is selected (used to build the COS policy ARN)."
  type        = string
  default     = null
}

# --- 2.3 / 2.20  Cloud Log Service --------------------------------------

variable "cls_logset_id" {
  description = "Reuse an existing CLS logset instead of creating one. Leave null to let this stack create it."
  type        = string
  default     = null
}

variable "cls_topic_id" {
  description = <<-EOT
    Reuse an existing CLS topic for the audit stream. Leave null to create one.

    Reusing a topic makes CIS 2.20 unreachable from here - the retention period
    lives on the topic resource, and the stack will not import a topic it
    does not own. The stack reports that in `unreachable_controls`.
  EOT
  type        = string
  default     = null
}

variable "cls_logset_name" {
  description = "Name of the logset created for CIS 2.3."
  type        = string
  default     = "cis-benchmark-audit"
}

variable "cls_topic_name" {
  description = "Name of the topic created for CIS 2.3."
  type        = string
  default     = "cis-benchmark-cloudaudit"
}

variable "cls_retention_days" {
  description = "CIS 2.20 - Logstore retention in days. Must be 365 or greater, or -1 for permanent."
  type        = number
  default     = 365

  validation {
    condition     = var.cls_retention_days == -1 || var.cls_retention_days >= 365
    error_message = "CIS 2.20 requires 365 days or more (use -1 for permanent retention)."
  }
}

variable "cls_partition_count" {
  description = "Partitions for the audit topic."
  type        = number
  default     = 1
}

variable "cls_auto_split" {
  description = "Let CLS split the topic as volume grows."
  type        = bool
  default     = true
}

variable "cls_max_split_partitions" {
  description = "Upper bound for automatic splitting."
  type        = number
  default     = 10
}

# --- 2.1  CloudAudit track ------------------------------------------------

variable "audit_track_name" {
  description = "Name of the CloudAudit track created for CIS 2.1."
  type        = string
  default     = "cis-benchmark-track"
}

variable "audit_track_storage" {
  description = <<-EOT
    Where the CloudAudit track delivers records.

    storage_type: "cos" or "cls"
    storage_name: bucket name (cos) or topic id (cls)
    storage_prefix: key prefix (cos) - use "cis" or similar
    storage_region: region of the destination
  EOT
  type = object({
    storage_type   = string
    storage_name   = string
    storage_prefix = string
    storage_region = string
    compress       = optional(number, 2)
  })
  default = null

  validation {
    condition     = var.audit_track_storage == null || contains(["cos", "cls"], try(var.audit_track_storage.storage_type, ""))
    error_message = "audit_track_storage.storage_type must be \"cos\" or \"cls\"."
  }
}

variable "audit_track_action_type" {
  description = "Operations recorded by the track. CIS 2.1 wants everything."
  type        = string
  default     = "*"
}

variable "audit_track_resource_type" {
  description = "Products recorded by the track. CIS 2.1 wants everything."
  type        = string
  default     = "*"
}

variable "audit_track_event_names" {
  description = "Event names recorded by the track. CIS 2.1 wants everything."
  type        = list(string)
  default     = ["*"]
}

variable "audit_track_for_all_members" {
  description = "1 to record every member of the organisation, 0 for this account only."
  type        = number
  default     = 0
}

# --- 2.2  the COS bucket behind CloudAudit --------------------------------

variable "cloudaudit_cos_bucket" {
  description = <<-EOT
    CIS 2.2 - bucket holding CloudAudit logs, including the APPID suffix.
    A deny-anonymous bucket policy is attached to it. The bucket itself is not
    imported, so its ACL and encryption settings are left alone; use the
    storage stack for those once the bucket is under Terraform management.
  EOT
  type        = string
  default     = null
}

# --- 2.5  EdgeOne real time log delivery ----------------------------------

variable "edgeone_log_delivery" {
  description = <<-EOT
    CIS 2.5 - EdgeOne real time log delivery to CLS.

    zone_id     : EdgeOne zone
    entity_list : sites / L4 proxy ids the task covers
    log_type    : "domain" | "application" | "web-rateLimiting" | "web-attack" | "web-rule" | "web-bot"
    task_type   : "cls" for delivery into Cloud Log Service
    area        : "mainland" | "overseas" | "global"
  EOT
  type = object({
    zone_id     = string
    task_name   = string
    entity_list = list(string)
    log_type    = optional(string, "domain")
    task_type   = optional(string, "cls")
    area        = optional(string, "global")
    sample      = optional(number, 100)
    fields = optional(list(string), [
      "RequestID", "ClientIP", "RequestHost", "RequestMethod", "RequestUrl",
      "RequestUA", "RequestTime", "EdgeResponseStatusCode", "EdgeInternalTime",
    ])
    cls_logset_id     = optional(string)
    cls_topic_id      = optional(string)
    cls_logset_region = optional(string)
  })
  default = null
}

# --- 2.9 - 2.19  log monitoring and alerts --------------------------------

variable "alarm_notice_ids" {
  description = "Existing CLS notice ids for the CIS alarms. Set this or alarm_notice_receivers."
  type        = list(string)
  default     = []
}

variable "alarm_notice_receivers" {
  description = "Receivers for a notice channel created by this stack."
  type = list(object({
    receiver_type     = string
    receiver_ids      = list(number)
    receiver_channels = list(string)
    start_time        = optional(string, "00:00:00")
    end_time          = optional(string, "23:59:59")
  }))
  default = []
}

variable "alarm_overrides" {
  description = <<-EOT
    Per-control overrides for the built-in alarm queries, merged over the
    defaults in main.tf.

    The default queries assume CloudAudit's standard CLS field mapping
    (eventName, eventSource, userIdentity.type). Verify them against your own
    topic once - field names differ if you ship through a custom pipeline.

      alarm_overrides = {
        "2.16" = { name = "root-usage", query = "principalId:\"root\"" }
      }
  EOT
  type = map(object({
    name  = string
    query = string
  }))
  default = {}
}

variable "alarm_period_minutes" {
  description = "Minutes between repeat notifications while an alarm is firing."
  type        = number
  default     = 15
}

variable "alarm_monitor_period_minutes" {
  description = "How often CLS evaluates the alarm queries."
  type        = number
  default     = 15
}

variable "alarm_lookback_minutes" {
  description = "Size of the alarm search window in minutes. Should be >= monitor_period_minutes."
  type        = number
  default     = 15
}

variable "alarm_level" {
  description = "0 warning, 1 reminder, 2 urgent."
  type        = number
  default     = 1
}

variable "tags" {
  description = "Tags applied to resources created by this stack."
  type        = map(string)
  default     = { "managed-by" = "cis" }
}
