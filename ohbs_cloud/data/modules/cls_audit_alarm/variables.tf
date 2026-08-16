variable "logset_id" {
  description = "CLS logset holding the CloudAudit shipment (see CIS 2.3)."
  type        = string
}

variable "topic_id" {
  description = "CLS topic holding the CloudAudit shipment."
  type        = string
}

variable "enabled_controls" {
  description = "CIS ids selected for this run. Only alarms whose id appears here are created."
  type        = list(string)
  default     = []
}

variable "alarms" {
  description = <<-EOT
    CIS id -> alarm definition. `query` is a CLS search statement evaluated over
    the CloudAudit topic; the alarm fires when it returns any row.

    Overriding a single entry is fine - merge your version over the default map
    in the caller rather than redefining all eleven.
  EOT
  type = map(object({
    name  = string
    query = string
  }))
}

variable "name_prefix" {
  description = "Prepended to every alarm name so CIS-managed alarms are greppable in the console."
  type        = string
  default     = "cis"
}

variable "alarm_notice_ids" {
  description = <<-EOT
    Existing CLS notice ids to attach. Leave empty and set `notice_receivers`
    to have this module create a notice channel instead.
  EOT
  type        = list(string)
  default     = []
}

variable "notice_receivers" {
  description = <<-EOT
    Receivers for a notice channel created by this module. Ignored when
    `alarm_notice_ids` is non-empty.

    receiver_type: "Uin" or "Group"; receiver_ids: CAM uins or group ids;
    receiver_channels: any of "Email", "Sms", "WeChat", "Phone".
  EOT
  type = list(object({
    receiver_type     = string
    receiver_ids      = list(number)
    receiver_channels = list(string)
    start_time        = optional(string, "00:00:00")
    end_time          = optional(string, "23:59:59")
  }))
  default = []

  validation {
    condition = alltrue([
      for r in var.notice_receivers :
      contains(["Uin", "Group"], r.receiver_type) &&
      length(r.receiver_ids) > 0 &&
      alltrue([for c in r.receiver_channels : contains(["Email", "Sms", "WeChat", "Phone"], c)]) &&
      can(regex("^([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]$", r.start_time)) &&
      can(regex("^([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]$", r.end_time))
    ])
    error_message = "notice_receivers entries must use receiver_type 'Uin' or 'Group', non-empty receiver_ids, receiver_channels from Email/Sms/WeChat/Phone, and start/end times in HH:MM:SS."
  }
}

variable "notice_name" {
  description = "Name of the notice channel created when notice_receivers is used."
  type        = string
  default     = "cis-benchmark-notice"
}

variable "alarm_period" {
  description = "Minutes between repeat notifications for a firing alarm."
  type        = number
  default     = 15

  validation {
    condition     = var.alarm_period >= 0
    error_message = "alarm_period must be zero or greater."
  }
}

variable "trigger_count" {
  description = "Consecutive evaluations that must match before the alarm fires."
  type        = number
  default     = 1

  validation {
    condition     = var.trigger_count >= 1
    error_message = "trigger_count must be at least 1."
  }
}

variable "monitor_period_minutes" {
  description = "How often CLS evaluates the query, in minutes."
  type        = number
  default     = 15
}

variable "lookback_minutes" {
  description = "Size of the search window, in minutes. Should be >= monitor_period_minutes so no event slips between evaluations."
  type        = number
  default     = 15
}

variable "alarm_level" {
  description = "0 warning, 1 reminder, 2 urgent."
  type        = number
  default     = 1

  validation {
    condition     = contains([0, 1, 2], var.alarm_level)
    error_message = "alarm_level must be 0, 1 or 2."
  }
}

variable "condition" {
  description = "Trigger expression evaluated against the query result set."
  type        = string
  default     = "$1.count > 0"
}

variable "status" {
  description = "Create the alarms in an enabled state."
  type        = bool
  default     = true
}

variable "tags" {
  description = "Tags applied to every alarm."
  type        = map(string)
  default     = {}
}
