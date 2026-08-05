########################################################################
# cls_audit_alarm
#
# CIS 2.9 - 2.19: "ensure log monitoring and alerts are set up for <X>".
#
# All eleven recommendations are the same shape - watch the CloudAudit stream
# in CLS for a family of event names and notify - so they are one resource with
# eleven queries rather than eleven near-identical modules.
#
# Note the asymmetry, and it is deliberate: the provider ships
# tencentcloud_cls_alarm but no matching data source, so `cis apply` can create
# these alarms while `cis scan` cannot verify them. controls.yml records that
# as remediate=terraform / detect=none.
########################################################################

locals {
  selected = {
    for id, a in var.alarms : id => a
    if contains(var.enabled_controls, id)
  }

  create_notice = length(var.alarm_notice_ids) == 0 && length(var.notice_receivers) > 0

  notice_ids = local.create_notice ? [tencentcloud_cls_alarm_notice.this[0].id] : var.alarm_notice_ids
}

resource "tencentcloud_cls_alarm_notice" "this" {
  count = local.create_notice ? 1 : 0

  name = var.notice_name
  type = "All"
  tags = var.tags

  dynamic "notice_receivers" {
    for_each = var.notice_receivers
    content {
      receiver_type     = notice_receivers.value.receiver_type
      receiver_ids      = notice_receivers.value.receiver_ids
      receiver_channels = notice_receivers.value.receiver_channels
      start_time        = notice_receivers.value.start_time
      end_time          = notice_receivers.value.end_time
    }
  }
}

resource "tencentcloud_cls_alarm" "this" {
  for_each = local.selected

  name             = "${var.name_prefix}-${replace(each.key, ".", "-")}-${each.value.name}"
  alarm_period     = var.alarm_period
  trigger_count    = var.trigger_count
  condition        = var.condition
  alarm_level      = var.alarm_level
  status           = var.status
  alarm_notice_ids = local.notice_ids

  message_template = join("\n", [
    "CIS Tencent Cloud Foundation Benchmark v1.0.0 - control ${each.key}",
    each.value.name,
    "{{.QueryLog}}",
  ])

  tags = merge(var.tags, { "cis-control" = each.key })

  alarm_targets {
    logset_id         = var.logset_id
    topic_id          = var.topic_id
    query             = each.value.query
    number            = 1
    start_time_offset = -1 * var.lookback_minutes
    end_time_offset   = 0
    syntax_rule       = 1
  }

  monitor_time {
    type = "Period"
    time = var.monitor_period_minutes
  }

  lifecycle {
    precondition {
      condition     = length(local.notice_ids) > 0
      error_message = "CIS ${each.key} needs somewhere to send the alert. Set alarm_notice_ids or notice_receivers."
    }
  }
}
