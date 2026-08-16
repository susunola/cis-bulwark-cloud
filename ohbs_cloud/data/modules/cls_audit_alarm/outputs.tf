output "alarm_ids" {
  description = "CIS id -> created CLS alarm id."
  value       = { for id, a in tencentcloud_cls_alarm.this : id => a.id }
}

output "notice_id" {
  description = "Notice channel created by this module, or null when an existing one was reused."
  value       = local.create_notice ? tencentcloud_cls_alarm_notice.this[0].id : null
}

output "enforced_controls" {
  description = "CIS ids that got an alarm in this run."
  value       = sort(keys(local.selected))
}

output "skipped_controls" {
  description = "Alarms defined in `alarms` but filtered out of this run."
  value       = sort(setsubtract(keys(var.alarms), keys(local.selected)))
}
