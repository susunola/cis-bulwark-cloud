output "cis_applied" {
  description = "CIS ids this stack enforced in the current run."
  value       = local.active
}

output "cis_implemented" {
  description = "CIS ids this stack is capable of enforcing."
  value       = local.implemented
}

output "unreachable_controls" {
  description = <<-EOT
    Controls that were selected but had no target configured, so nothing was
    enforced for them. The check block turns this into a warning on every plan.
  EOT
  value       = local.unreachable
}

output "cls_audit_logset_id" {
  description = "CLS logset carrying the audit stream (created or reused)."
  value       = local.logset_id
}

output "cls_audit_topic_id" {
  description = <<-EOT
    CLS topic carrying the audit stream. Feed this into the network stack's
    flow_log_cls_topic_id so flow logs land in the same place.
  EOT
  value       = local.topic_id
}

output "cls_retention_days" {
  description = "Retention actually applied to the audit topic (CIS 2.20), null when the topic is not ours."
  value       = local.create_topic && local.on["2.20"] ? var.cls_retention_days : null
}

output "audit_track_id" {
  description = "CloudAudit track created for CIS 2.1."
  value       = length(tencentcloud_audit_track.this) > 0 ? tencentcloud_audit_track.this[0].id : null
}

output "alarm_ids" {
  description = "CIS id -> CLS alarm id for 2.9 - 2.19."
  value       = length(module.alarms) > 0 ? module.alarms[0].alarm_ids : {}
}

output "alarm_notice_id" {
  description = "Notice channel created for the CIS alarms, null when an existing one was reused."
  value       = length(module.alarms) > 0 ? module.alarms[0].notice_id : null
}
