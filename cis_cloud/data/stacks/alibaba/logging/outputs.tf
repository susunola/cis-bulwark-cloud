output "cis_applied" {
  description = "CIS ids this stack enforced in the current run."
  value       = local.active
}

output "cis_implemented" {
  description = "CIS ids this stack is capable of enforcing."
  value       = local.implemented
}

output "trail_created" {
  description = "Whether the ActionTrail trail was created."
  value       = length(alicloud_actiontrail.cis) > 0
}
