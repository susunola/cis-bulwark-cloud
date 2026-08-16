output "security_group_id" {
  description = "The security group this baseline was computed for."
  value       = var.security_group_id
}

output "applied_ingress" {
  description = "Ingress rules that survived the enabled CIS controls."
  value       = local.ingress_kept
}

output "dropped_ingress" {
  description = "Ingress rules removed because a selected control condemned them."
  value       = local.ingress_dropped
}

output "findings" {
  description = <<-EOT
    Every rule that violates at least one CIS control, whether or not that
    control was part of this run. `enforced` is the subset that actually caused
    the rule to be dropped - the difference is your remaining exposure.
  EOT
  value       = local.ingress_report
}

output "enforced" {
  description = "True when the filtered rule set was written back to the cloud."
  value       = var.enforce
}
