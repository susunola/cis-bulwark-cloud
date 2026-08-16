output "cis_applied" {
  description = "CIS ids this stack enforced in the current run."
  value       = local.active
}

output "cis_implemented" {
  description = "CIS ids this stack is capable of enforcing."
  value       = local.implemented
}

output "password_policy_managed" {
  description = "Whether the RAM password policy is under this stack's management."
  value       = length(alicloud_ram_account_password_policy.cis) > 0
}
