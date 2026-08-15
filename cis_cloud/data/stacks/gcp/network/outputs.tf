output "cis_applied" {
  description = "CIS ids this stack enforced in the current run."
  value       = local.active
}

output "cis_implemented" {
  description = "CIS ids this stack is capable of enforcing."
  value       = local.implemented
}

output "dns_policies_created" {
  description = "Networks with a DNS logging policy."
  value       = sort(keys(google_dns_policy.cis))
}
