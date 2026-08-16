output "cis_applied" {
  description = "CIS ids this stack enforced in the current run."
  value       = local.active
}

output "cis_implemented" {
  description = "CIS ids this stack is capable of enforcing."
  value       = local.implemented
}

output "oslogin_enabled" {
  description = "Whether oslogin is now enforced at project level."
  value       = length(google_compute_project_metadata.cis) > 0
}
