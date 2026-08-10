output "cis_applied" {
  description = "CIS ids this stack enforced in the current run."
  value       = local.active
}

output "cis_implemented" {
  description = "CIS ids this stack is capable of enforcing."
  value       = local.implemented
}

output "contact_created" {
  description = "Whether the security contact was created."
  value       = length(azurerm_security_center_contact.cis) > 0
}
