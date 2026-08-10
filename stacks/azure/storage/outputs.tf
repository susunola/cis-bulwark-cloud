output "cis_applied" {
  description = "CIS ids this stack enforced in the current run."
  value       = local.active
}

output "cis_implemented" {
  description = "CIS ids this stack is capable of enforcing."
  value       = local.implemented
}

output "accounts_hardened" {
  description = "Storage accounts under this stack's management."
  value       = sort(keys(azurerm_storage_account.cis))
}
