output "cis_applied" {
  description = "CIS ids this stack enforced in the current run."
  value       = local.active
}

output "cis_implemented" {
  description = "CIS ids this stack is capable of enforcing."
  value       = local.implemented
}

output "watchers_created" {
  description = "Locations where a Network Watcher now exists."
  value       = sort(keys(azurerm_network_watcher.cis))
}
