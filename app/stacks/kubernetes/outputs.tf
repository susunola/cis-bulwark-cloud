output "cis_applied" {
  description = "CIS ids this stack enforced in the current run."
  value       = local.active
}

output "cis_implemented" {
  description = "CIS ids this stack is capable of enforcing."
  value       = local.implemented
}

output "unreachable_controls" {
  description = "Controls selected but not enforceable with the current inputs."
  value       = local.unreachable
}

output "clusters" {
  description = "Clusters this stack acted on."
  value       = sort(keys(var.clusters))
}

output "monitored_clusters" {
  description = "CIS 6.2 - cluster id -> managed Prometheus instance it now reports into."
  value       = { for id, _ in local.monitor_targets : id => local.tmp_of[id] }
}

output "network_policy_addons" {
  description = "CIS 6.7 - cluster id -> add-on phase reported by TKE."
  value       = { for id, a in tencentcloud_kubernetes_addon.network_policy : id => a.phase }
}

output "private_api_endpoints" {
  description = "CIS 6.9 - cluster id -> private API server address after the public one was closed."
  value       = { for id, e in tencentcloud_kubernetes_cluster_endpoint.this : id => e.pgw_endpoint }
}

output "public_api_disabled" {
  description = "Clusters whose public API server endpoint this run turned off."
  value       = sort(keys(tencentcloud_kubernetes_cluster_endpoint.this))
}
