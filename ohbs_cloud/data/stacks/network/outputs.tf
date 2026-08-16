output "cis_applied" {
  description = "CIS ids this stack enforced in the current run."
  value       = local.active
}

output "cis_implemented" {
  description = "CIS ids this stack is capable of enforcing."
  value       = local.implemented
}

output "flow_log_ids" {
  description = "Target key -> created flow log id (CIS 2.4 / 3.2)."
  value       = { for k, v in tencentcloud_vpc_flow_log.this : k => v.id }
}

output "security_group_findings" {
  description = <<-EOT
    Per security group, the rules that violate a CIS control. `enforced` lists
    the controls that actually caused a drop in this run; anything in
    `violates` but not in `enforced` is exposure you filtered out.
  EOT
  value       = { for k, m in module.security_group : k => m.findings }
}

output "security_group_dropped_rules" {
  description = "Per security group, the ingress rules removed by this run."
  value       = { for k, m in module.security_group : k => m.dropped_ingress if length(m.dropped_ingress) > 0 }
}

output "clb_edge_security_group_id" {
  description = "Security group created for public CLB traffic (CIS 3.7)."
  value       = local.clb_wanted ? tencentcloud_security_group.clb_edge[0].id : null
}
