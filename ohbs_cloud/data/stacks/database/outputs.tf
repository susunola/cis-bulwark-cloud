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

output "instances" {
  description = "Instances this stack acted on."
  value       = sort(keys(var.mysql_instances))
}

output "ssl_enabled_instances" {
  description = "CIS 5.1 - instances whose connections now require SSL."
  value       = sort(keys(tencentcloud_mysql_ssl.this))
}

output "security_group_attachments" {
  description = "CIS 5.2 - instance id -> security groups attached by this run."
  value = {
    for id, sgs in local.sg_of : id => sgs if local.on["5.2"] && length(sgs) > 0
  }
}

output "db_security_group_id" {
  description = "Security group created for CIS 5.2, null when an existing one was reused."
  value       = local.create_sg ? tencentcloud_security_group.db[0].id : null
}

output "db_security_group_dropped_ingress" {
  description = <<-EOT
    Rules requested in db_security_group.allowed_cidrs that the section 3
    baseline refused to write. A non-empty list means somebody tried to expose
    MySQL more widely than CIS allows.
  EOT
  value       = local.create_sg ? module.db_security_group[0].dropped_ingress : []
}

output "audit_retention_days" {
  description = "CIS 5.4 - retention actually applied per instance."
  value       = local.audit_wanted ? local.audit_retention_of : {}
}

output "tde_protector" {
  description = <<-EOT
    CIS 5.5 / 5.6 - instance id -> TDE protector. "tencent-managed" satisfies
    5.5 only; a kms- id also satisfies 5.6.
  EOT
  value = local.tde_wanted ? {
    for id, key in local.tde_key_of :
    id => local.on["5.6"] && key != null ? key : "tencent-managed"
  } : {}
}
