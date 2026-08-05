output "cis_applied" {
  description = "CIS ids this stack enforced in the current run."
  value       = local.active
}

output "cis_implemented" {
  description = "CIS ids this stack is capable of enforcing."
  value       = local.implemented
}

output "unreachable_controls" {
  description = <<-EOT
    Controls that were selected but could not be enforced, either because no
    bucket was configured or because the bucket is policy-only. The check block
    turns this into a warning on every plan.
  EOT
  value       = local.unreachable
}

output "enforced_by_bucket" {
  description = "Bucket name -> CIS ids actually enforced on it."
  value       = { for name, m in module.bucket : name => m.enforced_controls }
}

output "unreachable_by_bucket" {
  description = "Bucket name -> CIS ids that bucket could not carry."
  value       = { for name, m in module.bucket : name => m.unreachable_controls if length(m.unreachable_controls) > 0 }
}

output "encryption_by_bucket" {
  description = "Bucket name -> server side encryption applied (KMS, AES256 or null for policy-only buckets)."
  value       = { for name, m in module.bucket : name => m.encryption_algorithm }
}

output "policy_only_buckets" {
  description = "Buckets this stack does not own. Import them to unlock 4.3 / 4.6 / 4.7."
  value       = local.policy_only
}
