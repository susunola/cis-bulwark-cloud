output "bucket" {
  description = "Bucket name this module operated on."
  value       = var.bucket
}

output "bucket_url" {
  description = "Endpoint of the managed bucket (null when the bucket is not managed here)."
  value       = var.manage_bucket ? tencentcloud_cos_bucket.this[0].cos_bucket_url : null
}

output "encryption_algorithm" {
  description = "Server side encryption actually applied: KMS, AES256 or null."
  value       = var.manage_bucket ? local.encryption_algorithm : null
}

output "policy" {
  description = "Bucket policy document written to COS, or null when no policy was attached."
  value       = local.attach_policy ? local.policy_document : null
}

output "enforced_controls" {
  description = "CIS ids this invocation actually enforced."
  value = sort(distinct(compact([
    local.on["4.1"] && var.manage_bucket ? "4.1" : "",
    local.on["4.1"] && local.attach_policy ? "4.1" : "",
    local.on["4.3"] && local.enable_logging ? "4.3" : "",
    local.on["4.4"] && local.attach_policy ? "4.4" : "",
    local.on["4.5"] && local.attach_policy ? "4.5" : "",
    local.on["4.6"] && local.encryption_algorithm == "AES256" ? "4.6" : "",
    local.on["4.7"] && local.encryption_algorithm == "KMS" ? "4.7" : "",
  ])))
}

output "unreachable_controls" {
  description = <<-EOT
    Selected controls this invocation could NOT enforce, because the bucket is
    not managed by Terraform here. Import the bucket and set
    manage_bucket = true, or remediate these in the console.
  EOT
  value       = local.unreachable
}
