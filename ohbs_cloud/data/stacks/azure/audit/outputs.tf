# bin/cis reads cis_findings back with `terraform output -json` and renders it.
output "cis_findings" {
  description = "control id -> { status = PASS|FAIL, evidence = ... }"
  value       = local.findings
}

output "cis_summary" {
  description = "Counts, for humans reading raw terraform output."
  value = {
    assessed = length(local.findings)
    passed   = length(local.findings) - length(local.failed)
    failed   = length(local.failed)
    failing  = local.failed
  }
}

# Subscription / tenant identity for the report header.
output "cis_account" {
  description = "Account identity (subscription, tenant, region) for the report header."
  value = length(data.azurerm_client_config.self) > 0 ? {
    subscription_id = data.azurerm_client_config.self[0].subscription_id
    tenant_id       = data.azurerm_client_config.self[0].tenant_id
    region          = var.region
  } : null
}

# Makes `terraform plan` (or `cis plan`) useful on its own.
check "cis_baseline" {
  assert {
    condition     = length(local.failed) == 0
    error_message = "CIS controls failing: ${join(", ", local.failed)}"
  }
}
