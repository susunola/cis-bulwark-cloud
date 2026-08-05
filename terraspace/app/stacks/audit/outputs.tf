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

# Account identity shown at the top of the scan/hardening report. `bin/cis`
# reads this back with `terraform output -json cis_account`. Null when no
# controls were selected, in which case `bin/cis` falls back to CIS_UIN /
# CIS_ACCOUNT_NAME / CIS_APP_ID / TENCENTCLOUD_REGION.
output "cis_account" {
  description = "Account identity (UIN, name, app id, region) for the report header."
  value = length(data.tencentcloud_user_info.self) > 0 ? {
    uin    = data.tencentcloud_user_info.self[0].uin
    name   = data.tencentcloud_user_info.self[0].name
    app_id = data.tencentcloud_user_info.self[0].app_id
    region = var.region
  } : null
}

# Makes `terraspace plan audit` useful on its own: checks are evaluated during
# plan, so a failing baseline shows up without applying anything.
check "cis_baseline" {
  assert {
    condition     = length(local.failed) == 0
    error_message = "CIS controls failing: ${join(", ", local.failed)}"
  }
}
