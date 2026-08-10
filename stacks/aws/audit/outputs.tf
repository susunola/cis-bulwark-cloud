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
# controls were selected, in which case `bin/cis` falls back to the CIS_* and
# AWS_* environment variables.
output "cis_account" {
  description = "Account identity (account id, arn, region) for the report header."
  value = length(data.aws_caller_identity.self) > 0 ? {
    account_id = data.aws_caller_identity.self[0].account_id
    arn        = data.aws_caller_identity.self[0].arn
    region     = var.region
  } : null
}

# Makes `terraform plan` (or `cis plan`) useful on its own: checks are evaluated
# during plan, so a failing baseline shows up without applying anything.
check "cis_baseline" {
  assert {
    condition     = length(local.failed) == 0
    error_message = "CIS controls failing: ${join(", ", local.failed)}"
  }
}
