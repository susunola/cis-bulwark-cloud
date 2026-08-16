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

# Project identity for the report header.
output "cis_account" {
  description = "Account identity (project id / number, region) for the report header."
  value = length(data.google_project.self) > 0 ? {
    project_id     = data.google_project.self[0].project_id
    project_number = data.google_project.self[0].number
    region         = var.region
  } : null
}

# Makes `terraform plan` (or `cis plan`) useful on its own.
check "cis_baseline" {
  assert {
    condition     = length(local.failed) == 0
    error_message = "CIS controls failing: ${join(", ", local.failed)}"
  }
}
