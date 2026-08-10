output "cis_applied" {
  description = "CIS ids this stack enforced in the current run."
  value       = local.active
}

output "cis_implemented" {
  description = "CIS ids this stack is capable of enforcing."
  value       = local.implemented
}

output "password_policy_managed" {
  description = "Whether the account password policy is under this stack's management."
  value       = length(aws_iam_account_password_policy.cis) > 0
}

output "analyzer_created" {
  description = "Whether the IAM External Access Analyzer was created."
  value       = length(aws_accessanalyzer_analyzer.cis) > 0
}
