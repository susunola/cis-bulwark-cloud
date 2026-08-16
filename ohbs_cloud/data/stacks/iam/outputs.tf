output "cis_applied" {
  description = "CIS ids this stack enforced in the current run."
  value       = local.active
}

output "cis_implemented" {
  description = "CIS ids this stack is capable of enforcing."
  value       = local.implemented
}

output "mfa_enforced_uins" {
  description = "CAM UINs that now require MFA at console login (CIS 1.4)."
  value       = sort([for k, v in tencentcloud_cam_mfa_flag.console_user : k])
}
