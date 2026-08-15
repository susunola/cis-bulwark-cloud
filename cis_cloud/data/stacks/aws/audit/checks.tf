# Assessment logic.
#
# Two probe shapes cover every control:
#
#   violation_probes  a non-empty `bad` list means FAIL   (offending resources)
#   presence_probes   an empty `good` list means FAIL     (missing safeguards)
#
# Keeping the verdict/evidence formatting in one place means a new control is
# one entry, not one more hand-written conditional.

locals {
  evidence_limit = 6

  # ---- 2 IAM ----------------------------------------------------------------

  # 2.16 - every EC2 instance must carry an instance role.
  instances_without_role = [
    for id, i in data.aws_instance.this : "${id}(${i.instance_state})"
    if i.iam_instance_profile == null || i.iam_instance_profile == ""
  ]

  # ---- 3 Storage --------------------------------------------------------------

  # 3.2.x - RDS instance flags.
  db_unencrypted = [
    for id, d in data.aws_db_instance.this : id
    if !d.storage_encrypted
  ]

  db_without_minor_upgrade = [
    for id, d in data.aws_db_instance.this : id
    if !d.auto_minor_version_upgrade
  ]

  db_public = [
    for id, d in data.aws_db_instance.this : id
    if d.publicly_accessible
  ]

  # ---- 6 Networking -------------------------------------------------------------

  # 6.1.1 - account-level EBS encryption default.
  ebs_default_values = flatten(data.aws_ebs_encryption_by_default.this[*].enabled)
  ebs_encrypted_default = (
    length(local.ebs_default_values) > 0
    ? local.ebs_default_values[0]
    : false
  )

  # 6.3 / 6.4 / 6.5 - security group rules. A rule is an "admin port" rule when
  # its port range (or "all ports", from_port == null) overlaps any of
  # var.remote_admin_ports.
  sg_rules = [
    for k in local.sg_rule_keys : {
      sg   = k.sg
      key  = k.key
      rule = data.aws_vpc_security_group_rule.this[k.key]
    }
  ]

  rule_is_admin = [
    for r in local.sg_rules :
    r.rule.from_port != null
    ? anytrue([
      for p in var.remote_admin_ports :
      r.rule.from_port <= p && (r.rule.to_port == null ? true : r.rule.to_port >= p)
    ])
    : true # from_port == null means the rule covers all ports
  ]

  sg_admin_rules_v4 = [
    for i, r in local.sg_rules :
    "${r.sg} rule ${r.rule.security_group_rule_id} (${r.rule.ip_protocol} ${r.rule.from_port == null ? "all" : r.rule.from_port}-${r.rule.to_port == null ? "" : r.rule.to_port})"
    if !r.rule.is_egress && r.rule.cidr_ipv4 == "0.0.0.0/0" && local.rule_is_admin[i]
  ]

  sg_admin_rules_v6 = [
    for i, r in local.sg_rules :
    "${r.sg} rule ${r.rule.security_group_rule_id} (${r.rule.ip_protocol} ${r.rule.from_port == null ? "all" : r.rule.from_port}-${r.rule.to_port == null ? "" : r.rule.to_port})"
    if !r.rule.is_egress && r.rule.cidr_ipv6 == "::/0" && local.rule_is_admin[i]
  ]

  # 6.5 - the per-VPC "default" security group must have no rules at all.
  default_sg_rules = [
    for i, r in local.sg_rules :
    "${r.sg} rule ${r.rule.security_group_rule_id}"
    if contains(flatten(data.aws_security_groups.default[*].ids), r.sg)
  ]

  # 6.7 - IMDSv2 required on every instance.
  instances_without_imdsv2 = [
    for id, i in data.aws_instance.this : "${id}(${i.instance_state})"
    if try(i.metadata_options[0].http_tokens, "optional") != "required"
  ]
}

# ---- verdicts --------------------------------------------------------------

locals {
  violation_probes = {
    "2.16" = {
      bad   = local.instances_without_role
      ok    = "${length(data.aws_instance.this)} instance(s), all carry an IAM instance profile"
      label = "EC2 instance without an IAM instance role"
    }
    "3.2.1" = {
      bad   = local.db_unencrypted
      ok    = "${length(data.aws_db_instance.this)} RDS instance(s), all encrypted at rest"
      label = "RDS instance with encryption-at-rest disabled"
    }
    "3.2.2" = {
      bad   = local.db_without_minor_upgrade
      ok    = "${length(data.aws_db_instance.this)} RDS instance(s), all auto-upgrade minor versions"
      label = "RDS instance without auto minor version upgrade"
    }
    "3.2.3" = {
      bad   = local.db_public
      ok    = "${length(data.aws_db_instance.this)} RDS instance(s), none publicly accessible"
      label = "RDS instance is publicly accessible"
    }
    "6.1.1" = {
      bad   = local.ebs_encrypted_default ? [] : ["account default"]
      ok    = "EBS encryption by default is enabled at account level"
      label = "EBS encryption by default is disabled"
    }
    "6.3" = {
      bad   = local.sg_admin_rules_v4
      ok    = "${length(data.aws_security_groups.all)} security group(s), no 0.0.0.0/0 ingress on ${join("/", [for p in var.remote_admin_ports : tostring(p)])}"
      label = "0.0.0.0/0 ingress to a remote administration port"
    }
    "6.4" = {
      bad   = local.sg_admin_rules_v6
      ok    = "${length(data.aws_security_groups.all)} security group(s), no ::/0 ingress on ${join("/", [for p in var.remote_admin_ports : tostring(p)])}"
      label = "::/0 ingress to a remote administration port"
    }
    "6.5" = {
      bad   = local.default_sg_rules
      ok    = "${length(data.aws_security_groups.default)} default security group(s), all without rules"
      label = "default security group has rules (all traffic is allowed)"
    }
    "6.7" = {
      bad   = local.instances_without_imdsv2
      ok    = "${length(data.aws_instance.this)} instance(s), all require IMDSv2"
      label = "EC2 instance allows IMDSv1"
    }
  }

  presence_probes = {}

  findings_violation = {
    for id, p in local.violation_probes : id => {
      status = length(p.bad) == 0 ? "PASS" : "FAIL"
      evidence = length(p.bad) == 0 ? p.ok : format(
        "%s: %s%s",
        p.label,
        join(", ", slice(p.bad, 0, min(local.evidence_limit, length(p.bad)))),
        length(p.bad) > local.evidence_limit ? " (+${length(p.bad) - local.evidence_limit} more)" : ""
      )
    }
  }

  findings_presence = {
    for id, p in local.presence_probes : id => {
      status = length(p.good) > 0 ? "PASS" : "FAIL"
      evidence = length(p.good) > 0 ? format(
        "%s: %s",
        p.label,
        join(", ", slice(p.good, 0, min(local.evidence_limit, length(p.good))))
      ) : p.bad
    }
  }

  all_findings = merge(local.findings_violation, local.findings_presence)

  findings = {
    for id, f in local.all_findings : id => f
    if contains(var.enabled_controls, id)
  }

  failed = [for id, f in local.findings : id if f.status == "FAIL"]
}
