# Assessment logic.

locals {
  evidence_limit = 6

  # ---- 1 IAM ----------------------------------------------------------------

  # 1.5 - RAM users idle for var.unused_days or never logged in.
  ram_users = flatten(data.alicloud_ram_users.all[*].users)
  ram_user_idle = [
    for u in local.ram_users : u.name
    if u.last_login_date == "" || timecmp(u.last_login_date, timeadd(timestamp(), "-${var.unused_days}h")) < 0
  ]

  # ---- 2 Logging -------------------------------------------------------------

  actiontrails = flatten(data.alicloud_actiontrails.all[*].actiontrails)
  trail_enabled = [
    for t in local.actiontrails : t.trail_name
    if lower(t.status) == "enabled"
  ]
  trail_oss_buckets = distinct([
    for t in local.actiontrails : t.oss_bucket_name
    if t.oss_bucket_name != null && t.oss_bucket_name != ""
  ])

  oss_buckets = flatten(data.alicloud_oss_buckets.all[*].buckets)
  oss_public = [
    for b in local.oss_buckets : b.name
    if contains(["public-read", "public-read-write"], lower(b.acl))
  ]

  # 2.2 - trail bucket (by name) is publicly readable.
  trail_bucket_public = [
    for b in local.oss_buckets : b.name
    if contains(local.trail_oss_buckets, b.name) && contains(["public-read", "public-read-write"], lower(b.acl))
  ]

  # ---- 4 Virtual Machines ------------------------------------------------------

  cbs_disks = flatten(data.alicloud_disks.all[*].disks)
  disk_unattached_plain = [
    for d in local.cbs_disks : "${d.disk_id}(${d.disk_name})"
    if(d.instance_id == null || d.instance_id == "") && !d.encrypted
  ]
  disk_attached_plain = [
    for d in local.cbs_disks : "${d.disk_id}(${d.disk_name})"
    if d.instance_id != null && d.instance_id != "" && !d.encrypted
  ]

  # security group rules - port_range "22/22" or "1/65535".
  sg_rules = flatten([
    for gid, ds in data.alicloud_security_group_rules.this : [
      for r in ds.rules : {
        sg   = gid
        rule = r
      }
      if r.direction == "ingress" && r.policy == "accept" &&
      (r.source_cidr_ip == "0.0.0.0/0" || r.source_cidr_ip == "::/0")
    ]
  ])

  rule_has_port = {
    for p in [22, 3389] : p => [
      for r in local.sg_rules :
      "${r.sg} rule ${r.rule.id} (${r.rule.ip_protocol} ${r.rule.port_range})"
      if(
        r.rule.port_range == "" || r.rule.port_range == "-1/-1" || r.rule.port_range == "1/65535" ||
        (can(regex("^[0-9]+/[0-9]+$", r.rule.port_range)) &&
          tonumber(split("/", r.rule.port_range)[0]) <= p &&
        p <= tonumber(split("/", r.rule.port_range)[1]))
      )
    ]
  }

  # ---- 5 Storage --------------------------------------------------------------

  oss_no_logging = [
    for b in local.oss_buckets : b.name
    if try(length(b.logging), 0) == 0
  ]

  oss_no_sse = [
    for b in local.oss_buckets : b.name
    if try(length(b.server_side_encryption_rule), 0) == 0
  ]

  # ---- 6 RDS --------------------------------------------------------------------

  db_instances = flatten(data.alicloud_db_instances.all[*].instances)
  db_no_ssl = [
    for d in local.db_instances : d.id
    if !d.ssl_enabled
  ]
  db_no_tde = [
    for d in local.db_instances : d.id
    if d.encryption_key == null || d.encryption_key == ""
  ]

  # ---- 8 Security Center -----------------------------------------------------------

  td_instances = flatten(data.alicloud_threat_detection_instances.all[*].instances)
}

locals {
  violation_probes = {
    "1.5" = {
      bad   = local.ram_user_idle
      ok    = "${length(local.ram_users)} RAM user(s), all active within ${var.unused_days} days"
      label = "RAM user idle for ${var.unused_days} days or never logged in"
    }
    "2.2" = {
      bad   = local.trail_bucket_public
      ok    = "${length(local.trail_oss_buckets)} ActionTrail bucket(s), none public"
      label = "ActionTrail log bucket is publicly readable"
    }
    "4.1" = {
      bad   = local.disk_unattached_plain
      ok    = "${length(local.cbs_disks)} disk(s), every unattached disk encrypted"
      label = "unattached disk is not encrypted"
    }
    "4.2" = {
      bad   = local.disk_attached_plain
      ok    = "${length(local.cbs_disks)} disk(s), every attached disk encrypted"
      label = "attached disk is not encrypted"
    }
    "4.3" = {
      bad   = local.rule_has_port[22]
      ok    = "${length(local.sg_rules)} internet ingress rule(s) across ${length(data.alicloud_security_group_rules.this)} group(s), none to 22"
      label = "0.0.0.0/0 ingress to port 22"
    }
    "4.4" = {
      bad   = local.rule_has_port[3389]
      ok    = "${length(local.sg_rules)} internet ingress rule(s) across ${length(data.alicloud_security_group_rules.this)} group(s), none to 3389"
      label = "0.0.0.0/0 ingress to port 3389"
    }
    "5.1" = {
      bad   = local.oss_public
      ok    = "${length(local.oss_buckets)} bucket(s), all private"
      label = "bucket ACL grants public access"
    }
    "5.3" = {
      bad   = local.oss_no_logging
      ok    = "${length(local.oss_buckets)} bucket(s), all with logging enabled"
      label = "bucket has no access logging"
    }
    "5.8" = {
      bad   = local.oss_no_sse
      ok    = "${length(local.oss_buckets)} bucket(s), all with server-side encryption"
      label = "bucket has no server-side encryption rule"
    }
    "6.1" = {
      bad   = local.db_no_ssl
      ok    = "${length(local.db_instances)} RDS instance(s), all with SSL enabled"
      label = "RDS instance has SSL disabled"
    }
    "6.5" = {
      bad   = local.db_no_tde
      ok    = "${length(local.db_instances)} RDS instance(s), all with TDE enabled"
      label = "RDS instance has TDE disabled"
    }
  }

  presence_probes = {
    "2.1" = {
      good  = local.trail_enabled
      label = "ActionTrail trail enabled"
      bad   = "no ActionTrail trail has status = enabled"
    }
    "8.1" = {
      good  = [for i in local.td_instances : i.instance_id]
      label = "Security Center (threat detection) instance active"
      bad   = "no threat-detection instance found - Security Center is not subscribed"
    }
  }

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
