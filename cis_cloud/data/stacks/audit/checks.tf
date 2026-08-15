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
}

# ---- 1 Identity and Access Management --------------------------------------

locals {
  cam_policies = flatten(data.tencentcloud_cam_policies.all[*].policy_list)

  # The provider does not expose policy documents, so "grants *:*" is decided
  # by name. var.admin_policy_names is the knob for in-house admin policies.
  cam_admin_attached = [
    for p in local.cam_policies : "${p.name} (${p.attachments} attachment(s))"
    if contains(var.admin_policy_names, p.name) && p.attachments > 0
  ]

  cam_direct_attachments = flatten([
    for uid, ds in data.tencentcloud_cam_user_policy_attachments.per_user : [
      for a in ds.user_policy_attachment_list : "${a.user_name}->${a.policy_name}"
    ]
  ])
}

# ---- 2 Logging and Monitoring ----------------------------------------------

locals {
  audit_tracks    = flatten(data.tencentcloud_audits.all[*].audit_list)
  audit_tracks_on = [for a in local.audit_tracks : a.name if a.audit_switch]

  audit_cos_buckets = distinct([
    for a in local.audit_tracks : a.cos_bucket
    if a.cos_bucket != null && a.cos_bucket != ""
  ])

  audit_public_buckets = [
    for b in local.audit_cos_buckets : b if contains(local.cos_public_buckets, b)
  ]

  cls_topics    = flatten(data.tencentcloud_cls_topics.all[*].topics)
  cls_topics_on = [for t in local.cls_topics : t.topic_name if t.status]

  # period <= 0 means "store permanently", which satisfies any minimum.
  cls_short_retention = [
    for t in local.cls_topics : "${t.topic_name}=${t.period}d"
    if t.period > 0 && t.period < var.cls_min_retention_days
  ]
}

# ---- 3 Networking ----------------------------------------------------------

locals {
  security_groups = flatten(data.tencentcloud_security_groups.all[*].security_groups)

  # Rules arrive as "ACCEPT#0.0.0.0/0#22#TCP".
  sg_rules = flatten([
    for sg in local.security_groups : [
      for r in sg.ingress : {
        sg_id = sg.security_group_id
        name  = sg.name
        raw   = r
        parts = split("#", r)
      }
    ]
  ])

  sg_internet_rules = [
    for r in local.sg_rules : {
      sg_id     = r.sg_id
      name      = r.name
      raw       = r.raw
      proto     = length(r.parts) > 3 ? upper(r.parts[3]) : "ALL"
      ports     = length(r.parts) > 2 ? upper(r.parts[2]) : "ALL"
      segments  = split(",", length(r.parts) > 2 ? r.parts[2] : "ALL")
      all_ports = contains(["ALL", "", "-1", "0"], length(r.parts) > 2 ? upper(r.parts[2]) : "ALL")
      tcp_like  = contains(["ALL", "ANY", "-1", "TCP"], length(r.parts) > 3 ? upper(r.parts[3]) : "ALL")
    }
    if length(r.parts) > 1 && upper(r.parts[0]) == "ACCEPT" && contains(var.world_cidrs, r.parts[1])
  ]

  # CIS 3.1 - ports considered remote administration.
  remote_access_ports = var.remote_access_ports

  sg_open_on_port = {
    for cid, port in { "3.5" = 22, "3.6" = 3389 } : cid => distinct([
      for r in local.sg_internet_rules : "${r.sg_id}(${r.name}) ${r.raw}"
      if r.tcp_like && (r.all_ports || anytrue([
        for seg in r.segments :
        can(regex("^[0-9]+$", seg))
        ? tonumber(seg) == port
        : (
          can(regex("^[0-9]+-[0-9]+$", seg))
          ? (tonumber(split("-", seg)[0]) <= port && port <= tonumber(split("-", seg)[1]))
          : false
        )
      ]))
    ])
  }

  # 3.1 - any configured remote administration port reachable from the internet.
  sg_remote_access = distinct(concat(
    local.sg_open_on_port["3.5"],
    local.sg_open_on_port["3.6"],
    [
      for r in local.sg_internet_rules : "${r.sg_id}(${r.name}) ${r.raw}"
      if r.tcp_like && anytrue([
        for port in local.remote_access_ports :
        anytrue([
          for seg in r.segments :
          can(regex("^[0-9]+$", seg))
          ? tonumber(seg) == port
          : (
            can(regex("^[0-9]+-[0-9]+$", seg))
            ? (tonumber(split("-", seg)[0]) <= port && port <= tonumber(split("-", seg)[1]))
            : false
          )
        ])
      ])
    ]
  ))

  # 3.4 - "fine grained" means: not all ports, not all protocols, and no port
  # range wider than var.max_port_range_span.
  sg_coarse_rules = distinct([
    for r in local.sg_internet_rules : "${r.sg_id}(${r.name}) ${r.raw}"
    if r.all_ports || contains(["ALL", "", "-1"], r.proto) || anytrue([
      for seg in r.segments :
      can(regex("^[0-9]+-[0-9]+$", seg))
      ? (tonumber(split("-", seg)[1]) - tonumber(split("-", seg)[0])) > var.max_port_range_span
      : false
    ])
  ])

  route_tables = flatten(data.tencentcloud_vpc_route_tables.all[*].instance_list)

  route_broad_peering = flatten([
    for rt in local.route_tables : [
      for e in rt.route_entry_infos :
      "${rt.route_table_id}(${rt.name}) ${e.destination_cidr_block}->${e.next_type}"
      if contains(var.world_cidrs, e.destination_cidr_block) &&
      contains(var.peering_next_types, upper(e.next_type))
    ]
  ])
}

# ---- 4 Storage -------------------------------------------------------------

locals {
  cos_buckets = [
    for b in flatten(data.tencentcloud_cos_buckets.all[*].bucket_list) : {
      name = b.bucket
      acl  = lower(b.acl == null ? "" : b.acl)
      body = b.acl_body == null ? "" : b.acl_body
    }
  ]

  cos_public_buckets = [
    for b in local.cos_buckets : b.name
    if contains(var.public_acls, b.acl) || can(regex("AllUsers|AnyoneCanRead", b.body))
  ]

  cbs_disks = flatten(data.tencentcloud_cbs_storages.all[*].storage_list)

  cbs_unattached_plain = [
    for d in local.cbs_disks : "${d.storage_id}(${d.storage_name})"
    if !d.attached && !d.encrypt
  ]

  cbs_attached_plain = [
    for d in local.cbs_disks : "${d.storage_id}(${d.storage_name})"
    if d.attached && !d.encrypt
  ]
}

# ---- 5 TencentDB for MySQL -------------------------------------------------

locals {
  mysql_instances = flatten(data.tencentcloud_mysql_instance.all[*].instance_list)

  # The provider cannot list the security groups bound to an instance, so this
  # detects the stronger violation the console calls "public network address".
  mysql_public = [
    for m in local.mysql_instances : "${m.mysql_id} ${m.internet_host}:${m.internet_port}"
    if(m.internet_host != null && m.internet_host != "") && m.internet_port > 0
  ]
}

# ---- 6 Kubernetes Engine ---------------------------------------------------

locals {
  tke_clusters = flatten(data.tencentcloud_kubernetes_clusters.all[*].list)

  tke_internet_enabled = [
    for c in local.tke_clusters : "${c.cluster_id}(${c.cluster_name})"
    if c.cluster_external_endpoint != null && c.cluster_external_endpoint != ""
  ]

  tke_without_vpc_cni = [
    for c in local.tke_clusters : "${c.cluster_id}(${c.cluster_name}) network_type=${c.network_type}"
    if c.vpc_cni_type == null || c.vpc_cni_type == ""
  ]
}

# ---- 8 Cloud Workload Protection Platform ----------------------------------

locals {
  cvm_instances = flatten(data.tencentcloud_instances.all[*].instance_list)
  cwp_machines  = flatten(data.tencentcloud_cwp_machines_simple.cvm[*].machines)
  cwp_ids       = [for m in local.cwp_machines : m.instance_id]

  cvm_without_agent = [
    for i in local.cvm_instances : "${i.instance_id}(${i.instance_name})"
    if !contains(local.cwp_ids, i.instance_id)
  ]

  cwp_not_professional = [
    for m in local.cwp_machines : "${m.instance_id}(${m.machine_name})"
    if !m.is_pro_version
  ]
}

# ---- verdicts --------------------------------------------------------------

locals {
  violation_probes = {
    "1.15" = {
      bad   = local.cam_admin_attached
      ok    = "${length(local.cam_policies)} policy(ies) checked by name; none of ${join("/", var.admin_policy_names)} is attached"
      label = "full-admin policy in use (name-based check; provider does not expose policy documents)"
    }
    "1.16" = {
      bad   = local.cam_direct_attachments
      ok    = "${length(data.tencentcloud_cam_user_policy_attachments.per_user)} user(s) checked, no direct policy attachment"
      label = "policy attached directly to a user"
    }
    "2.2" = {
      bad   = local.audit_public_buckets
      ok    = "${length(local.audit_cos_buckets)} CloudAudit bucket(s), none public"
      label = "CloudAudit log bucket is publicly readable"
    }
    "2.20" = {
      bad   = local.cls_short_retention
      ok    = "${length(local.cls_topics)} topic(s), all retain >= ${var.cls_min_retention_days}d or permanently"
      label = "Logstore retention below ${var.cls_min_retention_days}d"
    }
    "3.1" = {
      bad   = local.sg_remote_access
      ok    = "${length(local.security_groups)} security group(s), no internet-facing remote administration ports"
      label = "remote access reachable from the internet"
    }
    "3.3" = {
      bad   = local.route_broad_peering
      ok    = "${length(local.route_tables)} route table(s), no 0.0.0.0/0 peering route"
      label = "route table sends 0.0.0.0/0 over a peering/CCN hop"
    }
    "3.4" = {
      bad   = local.sg_coarse_rules
      ok    = "${length(local.security_groups)} security group(s), all internet rules are fine grained"
      label = "coarse internet-facing rule (all ports/protocols or range > ${var.max_port_range_span})"
    }
    "3.5" = {
      bad   = local.sg_open_on_port["3.5"]
      ok    = "${length(local.security_groups)} security group(s), none expose 22"
      label = "0.0.0.0/0 to port 22"
    }
    "3.6" = {
      bad   = local.sg_open_on_port["3.6"]
      ok    = "${length(local.security_groups)} security group(s), none expose 3389"
      label = "0.0.0.0/0 to port 3389"
    }
    "4.1" = {
      bad   = local.cos_public_buckets
      ok    = "${length(local.cos_buckets)} bucket(s), all private"
      label = "bucket ACL grants public access"
    }
    "4.2" = {
      bad   = local.cos_public_buckets
      ok    = "${length(local.cos_buckets)} bucket(s) private at bucket level (object ACLs are not enumerable via Terraform)"
      label = "public at bucket level, so objects inside are reachable"
    }
    "4.8" = {
      bad   = local.cbs_unattached_plain
      ok    = "${length(local.cbs_disks)} disk(s), every unattached disk is encrypted"
      label = "unattached disk is not encrypted"
    }
    "4.9" = {
      bad   = local.cbs_attached_plain
      ok    = "${length(local.cbs_disks)} disk(s), every attached disk is encrypted"
      label = "attached disk is not encrypted"
    }
    "5.2" = {
      bad   = local.mysql_public
      ok    = "${length(local.mysql_instances)} instance(s), no public network address"
      label = "MySQL instance has a public network address"
    }
    "6.8" = {
      bad   = local.tke_without_vpc_cni
      ok    = "${length(local.tke_clusters)} cluster(s), all in VPC-CNI mode"
      label = "cluster is not in VPC-CNI mode (fix requires re-creation)"
    }
    "6.9" = {
      bad   = local.tke_internet_enabled
      ok    = "${length(local.tke_clusters)} cluster(s), no public API endpoint"
      label = "cluster API server is reachable from the internet"
    }
    "8.1" = {
      bad   = local.cvm_without_agent
      ok    = "${length(local.cvm_instances)} CVM(s), all report to CWPP in ${var.region}"
      label = "CVM has no CWPP agent"
    }
    "8.2" = {
      bad   = local.cwp_not_professional
      ok    = "${length(local.cwp_machines)} CWPP machine(s), all on a professional edition"
      label = "CWPP agent is on the basic edition"
    }
  }

  presence_probes = {
    "2.1" = {
      good  = local.audit_tracks_on
      label = "CloudAudit track enabled"
      bad   = "no CloudAudit track has audit_switch = true"
    }
    "2.3" = {
      good  = local.cls_topics_on
      label = "CLS topic receiving logs"
      bad   = "no enabled CLS log topic found - audit logs are not integrated with Cloud Log Service"
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
