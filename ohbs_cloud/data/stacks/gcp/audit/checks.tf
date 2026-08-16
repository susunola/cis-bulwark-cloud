# Assessment logic.

locals {
  evidence_limit = 6

  # ---- 2 Logging ------------------------------------------------------------

  # 2.4 - log-export buckets must carry a retention policy (bucket lock).
  bucket_no_retention = [
    for name, b in data.google_storage_bucket.this : name
    if !can(b.retention_policy[0].retention_period) && contains(var.log_export_buckets, name)
  ]

  # ---- 3 Networking ----------------------------------------------------------

  # 3.1 - the default network must not exist.
  default_network_present = [
    for link in flatten(data.google_compute_networks.all[*].networks) : link
    if can(regex("/networks/default$", link))
  ]

  # ---- 4 Compute ---------------------------------------------------------------

  instance_default_sa = [
    for name, i in data.google_compute_instance.this : name
    if length(i.service_account) == 0 ||
    can(regex("-compute@developer\\.gserviceaccount\\.com$", i.service_account[0].email))
  ]

  instance_full_access_sa = [
    for name, i in data.google_compute_instance.this : name
    if length(i.service_account) == 0 ||
    contains(try(i.service_account[0].scopes, []), "https://www.googleapis.com/auth/cloud-platform")
  ]

  instance_no_ssh_block = [
    for name, i in data.google_compute_instance.this : name
    if try(i.metadata["block-project-ssh-keys"], "false") != "true"
  ]

  instance_serial_ports = [
    for name, i in data.google_compute_instance.this : name
    if try(i.metadata["serial-port-enable"], "false") == "true"
  ]

  instance_ip_forwarding = [
    for name, i in data.google_compute_instance.this : name
    if i.can_ip_forward
  ]

  instance_not_shielded = [
    for name, i in data.google_compute_instance.this : name
    if length(i.shielded_instance_config) == 0 ||
    !try(i.shielded_instance_config[0].enable_secure_boot, false)
  ]

  instance_public_ip = [
    for name, i in data.google_compute_instance.this : name
    if length(flatten([
      for nic in i.network_interface : try(nic.access_config, [])
    ])) > 0
  ]

  instance_not_confidential = [
    for name, i in data.google_compute_instance.this : name
    if length(i.confidential_instance_config) == 0 ||
    !try(i.confidential_instance_config[0].enable_confidential_compute, false)
  ]

  # ---- 5 Storage / 7 BigQuery -----------------------------------------------------

  # any allUsers / allAuthenticatedUsers binding == public.
  public_bindings = {
    for kind, src in {
      "5.1" = data.google_storage_bucket_iam_policy.this,
      "7.1" = data.google_bigquery_dataset_iam_policy.this,
      } : kind => flatten([
        for name, p in src : [
          for b in try(jsondecode(p.policy_data).bindings, []) :
          [for m in try(b.members, []) : "${name} member ${m}"
          if contains(["allUsers", "allAuthenticatedUsers"], m)]
        ]
    ])
  }

  # ---- 6 Cloud SQL -------------------------------------------------------------------

  sql_flags = {
    for name, i in data.google_sql_database_instance.this : name => {
      for f in try(i.settings[0].database_flags, []) : f.name => f.value
    }
  }

  # explicit probes, one per control
  sql_bad = {
    "6.1.2" = [for name, f in local.sql_flags : name if lookup(f, "skip_show_database", "off") != "on"]
    "6.2.2" = [for name, f in local.sql_flags : name if lookup(f, "log_connections", "off") != "on"]
    "6.2.3" = [for name, f in local.sql_flags : name if lookup(f, "log_disconnections", "off") != "on"]
    "6.2.4" = [for name, f in local.sql_flags : name if !contains(["ddl", "mod", "all"], lookup(f, "log_statement", "ddl"))]
    "6.2.5" = [for name, f in local.sql_flags : name if !contains(["warning", "notice", "info", "log", "debug1", "debug2", "debug3", "debug4", "debug5"], lookup(f, "log_min_messages", "warning"))]
    "6.2.6" = [for name, f in local.sql_flags : name if !contains(["error", "log", "fatal", "panic"], lookup(f, "log_min_error_statement", "error"))]
    "6.2.7" = [for name, f in local.sql_flags : name if lookup(f, "log_min_duration_statement", "-1") != "-1"]
    "6.2.1" = [for name, f in local.sql_flags : name if !contains(["DEFAULT", "VERBOSE"], upper(lookup(f, "log_error_verbosity", "DEFAULT")))]
    "6.3.1" = [for name, f in local.sql_flags : name if lower(lookup(f, "external scripts enabled", "off")) != "off"]
    "6.3.2" = [for name, f in local.sql_flags : name if lower(lookup(f, "cross db ownership chaining", "off")) != "off"]
    "6.3.3" = [for name, f in local.sql_flags : name if contains(keys(f), "user connections")]
    "6.3.4" = [for name, f in local.sql_flags : name if contains(keys(f), "user options")]
    "6.3.5" = [for name, f in local.sql_flags : name if lower(lookup(f, "remote access", "off")) != "off"]
    "6.3.6" = [for name, f in local.sql_flags : name if lower(lookup(f, "3625 (trace flag)", "off")) != "on"]
    "6.3.7" = [for name, f in local.sql_flags : name if lower(lookup(f, "contained database authentication", "off")) != "off"]
    "6.4"   = [for name, i in data.google_sql_database_instance.this : name if !try(i.settings[0].ip_configuration[0].require_ssl, false)]
    "6.5" = [for name, i in data.google_sql_database_instance.this : name if length([
      for a in try(i.settings[0].ip_configuration[0].authorized_networks, []) :
      try(a.value, "")
      if try(a.value, "") == "0.0.0.0/0"
    ]) > 0]
    "6.7" = [for name, i in data.google_sql_database_instance.this : name if try(i.settings[0].ip_configuration[0].ipv4_enabled, false)]
    "6.8" = [for name, i in data.google_sql_database_instance.this : name if !try(i.settings[0].backup_configuration[0].enabled, false)]
  }
}

locals {
  violation_probes = {
    "2.4" = {
      bad   = local.bucket_no_retention
      ok    = "${length(var.log_export_buckets)} log-export bucket(s), all with bucket-lock retention"
      label = "log-export bucket without retention policy"
    }
    "3.1" = {
      bad   = local.default_network_present
      ok    = "no default network in the project"
      label = "default network exists"
    }
    "4.1" = {
      bad   = local.instance_default_sa
      ok    = "${length(data.google_compute_instance.this)} instance(s), none on the default service account"
      label = "instance uses the default compute service account"
    }
    "4.2" = {
      bad   = local.instance_full_access_sa
      ok    = "${length(data.google_compute_instance.this)} instance(s), none with full cloud-platform access"
      label = "instance uses the default SA with full cloud-platform scope"
    }
    "4.3" = {
      bad   = local.instance_no_ssh_block
      ok    = "${length(data.google_compute_instance.this)} instance(s), all block project-wide SSH keys"
      label = "instance does not block project-wide SSH keys"
    }
    "4.5" = {
      bad   = local.instance_serial_ports
      ok    = "${length(data.google_compute_instance.this)} instance(s), none with serial ports enabled"
      label = "instance has serial port access enabled"
    }
    "4.6" = {
      bad   = local.instance_ip_forwarding
      ok    = "${length(data.google_compute_instance.this)} instance(s), none with IP forwarding"
      label = "instance has IP forwarding enabled"
    }
    "4.8" = {
      bad   = local.instance_not_shielded
      ok    = "${length(data.google_compute_instance.this)} instance(s), all shielded VMs"
      label = "instance is not a shielded VM (secure boot)"
    }
    "4.9" = {
      bad   = local.instance_public_ip
      ok    = "${length(data.google_compute_instance.this)} instance(s), none with a public IP"
      label = "instance has a public IP address"
    }
    "4.11" = {
      bad   = local.instance_not_confidential
      ok    = "${length(data.google_compute_instance.this)} instance(s), all confidential"
      label = "instance does not have confidential computing enabled"
    }
    "5.1" = {
      bad   = flatten(local.public_bindings["5.1"])
      ok    = "${length(data.google_storage_bucket_iam_policy.this)} bucket(s), none publicly accessible"
      label = "bucket grants access to allUsers / allAuthenticatedUsers"
    }
    "6.1.2" = {
      bad   = local.sql_bad["6.1.2"]
      ok    = "${length(local.sql_flags)} SQL instance(s), skip_show_database on"
      label = "skip_show_database flag not set to on"
    }
    "6.2.1" = {
      bad   = local.sql_bad["6.2.1"]
      ok    = "${length(local.sql_flags)} SQL instance(s), log_error_verbosity DEFAULT or stricter"
      label = "log_error_verbosity below DEFAULT"
    }
    "6.2.2" = {
      bad   = local.sql_bad["6.2.2"]
      ok    = "${length(local.sql_flags)} SQL instance(s), log_connections on"
      label = "log_connections flag not on"
    }
    "6.2.3" = {
      bad   = local.sql_bad["6.2.3"]
      ok    = "${length(local.sql_flags)} SQL instance(s), log_disconnections on"
      label = "log_disconnections flag not on"
    }
    "6.2.4" = {
      bad   = local.sql_bad["6.2.4"]
      ok    = "${length(local.sql_flags)} SQL instance(s), log_statement set appropriately"
      label = "log_statement not set appropriately"
    }
    "6.2.5" = {
      bad   = local.sql_bad["6.2.5"]
      ok    = "${length(local.sql_flags)} SQL instance(s), log_min_messages at least warning"
      label = "log_min_messages below warning"
    }
    "6.2.6" = {
      bad   = local.sql_bad["6.2.6"]
      ok    = "${length(local.sql_flags)} SQL instance(s), log_min_error_statement error or stricter"
      label = "log_min_error_statement below error"
    }
    "6.2.7" = {
      bad   = local.sql_bad["6.2.7"]
      ok    = "${length(local.sql_flags)} SQL instance(s), log_min_duration_statement disabled (-1)"
      label = "log_min_duration_statement not disabled"
    }
    "6.3.1" = {
      bad   = local.sql_bad["6.3.1"]
      ok    = "${length(local.sql_flags)} SQL instance(s), external scripts off"
      label = "external scripts enabled"
    }
    "6.3.2" = {
      bad   = local.sql_bad["6.3.2"]
      ok    = "${length(local.sql_flags)} SQL instance(s), cross db ownership chaining off"
      label = "cross db ownership chaining on"
    }
    "6.3.3" = {
      bad   = local.sql_bad["6.3.3"]
      ok    = "${length(local.sql_flags)} SQL instance(s), user connections not limited"
      label = "user connections flag limits connections"
    }
    "6.3.4" = {
      bad   = local.sql_bad["6.3.4"]
      ok    = "${length(local.sql_flags)} SQL instance(s), user options not configured"
      label = "user options flag configured"
    }
    "6.3.5" = {
      bad   = local.sql_bad["6.3.5"]
      ok    = "${length(local.sql_flags)} SQL instance(s), remote access off"
      label = "remote access flag on"
    }
    "6.3.6" = {
      bad   = local.sql_bad["6.3.6"]
      ok    = "${length(local.sql_flags)} SQL instance(s), trace flag 3625 on"
      label = "trace flag 3625 off"
    }
    "6.3.7" = {
      bad   = local.sql_bad["6.3.7"]
      ok    = "${length(local.sql_flags)} SQL instance(s), contained database authentication off"
      label = "contained database authentication on"
    }
    "6.4" = {
      bad   = local.sql_bad["6.4"]
      ok    = "${length(local.sql_flags)} SQL instance(s), all requiring SSL"
      label = "SQL instance does not require SSL"
    }
    "6.5" = {
      bad   = local.sql_bad["6.5"]
      ok    = "${length(local.sql_flags)} SQL instance(s), no implicit public whitelist"
      label = "SQL instance whitelists 0.0.0.0/0"
    }
    "6.7" = {
      bad   = local.sql_bad["6.7"]
      ok    = "${length(local.sql_flags)} SQL instance(s), none with public IPs"
      label = "SQL instance has a public IP"
    }
    "6.8" = {
      bad   = local.sql_bad["6.8"]
      ok    = "${length(local.sql_flags)} SQL instance(s), all with automated backups"
      label = "SQL instance has automated backups disabled"
    }
    "7.1" = {
      bad   = flatten(local.public_bindings["7.1"])
      ok    = "${length(data.google_bigquery_dataset_iam_policy.this)} dataset(s), none publicly accessible"
      label = "BigQuery dataset grants access to allUsers / allAuthenticatedUsers"
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

  findings_presence = {}

  all_findings = merge(local.findings_violation, local.findings_presence)

  findings = {
    for id, f in local.all_findings : id => f
    if contains(var.enabled_controls, id)
  }

  failed = [for id, f in local.findings : id if f.status == "FAIL"]
}
