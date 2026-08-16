# Assessment logic.
#
# violation_probes: non-empty `bad` list means FAIL.
# presence_probes: empty `good` list means FAIL.

locals {
  evidence_limit = 6

  # ---- 2 Databricks ---------------------------------------------------------

  db_without_customer_vnet = [
    for name, w in data.azurerm_databricks_workspace.this : name
    if try(w.custom_parameters[0].virtual_network_id, "") == ""
  ]

  db_with_public_ip = [
    for name, w in data.azurerm_databricks_workspace.this : name
    if !try(w.custom_parameters[0].no_public_ip, false)
  ]

  # ---- 7 Networking -----------------------------------------------------------

  # An "internet" rule is Inbound with a source of Internet / * / 0.0.0.0/0.
  nsg_rules = flatten([
    for gname, g in data.azurerm_network_security_group.this : [
      for r in g.security_rule : {
        nsg  = gname
        rule = r
        internet = contains(
          ["Internet", "*", "0.0.0.0/0"],
          coalesce(r.source_address_prefix, "")
        ) || contains(try(r.source_address_prefixes, []), "0.0.0.0/0")
      }
      if r.access == "Allow" && r.direction == "Inbound"
    ]
  ])

  # A rule covers `port` when the port field equals it, is a range spanning it,
  # is empty/any, or the port is inside destination_port_ranges.
  covers = { for p in [22, 80, 3389, 443] : p =>
    [for r in local.nsg_rules : r if
      r.rule.destination_port_range == tostring(p) ||
      r.rule.destination_port_range == "" ||
      r.rule.destination_port_range == "*" ||
      (can(regex("^[0-9]+-[0-9]+$", r.rule.destination_port_range)) &&
        tonumber(split("-", r.rule.destination_port_range)[0]) <= p &&
      p <= tonumber(split("-", r.rule.destination_port_range)[1])) ||
      contains(try(r.rule.destination_port_ranges, []), tostring(p))
    ]
  }

  nsg_open = {
    "7.1" = [
      for r in local.covers[3389] : "${r.nsg} rule ${r.rule.name} (${r.rule.protocol} ${r.rule.destination_port_range})"
      if r.internet
    ]
    "7.2" = [
      for r in local.covers[22] : "${r.nsg} rule ${r.rule.name} (${r.rule.protocol} ${r.rule.destination_port_range})"
      if r.internet
    ]
    "7.3" = [
      for r in local.nsg_rules : "${r.nsg} rule ${r.rule.name} (${r.rule.protocol})"
      if r.internet && (r.rule.protocol == "Udp" || r.rule.protocol == "*")
    ]
    "7.4" = [
      for r in concat(local.covers[80], local.covers[443]) : "${r.nsg} rule ${r.rule.name} (${r.rule.protocol} ${r.rule.destination_port_range})"
      if r.internet
    ]
  }

  # ---- Application Gateway ----------------------------------------------------

  appgw_rules = data.azurerm_application_gateway.this
  appgw_waf_disabled = [
    for name, g in data.azurerm_application_gateway.this : name
    if !try(g.waf_configuration[0].enabled, false)
  ]
  appgw_tls_weak = [
    for name, g in data.azurerm_application_gateway.this : name
    if try(g.ssl_policy[0].min_protocol_version, "TLSv1_0") == "TLSv1_0" ||
    try(g.ssl_policy[0].min_protocol_version, "") == "TLSv1_1"
  ]
  appgw_no_body_check = [
    for name, g in data.azurerm_application_gateway.this : name
    if !try(g.waf_configuration[0].request_body_check, false)
  ]

  # ---- 8 Key Vault -------------------------------------------------------------

  kv_no_purge_protection = [
    for name, v in data.azurerm_key_vault.this : name
    if !v.purge_protection_enabled
  ]
  kv_rbac_disabled = [
    for name, v in data.azurerm_key_vault.this : name
    if !v.enable_rbac_authorization
  ]
  kv_public_network = [
    for name, v in data.azurerm_key_vault.this : name
    if try(v.public_network_access_enabled, true)
  ]

  # ---- 9 Storage ---------------------------------------------------------------

  sa_insecure_transfer = [
    for name, a in data.azurerm_storage_account.this : name
    if !a.https_traffic_only_enabled
  ]
  sa_low_tls = [
    for name, a in data.azurerm_storage_account.this : name
    if a.min_tls_version != "TLS1_2"
  ]
  sa_public_blob = [
    for name, a in data.azurerm_storage_account.this : name
    if a.allow_nested_items_to_be_public
  ]
  sa_not_geo_redundant = [
    for name, a in data.azurerm_storage_account.this : name
    if !contains(["GRS", "RAGRS"], a.account_replication_type)
  ]
}

# A rule covers `port` when destination_port_range equals it, a range spans it,
# or the port field is empty/any.

locals {
  violation_probes = {
    "2.1.1" = {
      bad   = local.db_without_customer_vnet
      ok    = "${length(data.azurerm_databricks_workspace.this)} workspace(s), all deployed in a customer-managed VNet"
      label = "Databricks workspace not deployed in a customer-managed VNet"
    }
    "2.1.9" = {
      bad   = local.db_with_public_ip
      ok    = "${length(data.azurerm_databricks_workspace.this)} workspace(s), all with No Public IP enabled"
      label = "Databricks workspace allows a public IP"
    }
    "7.1" = {
      bad   = local.nsg_open["7.1"]
      ok    = "${length(data.azurerm_network_security_group.this)} NSG(s), no internet inbound to 3389"
      label = "internet inbound RDP rule"
    }
    "7.2" = {
      bad   = local.nsg_open["7.2"]
      ok    = "${length(data.azurerm_network_security_group.this)} NSG(s), no internet inbound to 22"
      label = "internet inbound SSH rule"
    }
    "7.3" = {
      bad   = local.nsg_open["7.3"]
      ok    = "${length(data.azurerm_network_security_group.this)} NSG(s), no internet inbound UDP"
      label = "internet inbound UDP rule"
    }
    "7.4" = {
      bad   = local.nsg_open["7.4"]
      ok    = "${length(data.azurerm_network_security_group.this)} NSG(s), no internet inbound to 80/443"
      label = "internet inbound HTTP(S) rule"
    }
    "7.10" = {
      bad   = local.appgw_waf_disabled
      ok    = "${length(data.azurerm_application_gateway.this)} gateway(s), all with WAF enabled"
      label = "Application Gateway has WAF disabled"
    }
    "7.12" = {
      bad   = local.appgw_tls_weak
      ok    = "${length(data.azurerm_application_gateway.this)} gateway(s), all with min TLS 1.2"
      label = "Application Gateway allows TLS below 1.2"
    }
    "7.14" = {
      bad   = local.appgw_no_body_check
      ok    = "${length(data.azurerm_application_gateway.this)} gateway(s), all inspecting request bodies"
      label = "Application Gateway WAF does not inspect request bodies"
    }
    "8.3.5" = {
      bad   = local.kv_no_purge_protection
      ok    = "${length(data.azurerm_key_vault.this)} vault(s), all with purge protection"
      label = "Key Vault has purge protection disabled"
    }
    "8.3.6" = {
      bad   = local.kv_rbac_disabled
      ok    = "${length(data.azurerm_key_vault.this)} vault(s), all with RBAC authorization"
      label = "Key Vault RBAC authorization disabled"
    }
    "8.3.7" = {
      bad   = local.kv_public_network
      ok    = "${length(data.azurerm_key_vault.this)} vault(s), all blocking public network access"
      label = "Key Vault allows public network access"
    }
    "9.3.4" = {
      bad   = local.sa_insecure_transfer
      ok    = "${length(data.azurerm_storage_account.this)} account(s), all requiring secure transfer"
      label = "Storage Account allows insecure transfer"
    }
    "9.3.6" = {
      bad   = local.sa_low_tls
      ok    = "${length(data.azurerm_storage_account.this)} account(s), all at TLS 1.2 minimum"
      label = "Storage Account allows TLS below 1.2"
    }
    "9.3.8" = {
      bad   = local.sa_public_blob
      ok    = "${length(data.azurerm_storage_account.this)} account(s), all blocking anonymous blob access"
      label = "Storage Account allows anonymous blob access"
    }
    "9.3.11" = {
      bad   = local.sa_not_geo_redundant
      ok    = "${length(data.azurerm_storage_account.this)} account(s), all geo-redundant"
      label = "Storage Account not geo-redundant (GRS/RAGRS)"
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
