########################################################################
# security_group_baseline
#
# CIS 3.1 / 3.4 / 3.5 / 3.6.
#
# The module never invents access. It takes the rule set the operator says it
# wants, deletes the rules that violate the *selected* CIS controls, and writes
# the remainder back. Worst case it removes too much; it can never open a port.
########################################################################

locals {
  # --- stage 1: split the lite-rule strings ---------------------------------
  ingress_parts = [for raw in var.ingress : split("#", raw)]
  egress_parts  = [for raw in var.egress : split("#", raw)]

  ingress_parsed = [
    for i, raw in var.ingress : {
      raw       = raw
      action    = upper(trimspace(local.ingress_parts[i][0]))
      source    = trimspace(local.ingress_parts[i][1])
      port_spec = upper(trimspace(local.ingress_parts[i][2]))
      protocol  = upper(trimspace(local.ingress_parts[i][3]))
    }
  ]

  egress_parsed = [
    for i, raw in var.egress : {
      action    = upper(trimspace(local.egress_parts[i][0]))
      source    = trimspace(local.egress_parts[i][1])
      port_spec = upper(trimspace(local.egress_parts[i][2]))
      protocol  = upper(trimspace(local.egress_parts[i][3]))
    }
  ]

  # --- stage 2: expand the port spec into concrete ranges -------------------
  # "ALL" -> 1-65535, "80,443" -> two ranges, "3000-4000" -> one range.
  ingress_ranges = [
    for r in local.ingress_parsed : [
      for tok in split(",", contains(["ALL", "ANY", "-1", ""], r.port_spec) ? "1-65535" : r.port_spec) : {
        from = tonumber(split("-", trimspace(tok))[0])
        to   = tonumber(element(split("-", trimspace(tok)), length(split("-", trimspace(tok))) - 1))
      }
    ]
  ]

  # --- stage 3: derive the facts each control cares about -------------------
  ingress_facts = [
    for i, r in local.ingress_parsed : {
      raw        = r.raw
      accept     = r.action == "ACCEPT"
      from_world = contains(var.world_cidrs, r.source)
      any_proto  = contains(["ALL", "ANY", "-1"], r.protocol)
      tcp_like   = contains(["ALL", "ANY", "-1", "TCP"], r.protocol)

      # widest contiguous window this single rule opens
      span = max(concat([0], [for p in local.ingress_ranges[i] : (p.to - p.from + 1)])...)

      covers_ssh = anytrue([for p in local.ingress_ranges[i] : p.from <= 22 && 22 <= p.to])
      covers_rdp = anytrue([for p in local.ingress_ranges[i] : p.from <= 3389 && 3389 <= p.to])
      covers_remote_admin = anytrue([
        for q in var.remote_access_ports :
        anytrue([for p in local.ingress_ranges[i] : p.from <= q && q <= p.to])
      ])
    }
  ]

  # --- stage 4: verdict per rule -------------------------------------------
  ingress_violations = [
    for f in local.ingress_facts : compact([
      f.accept && f.from_world && f.tcp_like && f.covers_ssh ? "3.5" : "",
      f.accept && f.from_world && f.tcp_like && f.covers_rdp ? "3.6" : "",
      f.accept && f.from_world && f.covers_remote_admin ? "3.1" : "",
      f.accept && (f.any_proto || f.span > var.max_port_range_span) ? "3.4" : "",
    ])
  ]

  # A violation only bites when its control is part of this run.
  ingress_active = [
    for i, f in local.ingress_facts :
    [for v in local.ingress_violations[i] : v if contains(var.enabled_controls, v)]
  ]

  ingress_kept    = [for i, f in local.ingress_facts : f.raw if length(local.ingress_active[i]) == 0]
  ingress_dropped = [for i, f in local.ingress_facts : f.raw if length(local.ingress_active[i]) > 0]

  ingress_report = {
    for i, f in local.ingress_facts : format("%02d", i) => {
      rule     = f.raw
      violates = local.ingress_violations[i]
      enforced = local.ingress_active[i]
      dropped  = length(local.ingress_active[i]) > 0
    }
    if length(local.ingress_violations[i]) > 0
  }

  # --- stage 5: convert kept rules to tencentcloud_security_group_rule_set format
  # Source may be an IPv4 CIDR, an IPv6 CIDR, or another security group id.
  rule_set_ingress = [
    for r in local.ingress_parsed : {
      action             = r.action
      protocol           = contains(["ALL", "ANY", "-1", ""], r.protocol) ? null : r.protocol
      port               = contains(["ALL", "ANY", "-1", "", "0"], r.port_spec) ? null : r.port_spec
      cidr_block         = can(regex("^sg-[0-9a-z]+$", r.source)) || can(regex(":", r.source)) ? null : r.source
      ipv6_cidr_block    = can(regex(":", r.source)) && !can(regex("^sg-[0-9a-z]+$", r.source)) ? r.source : null
      source_security_id = can(regex("^sg-[0-9a-z]+$", r.source)) ? r.source : null
    }
    if contains(local.ingress_kept, r.raw)
  ]

  rule_set_egress = [
    for r in local.egress_parsed : {
      action             = r.action
      protocol           = contains(["ALL", "ANY", "-1", ""], r.protocol) ? null : r.protocol
      port               = contains(["ALL", "ANY", "-1", "", "0"], r.port_spec) ? null : r.port_spec
      cidr_block         = can(regex("^sg-[0-9a-z]+$", r.source)) || can(regex(":", r.source)) ? null : r.source
      ipv6_cidr_block    = can(regex(":", r.source)) && !can(regex("^sg-[0-9a-z]+$", r.source)) ? r.source : null
      source_security_id = can(regex("^sg-[0-9a-z]+$", r.source)) ? r.source : null
    }
  ]
}

resource "tencentcloud_security_group_rule_set" "this" {
  count = var.enforce ? 1 : 0

  security_group_id = var.security_group_id

  dynamic "ingress" {
    for_each = local.rule_set_ingress
    content {
      action             = ingress.value.action
      protocol           = ingress.value.protocol
      port               = ingress.value.port
      cidr_block         = ingress.value.cidr_block
      ipv6_cidr_block    = ingress.value.ipv6_cidr_block
      source_security_id = ingress.value.source_security_id
    }
  }

  dynamic "egress" {
    for_each = local.rule_set_egress
    content {
      action             = egress.value.action
      protocol           = egress.value.protocol
      port               = egress.value.port
      cidr_block         = egress.value.cidr_block
      ipv6_cidr_block    = egress.value.ipv6_cidr_block
      source_security_id = egress.value.source_security_id
    }
  }

  lifecycle {
    precondition {
      condition = length(local.ingress_kept) > 0 || var.allow_empty_ingress || length(var.ingress) == 0
      error_message = join(" ", [
        "CIS filtering removed every ingress rule from ${var.security_group_id}.",
        "Refusing to write a deny-all rule set. Fix the declared rules, narrow",
        "the selection with --exclude, or set allow_empty_ingress = true.",
      ])
    }
  }
}
