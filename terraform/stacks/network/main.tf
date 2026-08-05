########################################################################
# Stack: network
#
# CIS 2.4, 3.1, 3.2, 3.4, 3.5, 3.6, 3.7.
#
# 2.4 and 3.2 are the same recommendation printed in two sections
# ("Ensure virtual network flow log service is enabled"). Both are routed here
# so a single set of flow logs satisfies them; if the logging stack owned 2.4
# the two stacks would create duplicate tencentcloud_vpc_flow_log resources.
#
# 3.3 (least-access peering routes) is detect-only - the provider has a
# route table data source but no safe way to rewrite a live route table.
########################################################################

locals {
  implemented = ["2.4", "3.1", "3.2", "3.4", "3.5", "3.6", "3.7"]

  on     = { for id in local.implemented : id => contains(var.enabled_controls, id) }
  active = [for id in local.implemented : id if local.on[id]]

  # Either flow-log control turns the same resources on.
  flow_logs_wanted = local.on["2.4"] || local.on["3.2"]
  flow_log_set     = local.flow_logs_wanted ? var.flow_log_targets : {}

  # Any of the four rule controls makes the baseline worth computing.
  sg_controls_wanted = local.on["3.1"] || local.on["3.4"] || local.on["3.5"] || local.on["3.6"]
  sg_set             = local.sg_controls_wanted ? var.security_groups : {}

  clb_wanted = local.on["3.7"] && length(var.clb_instance_ids) > 0
}

# --- 2.4 / 3.2 Ensure virtual network flow log service is enabled ----------
resource "tencentcloud_vpc_flow_log" "this" {
  for_each = local.flow_log_set

  flow_log_name        = "${var.flow_log_name_prefix}-${each.key}"
  flow_log_description = coalesce(each.value.description, "CIS 2.4 / 3.2 - ${each.value.resource_type} ${each.value.resource_id}")
  resource_id          = each.value.resource_id
  resource_type        = each.value.resource_type
  traffic_type         = each.value.traffic_type
  vpc_id               = each.value.vpc_id

  storage_type = "cls"
  cloud_log_id = var.flow_log_cls_topic_id

  tags = var.tags

  lifecycle {
    precondition {
      condition     = var.flow_log_cls_topic_id != null
      error_message = "Flow logs need a CLS destination. Set flow_log_cls_topic_id (the logging stack outputs one as cls_audit_topic_id)."
    }
  }
}

# --- 3.1 / 3.4 / 3.5 / 3.6 security group rule baseline --------------------
module "security_group" {
  source   = "../../modules/security_group_baseline"
  for_each = local.sg_set

  security_group_id   = each.value.security_group_id
  ingress             = each.value.ingress
  egress              = each.value.egress
  allow_empty_ingress = each.value.allow_empty_ingress

  enabled_controls    = var.enabled_controls
  world_cidrs         = var.world_cidrs
  remote_access_ports = var.remote_access_ports
  max_port_range_span = var.max_port_range_span
}

# --- 3.7 Ensure a CLB security group isolates public network traffic -------
resource "tencentcloud_security_group" "clb_edge" {
  count = local.clb_wanted ? 1 : 0

  name        = var.clb_security_group_name
  description = "CIS 3.7 - dedicated edge security group for public CLB traffic"
  tags        = var.tags
}

module "clb_edge_rules" {
  source = "../../modules/security_group_baseline"
  count  = local.clb_wanted ? 1 : 0

  security_group_id = tencentcloud_security_group.clb_edge[0].id
  ingress           = var.clb_ingress
  egress            = var.clb_egress

  enabled_controls    = var.enabled_controls
  world_cidrs         = var.world_cidrs
  remote_access_ports = var.remote_access_ports
  max_port_range_span = var.max_port_range_span
}

resource "tencentcloud_clb_security_group_attachment" "this" {
  count = local.clb_wanted ? 1 : 0

  security_group    = tencentcloud_security_group.clb_edge[0].id
  load_balancer_ids = var.clb_instance_ids

  depends_on = [module.clb_edge_rules]
}

check "cis_registry_alignment" {
  assert {
    condition = length(setsubtract(var.enabled_controls, local.implemented)) == 0
    error_message = format(
      "controls.yml routes %s to the network stack but main.tf does not implement it.",
      join(", ", setsubtract(var.enabled_controls, local.implemented))
    )
  }
}

check "cis_targets_present" {
  assert {
    condition     = !local.flow_logs_wanted || length(var.flow_log_targets) > 0
    error_message = "CIS 2.4 / 3.2 selected but flow_log_targets is empty - no flow logs were created."
  }

  assert {
    condition     = !local.sg_controls_wanted || length(var.security_groups) > 0
    error_message = "CIS 3.1 / 3.4 / 3.5 / 3.6 selected but security_groups is empty - no rules were evaluated."
  }

  assert {
    condition     = !local.on["3.7"] || length(var.clb_instance_ids) > 0
    error_message = "CIS 3.7 selected but clb_instance_ids is empty - no load balancer was isolated."
  }
}
