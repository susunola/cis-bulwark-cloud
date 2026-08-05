########################################################################
# Stack: kubernetes - Tencent Kubernetes Engine
#
# CIS 6.2, 6.7, 6.9.
#
# Not here, on purpose:
#   6.1  Cluster Audit          - only settable through the cluster_audit block
#                                 of tencentcloud_kubernetes_cluster. Enforcing
#                                 it on a live cluster means importing the whole
#                                 cluster into this state file. MANUAL.
#   6.3  RBAC                   - on by default and not exposed as a resource.
#   6.4  cluster health check   - no provider resource.
#   6.5  Dashboard not enabled  - no provider resource.
#   6.6  Basic auth not enabled - no provider resource.
#   6.8  VPC-CNI mode           - a creation time network mode. Detected by the
#                                 audit stack, never rewritten: switching CNI
#                                 re-IPs every pod in the cluster.
########################################################################

locals {
  implemented = ["6.2", "6.7", "6.9"]

  on     = { for id in local.implemented : id => contains(var.enabled_controls, id) }
  active = [for id in local.implemented : id if local.on[id]]

  any_selected = length(local.active) > 0
  has_targets  = length(var.clusters) > 0

  # ---- 6.2 monitoring ------------------------------------------------------
  tmp_of = {
    for id, cfg in var.clusters :
    id => cfg.prometheus_instance_id != null ? cfg.prometheus_instance_id : var.prometheus_instance_id
  }

  monitor_targets = local.on["6.2"] ? {
    for id, cfg in var.clusters : id => cfg if local.tmp_of[id] != null
  } : {}

  clusters_without_tmp = [for id, tmp in local.tmp_of : id if tmp == null]

  # ---- 6.7 network policy --------------------------------------------------
  network_policy_targets = local.on["6.7"] ? var.clusters : {}

  # ---- 6.9 public API server -----------------------------------------------
  endpoint_targets = local.on["6.9"] && var.manage_cluster_endpoint ? var.clusters : {}

  # ---- selected but out of reach -------------------------------------------
  unreachable = sort(distinct(concat(
    local.has_targets ? [] : local.active,
    local.on["6.2"] && length(local.clusters_without_tmp) > 0 ? ["6.2"] : [],
    local.on["6.9"] && !var.manage_cluster_endpoint ? ["6.9"] : [],
  )))
}

# --- 6.2 Ensure Cloud Monitoring is enabled --------------------------------
# Registering the cluster with a managed Prometheus instance is what "cloud
# monitoring enabled" means in TKE terms. One resource per cluster: the agents
# block takes exactly one entry.
resource "tencentcloud_monitor_tmp_tke_cluster_agent" "this" {
  for_each = local.monitor_targets

  instance_id = local.tmp_of[each.key]

  agents {
    cluster_id      = each.key
    cluster_type    = each.value.cluster_type
    region          = var.region
    enable_external = var.monitor_enable_external

    open_default_record = var.monitor_open_default_record
  }
}

# --- 6.7 Ensure Network policy is enabled ----------------------------------
resource "tencentcloud_kubernetes_addon" "network_policy" {
  for_each = local.network_policy_targets

  cluster_id = each.key
  addon_name = var.network_policy_addon_name

  addon_version = each.value.network_policy_version != null ? each.value.network_policy_version : var.network_policy_version
  raw_values    = each.value.network_policy_raw_values != null ? each.value.network_policy_raw_values : var.network_policy_raw_values
}

# --- 6.9 Ensure the API server is not reachable from the internet ----------
# This resource owns both endpoints of the cluster. Disabling the public one
# without a private one in place would cut off kubectl entirely, so the private
# endpoint is a precondition rather than an afterthought.
resource "tencentcloud_kubernetes_cluster_endpoint" "this" {
  for_each = local.endpoint_targets

  cluster_id = each.key

  cluster_internet = false
  cluster_intranet = each.value.cluster_intranet

  cluster_intranet_subnet_id = each.value.cluster_intranet_subnet_id
  cluster_intranet_domain    = each.value.cluster_intranet_domain

  # Only meaningful while the public endpoint is on; kept so that excluding 6.9
  # from a run does not silently widen an existing allow list.
  managed_cluster_internet_security_policies = var.cluster_internet_security_policies

  lifecycle {
    precondition {
      condition     = each.value.cluster_intranet
      error_message = "CIS 6.9 would close the public API server of ${each.key} while cluster_intranet is false, leaving no way in. Set cluster_intranet = true, or exclude ${each.key} from var.clusters."
    }

    precondition {
      condition     = !each.value.cluster_intranet || each.value.cluster_intranet_subnet_id != null
      error_message = "The private API server endpoint for ${each.key} needs cluster_intranet_subnet_id."
    }
  }
}

check "cis_registry_alignment" {
  assert {
    condition = length(setsubtract(var.enabled_controls, local.implemented)) == 0
    error_message = format(
      "controls.yml routes %s to the kubernetes stack but main.tf does not implement it.",
      join(", ", setsubtract(var.enabled_controls, local.implemented))
    )
  }
}

check "cis_targets_present" {
  assert {
    condition = !local.any_selected || local.has_targets
    error_message = format(
      "CIS %s selected but var.clusters is empty, so nothing was hardened. See tfvars/base.tfvars.",
      join(", ", local.active)
    )
  }

  assert {
    condition = length(local.unreachable) == 0
    error_message = format(
      "selected but out of reach: %s. No Prometheus instance for %s; manage_cluster_endpoint is %s.",
      join(", ", local.unreachable),
      length(local.clusters_without_tmp) > 0 ? join(", ", local.clusters_without_tmp) : "(none)",
      var.manage_cluster_endpoint
    )
  }
}
