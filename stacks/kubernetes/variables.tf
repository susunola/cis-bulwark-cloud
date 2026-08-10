variable "enabled_controls" {
  description = "CIS ids this run may enforce, injected from Cis.controls_for_stack(\"kubernetes\")."
  type        = list(string)
  default     = []
}

variable "region" {
  description = "Region the clusters live in. Used when registering the monitoring agent."
  type        = string
  default     = "ap-guangzhou"
}

variable "clusters" {
  description = <<-EOT
    TKE cluster id -> per-cluster overrides. Every field is optional.

      cls-xxxxxxxx = {}
      cls-yyyyyyyy = { cluster_intranet_subnet_id = "subnet-abc123" }

    List your clusters with:
      tccli tke DescribeClusters
  EOT
  type = map(object({
    cluster_type = optional(string, "tke")

    # 6.9 - the private endpoint that replaces the public one.
    cluster_intranet           = optional(bool, true)
    cluster_intranet_subnet_id = optional(string)
    cluster_intranet_domain    = optional(string)

    # 6.7 - override the add-on version or values for this cluster.
    network_policy_version    = optional(string)
    network_policy_raw_values = optional(string)

    # 6.2 - override the monitoring target for this cluster.
    prometheus_instance_id = optional(string)
  }))
  default = {}

  validation {
    condition     = alltrue([for id, _ in var.clusters : can(regex("^cls-[0-9a-z]+$", id))])
    error_message = "keys of clusters must be TKE cluster ids like 'cls-abcd1234'."
  }

  validation {
    condition     = alltrue([for _, c in var.clusters : contains(["tke", "eks"], c.cluster_type)])
    error_message = "cluster_type must be 'tke' or 'eks'."
  }
}

# --- 6.2  cloud monitoring --------------------------------------------------

variable "prometheus_instance_id" {
  description = <<-EOT
    CIS 6.2. Managed Prometheus (TMP) instance the clusters report into. This is
    the monitoring backend TKE actually attaches to; without one there is
    nothing to enable.

      tccli monitor DescribePrometheusInstances
  EOT
  type        = string
  default     = null
}

variable "monitor_enable_external" {
  description = "Let the monitoring agent reach the TMP instance over the public network. Keep false."
  type        = bool
  default     = false
}

variable "monitor_open_default_record" {
  description = "Install the default Prometheus recording rules along with the agent."
  type        = bool
  default     = true
}

# --- 6.7  network policy ----------------------------------------------------

variable "network_policy_addon_name" {
  description = <<-EOT
    CIS 6.7. Name of the TKE add-on that provides NetworkPolicy. Confirm the
    exact spelling for your cluster version before applying:

      tccli tke DescribeAddonValues --ClusterId cls-xxxxxxxx --AddonName NetworkPolicy
  EOT
  type        = string
  default     = "NetworkPolicy"
}

variable "network_policy_version" {
  description = "Add-on version. Null lets TKE pick the default for the cluster version."
  type        = string
  default     = null
}

variable "network_policy_raw_values" {
  description = "JSON values passed to the add-on. Null uses the TKE defaults."
  type        = string
  default     = null
}

# --- 6.9  cluster internet access ------------------------------------------

variable "manage_cluster_endpoint" {
  description = <<-EOT
    CIS 6.9. tencentcloud_kubernetes_cluster_endpoint owns the API server
    endpoints of a cluster, so this stack will disable the public one and, by
    default, make sure a private one exists.

    If a cluster already has endpoints configured, import them first:

      terraform -chdir=stacks/kubernetes import 'tencentcloud_kubernetes_cluster_endpoint.this["cls-abcd1234"]' cls-abcd1234

    Set this to false to report 6.9 as unreachable rather than have Terraform
    take ownership of the endpoint.
  EOT
  type        = bool
  default     = true
}

variable "cluster_internet_security_policies" {
  description = <<-EOT
    Source CIDRs allowed to reach the public API server, applied only if you
    deliberately exclude 6.9 from the run and leave the public endpoint on.
  EOT
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags applied to resources created by this stack."
  type        = map(string)
  default     = { "managed-by" = "cis" }
}
