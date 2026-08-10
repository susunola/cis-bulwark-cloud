variable "enabled_controls" {
  description = "CIS ids this run may enforce (injected by bin/cis)."
  type        = list(string)
  default     = []
}

# ---- 7.6 Network Watcher -----------------------------------------------------

variable "watcher_locations" {
  description = "CIS 7.6 - Azure regions (locations) that must each have a Network Watcher."
  type        = list(string)
  default     = []
}

variable "watcher_resource_group" {
  description = "CIS 7.6 - resource group the Network Watchers are created in."
  type        = string
  default     = "NetworkWatcherRG"
}

variable "network_watcher_name" {
  description = "CIS 7.6 - name prefix for the Network Watcher per region."
  type        = string
  default     = "cis-network-watcher"
}

variable "tags" {
  description = "Tags applied to resources this stack creates."
  type        = map(string)
  default     = {}
}
