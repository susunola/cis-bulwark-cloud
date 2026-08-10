########################################################################
# Stack: logging
#
# CIS section 2 (Logging). 2.1 writes the project audit config for the
# admin/data services, 2.3 creates a project log sink.
########################################################################

locals {
  implemented = ["2.1", "2.3"]

  on     = { for id in local.implemented : id => contains(var.enabled_controls, id) }
  active = [for id in local.implemented : id if local.on[id]]
}

# --- 2.1 Cloud Audit Logging configured properly ------------------------------
# Admin-read and data-read/write for every service in var.audit_services.
resource "google_project_iam_audit_config" "cis" {
  count   = local.on["2.1"] ? 1 : 0
  service = var.audit_service
  project = var.project_id

  audit_log_config {
    log_type = "ADMIN_READ"
  }
  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}

# --- 2.3 sink for all log entries ---------------------------------------------
resource "google_logging_project_sink" "cis" {
  count = local.on["2.3"] ? 1 : 0

  name                   = var.sink_name
  destination            = var.sink_destination
  filter                 = "LOG_ID(\\\"cloudaudit.googleapis.com/activity\\\") OR LOG_ID(\\\"cloudaudit.googleapis.com/data_access\\\")"
  unique_writer_identity = true
}

check "cis_registry_alignment" {
  assert {
    condition = length(setsubtract(var.enabled_controls, local.implemented)) == 0
    error_message = format(
      "controls.yml routes %s to the gcp logging stack but main.tf does not implement it.",
      join(", ", setsubtract(var.enabled_controls, local.implemented))
    )
  }
}

check "cis_targets_present" {
  assert {
    condition = (
      (!local.on["2.1"] || var.audit_service != "") &&
      (!local.on["2.3"] || var.sink_destination != "")
    )
    error_message = "a selected control needs operator-supplied variables - nothing was hardened."
  }
}
