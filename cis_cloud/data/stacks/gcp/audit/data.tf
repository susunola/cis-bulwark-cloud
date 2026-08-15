# Read-only inventory. Every data source is gated on the controls it serves,
# so a narrowed `cis scan` only calls the APIs it needs.

locals {
  wanted = toset(var.enabled_controls)

  needs_networks = contains(var.enabled_controls, "3.1")
  needs_sql = length(setintersection(local.wanted, toset([
    "6.1.2", "6.2.1", "6.2.2", "6.2.3", "6.2.4", "6.2.5",
    "6.2.6", "6.2.7", "6.3.1", "6.3.2", "6.3.3", "6.3.4",
    "6.3.5", "6.3.6", "6.3.7", "6.4", "6.5", "6.7", "6.8",
  ]))) > 0
  needs_buckets = length(setintersection(local.wanted, toset(["2.4", "5.1"]))) > 0
  needs_bq      = contains(var.enabled_controls, "7.1")
  needs_instances = length(setintersection(local.wanted, toset([
    "4.1", "4.2", "4.3", "4.5", "4.6", "4.8", "4.9", "4.11",
  ]))) > 0
  needs_identity = length(var.enabled_controls) > 0
}

# ---- networks (3.1) ----------------------------------------------------------

data "google_compute_networks" "all" {
  count = local.needs_networks ? 1 : 0
}

# ---- Cloud SQL (6.x) -----------------------------------------------------------

data "google_sql_database_instances" "all" {
  count = local.needs_sql ? 1 : 0
}

data "google_sql_database_instance" "this" {
  for_each = toset(flatten(data.google_sql_database_instances.all[*].instances)[*].name)
  name     = each.key
}

# ---- storage buckets (2.4 / 5.1) ------------------------------------------------

data "google_storage_buckets" "all" {
  count = local.needs_buckets ? 1 : 0
}

data "google_storage_bucket" "this" {
  for_each = toset(concat(
    flatten(data.google_storage_buckets.all[*].buckets)[*].name,
    var.log_export_buckets
  ))
  name = each.key
}

data "google_storage_bucket_iam_policy" "this" {
  for_each = local.needs_buckets ? data.google_storage_bucket.this : {}
  bucket   = each.key
}

# ---- BigQuery (7.1) ------------------------------------------------------------

data "google_bigquery_datasets" "all" {
  count = local.needs_bq ? 1 : 0
}

data "google_bigquery_dataset_iam_policy" "this" {
  for_each = {
    for d in flatten(data.google_bigquery_datasets.all[*].datasets) : d.dataset_id => d.dataset_id
  }
  dataset_id = each.key
}

# ---- compute instances (4.x) ---------------------------------------------------

data "google_compute_instance" "this" {
  for_each = (
    local.needs_instances
    ? { for i in var.compute_instances : i.name => i }
    : {}
  )

  name = each.key
  zone = each.value.zone
}

# ---- project identity -----------------------------------------------------------

data "google_project" "self" {
  count = local.needs_identity ? 1 : 0
}
