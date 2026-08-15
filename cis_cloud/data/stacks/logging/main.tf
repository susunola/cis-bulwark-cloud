########################################################################
# Stack: logging
#
# CIS 2.1, 2.2, 2.3, 2.5, 2.9 - 2.19, 2.20.
#
# 2.4 lives in the network stack: it is the same "enable flow logs"
# recommendation as 3.2, and two stacks creating the same flow log is worse
# than one stack owning it.
#
# 2.6 (WAF), 2.7 (Cloud Firewall) and 2.8 (CSC log analysis) have no provider
# resources and are reported as MANUAL by controls.yml.
########################################################################

locals {
  implemented = [
    "2.1", "2.2", "2.3", "2.5",
    "2.9", "2.10", "2.11", "2.12", "2.13", "2.14",
    "2.15", "2.16", "2.17", "2.18", "2.19", "2.20",
  ]

  on     = { for id in local.implemented : id => contains(var.enabled_controls, id) }
  active = [for id in local.implemented : id if local.on[id]]

  alarm_controls = ["2.9", "2.10", "2.11", "2.12", "2.13", "2.14", "2.15", "2.16", "2.17", "2.18", "2.19"]
  alarms_wanted  = anytrue([for id in local.alarm_controls : local.on[id]])

  # ---- CLS plumbing -------------------------------------------------------
  # A logset/topic is needed by 2.3 itself, by 2.20 (retention lives on the
  # topic) and by every alarm in 2.9-2.19 because they query that topic.
  cls_wanted = local.on["2.3"] || local.on["2.5"] || local.on["2.20"] || local.alarms_wanted

  create_logset = local.cls_wanted && var.cls_logset_id == null && var.cls_topic_id == null
  create_topic  = local.cls_wanted && var.cls_topic_id == null

  logset_id = local.create_logset ? tencentcloud_cls_logset.audit[0].id : var.cls_logset_id
  topic_id  = local.create_topic ? tencentcloud_cls_topic.audit[0].id : var.cls_topic_id

  # ---- 2.9 - 2.19 default alarm queries -----------------------------------
  # CloudAudit -> CLS standard field mapping. Override per control with
  # var.alarm_overrides after checking the field names on your own topic.
  default_alarms = {
    "2.9" = {
      name  = "cam-role-change"
      query = "eventName:\"CreateRole\" OR eventName:\"DeleteRole\" OR eventName:\"UpdateRoleDescription\" OR eventName:\"UpdateAssumeRolePolicy\" OR eventName:\"AttachRolePolicy\" OR eventName:\"DetachRolePolicy\""
    }
    "2.10" = {
      name  = "cloud-firewall-change"
      query = "eventSource:\"cfw.tencentcloudapi.com\" AND (eventName:\"ModifyTableStatus\" OR eventName:\"CreateAcRules\" OR eventName:\"DeleteAcRule\" OR eventName:\"ModifyAcRule\" OR eventName:\"ModifySecurityGroupRule\")"
    }
    "2.11" = {
      name  = "vpc-route-change"
      query = "eventName:\"CreateRoutes\" OR eventName:\"DeleteRoutes\" OR eventName:\"ReplaceRoutes\" OR eventName:\"ReplaceRouteTableAssociation\" OR eventName:\"ModifyRouteTableAttribute\" OR eventName:\"CreateRouteTable\" OR eventName:\"DeleteRouteTable\""
    }
    "2.12" = {
      name  = "vpc-change"
      query = "eventName:\"CreateVpc\" OR eventName:\"DeleteVpc\" OR eventName:\"ModifyVpcAttribute\" OR eventName:\"CreateSubnet\" OR eventName:\"DeleteSubnet\" OR eventName:\"ModifySubnetAttribute\" OR eventName:\"CreateVpcPeeringConnection\" OR eventName:\"DeleteVpcPeeringConnection\""
    }
    "2.13" = {
      name  = "cos-permission-change"
      query = "eventSource:\"cos.tencentcloudapi.com\" AND (eventName:\"PutBucketAcl\" OR eventName:\"PutObjectAcl\" OR eventName:\"PutBucketReferer\")"
    }
    "2.14" = {
      name  = "cdb-config-change"
      query = "eventSource:\"cdb.tencentcloudapi.com\" AND (eventName:\"ModifyDBInstanceSpec\" OR eventName:\"ModifyInstanceParam\" OR eventName:\"ModifyDBInstanceSecurityGroups\" OR eventName:\"OpenWanService\" OR eventName:\"CloseWanService\" OR eventName:\"ModifyBackupConfig\" OR eventName:\"IsolateDBInstance\")"
    }
    "2.15" = {
      name  = "console-login-without-mfa"
      query = "eventName:\"Login\" AND mfaUsed:\"NO\""
    }
    "2.16" = {
      name  = "root-account-usage"
      query = "userIdentity.type:\"root\""
    }
    "2.17" = {
      name  = "kms-cmk-disable-or-delete"
      query = "eventSource:\"kms.tencentcloudapi.com\" AND (eventName:\"DisableKey\" OR eventName:\"ScheduleKeyDeletion\" OR eventName:\"ArchiveKey\" OR eventName:\"DisableKeyRotation\")"
    }
    "2.18" = {
      name  = "cos-bucket-policy-change"
      query = "eventSource:\"cos.tencentcloudapi.com\" AND (eventName:\"PutBucketPolicy\" OR eventName:\"DeleteBucketPolicy\")"
    }
    "2.19" = {
      name  = "security-group-change"
      query = "eventName:\"CreateSecurityGroup\" OR eventName:\"DeleteSecurityGroup\" OR eventName:\"CreateSecurityGroupPolicies\" OR eventName:\"DeleteSecurityGroupPolicies\" OR eventName:\"ModifySecurityGroupPolicies\" OR eventName:\"ReplaceSecurityGroupPolicy\""
    }
  }

  alarms = merge(local.default_alarms, var.alarm_overrides)

  # ---- controls selected but out of reach in this configuration -----------
  unreachable = compact([
    local.on["2.20"] && !local.create_topic ? "2.20" : "",
    local.on["2.1"] && var.audit_track_storage == null ? "2.1" : "",
    local.on["2.2"] && var.cloudaudit_cos_bucket == null ? "2.2" : "",
    local.on["2.5"] && var.edgeone_log_delivery == null ? "2.5" : "",
  ])
}

# --- 2.3 Ensure audit logs are integrated with Cloud Log Service -----------
resource "tencentcloud_cls_logset" "audit" {
  count = local.create_logset ? 1 : 0

  logset_name = var.cls_logset_name
  tags        = var.tags
}

# --- 2.3 + 2.20 (retention lives on the topic) -----------------------------
resource "tencentcloud_cls_topic" "audit" {
  count = local.create_topic ? 1 : 0

  logset_id  = local.logset_id
  topic_name = var.cls_topic_name
  describes  = "CIS 2.3 / 2.20 - CloudAudit stream with enforced retention"

  # CIS 2.20: 365 days minimum, -1 for permanent.
  period = local.on["2.20"] ? var.cls_retention_days : null

  partition_count      = var.cls_partition_count
  auto_split           = var.cls_auto_split
  max_split_partitions = var.cls_max_split_partitions
  storage_type         = "hot"

  tags = var.tags

  lifecycle {
    precondition {
      condition     = local.logset_id != null
      error_message = "A CLS topic needs a logset. Either let this stack create one or set cls_logset_id."
    }
  }
}

# --- 2.1 Ensure CloudAudit exports all operational log records -------------
resource "tencentcloud_audit_track" "this" {
  count = local.on["2.1"] && var.audit_track_storage != null ? 1 : 0

  name                  = var.audit_track_name
  action_type           = var.audit_track_action_type
  resource_type         = var.audit_track_resource_type
  event_names           = var.audit_track_event_names
  status                = 1
  track_for_all_members = var.audit_track_for_all_members

  storage {
    storage_type   = var.audit_track_storage.storage_type
    storage_name   = var.audit_track_storage.storage_name
    storage_prefix = var.audit_track_storage.storage_prefix
    storage_region = var.audit_track_storage.storage_region
    compress       = var.audit_track_storage.compress
  }

  depends_on = [tencentcloud_cls_topic.audit]
}

# --- 2.2 Ensure the CloudAudit COS bucket is not publicly accessible -------
module "cloudaudit_bucket" {
  source = "../../modules/cos_secure_bucket"
  count  = local.on["2.2"] && var.cloudaudit_cos_bucket != null ? 1 : 0

  bucket = var.cloudaudit_cos_bucket
  region = var.region
  app_id = var.app_id

  # The audit bucket usually predates this project, so policy-only.
  manage_bucket = false
  manage_policy = true

  # 4.5 is the "deny anonymous" statement; borrowing it is what makes 2.2 true.
  enabled_controls = ["4.5"]
}

# --- 2.5 Ensure EdgeOne log service is enabled -----------------------------
resource "tencentcloud_teo_realtime_log_delivery" "edgeone" {
  count = local.on["2.5"] && var.edgeone_log_delivery != null ? 1 : 0

  zone_id     = var.edgeone_log_delivery.zone_id
  task_name   = var.edgeone_log_delivery.task_name
  task_type   = var.edgeone_log_delivery.task_type
  entity_list = var.edgeone_log_delivery.entity_list
  log_type    = var.edgeone_log_delivery.log_type
  area        = var.edgeone_log_delivery.area
  fields      = var.edgeone_log_delivery.fields
  sample      = var.edgeone_log_delivery.sample

  delivery_status = "enabled"

  cls {
    log_set_id     = coalesce(var.edgeone_log_delivery.cls_logset_id, local.logset_id)
    topic_id       = coalesce(var.edgeone_log_delivery.cls_topic_id, local.topic_id)
    log_set_region = coalesce(var.edgeone_log_delivery.cls_logset_region, var.region)
  }

  depends_on = [tencentcloud_cls_topic.audit]
}

# --- 2.9 - 2.19 log monitoring and alerts ----------------------------------
module "alarms" {
  source = "../../modules/cls_audit_alarm"
  count  = local.alarms_wanted ? 1 : 0

  logset_id = local.logset_id
  topic_id  = local.topic_id

  enabled_controls = var.enabled_controls
  alarms           = local.alarms

  alarm_notice_ids = var.alarm_notice_ids
  notice_receivers = var.alarm_notice_receivers

  alarm_period           = var.alarm_period_minutes
  monitor_period_minutes = var.alarm_monitor_period_minutes
  lookback_minutes       = var.alarm_lookback_minutes
  alarm_level            = var.alarm_level

  tags = var.tags

  depends_on = [tencentcloud_cls_topic.audit]
}

check "cis_registry_alignment" {
  assert {
    condition = length(setsubtract(var.enabled_controls, local.implemented)) == 0
    error_message = format(
      "controls.yml routes %s to the logging stack but main.tf does not implement it.",
      join(", ", setsubtract(var.enabled_controls, local.implemented))
    )
  }
}

check "cls_topic_requires_logset" {
  assert {
    condition     = var.cls_topic_id == null || var.cls_logset_id != null
    error_message = "cls_topic_id is set but cls_logset_id is null. Reusing a topic requires the logset it belongs to."
  }
}

check "cis_targets_present" {
  assert {
    condition = length(local.unreachable) == 0
    error_message = format(
      "selected but not configured, so nothing was enforced: %s. See tfvars/base.tfvars.",
      join(", ", local.unreachable)
    )
  }

  assert {
    condition     = !local.alarms_wanted || length(var.alarm_notice_ids) > 0 || length(var.alarm_notice_receivers) > 0
    error_message = "CIS 2.9-2.19 selected but no alert destination. Set alarm_notice_ids or alarm_notice_receivers."
  }
}
