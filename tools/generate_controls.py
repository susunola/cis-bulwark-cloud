#!/usr/bin/env python3
"""Regenerate config/<cloud>/controls.yml from a benchmark catalog + mapping.

Two inputs are combined:

1. benchmarks/<cloud>/catalog.json - facts extracted from the CIS PDF (id,
   title, assessment, profile). Produced by tools/extract_benchmark.py.
   Never hand-edited.
2. <CLOUD>_MAPPING below       - how each control maps onto the cloud's
   Terraform provider. Derived from `terraform providers schema -json` and
   hand-verified.

`remediate` / `detect` values:
    terraform  - a provider resource / data source really exists for this
    none       - the provider has no support; the control is reported as MANUAL

`remediate` is terraform only when apply can produce a real hardening action
without deleting user-owned resources or forcing a destructive replacement
(importing an existing resource is an operator prerequisite, documented in the
stack variables). `detect` is terraform only when an enumerable data source
exists - a data source you must already know the name/arn of does not count.

Run:  python3 tools/generate_controls.py            # tencent
      python3 tools/generate_controls.py --cloud aws
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

T, N = "terraform", "none"

# ---- tencentcloudstack/tencentcloud ~> 1.81 ---------------------------------

TENCENT_MAPPING = {
    # ---- 1 Identity and Access Management -------------------------------
    # No CAM password-policy resource or data source exists in the provider
    # (searched: password / account_setting / security_polic / login_policy).
    "1.1":  (N, N, None, ["root", "governance"]),
    "1.2":  (N, N, None, ["root", "access-key"]),
    "1.3":  (N, N, None, ["root", "mfa"]),
    "1.4":  (T, N, "iam", ["mfa", "cam-user"]),
    "1.5":  (N, N, None, ["cam-user", "lifecycle"]),
    "1.6":  (N, N, None, ["access-key", "rotation"]),
    "1.7":  (N, N, None, ["password-policy"]),
    "1.8":  (N, N, None, ["password-policy"]),
    "1.9":  (N, N, None, ["password-policy"]),
    "1.10": (N, N, None, ["password-policy"]),
    "1.11": (N, N, None, ["password-policy"]),
    "1.12": (N, N, None, ["password-policy"]),
    "1.13": (N, N, None, ["password-policy"]),
    "1.14": (N, N, None, ["password-policy", "lockout"]),
    "1.15": (N, T, "iam", ["cam-policy", "least-privilege"]),
    "1.16": (N, T, "iam", ["cam-policy", "attachment"]),

    # ---- 2 Logging and Monitoring ---------------------------------------
    "2.1":  (T, T, "logging", ["cloudaudit"]),
    "2.2":  (T, T, "logging", ["cloudaudit", "cos", "public-access"]),
    "2.3":  (T, T, "logging", ["cls"]),
    # 2.4 and 3.2 are the same recommendation, printed once in section 2 and
    # once in section 3 ("Ensure virtual network flow log service is enabled").
    # Both are pinned to the network stack so one tencentcloud_vpc_flow_log set
    # satisfies them, instead of two stacks fighting over the same resource.
    "2.4":  (T, N, "network", ["flow-log", "vpc"]),
    "2.5":  (T, N, "logging", ["edgeone"]),
    "2.6":  (N, N, None, ["waf"]),
    "2.7":  (N, N, None, ["cloud-firewall"]),
    "2.8":  (N, N, None, ["csc", "log-analysis"]),
    "2.9":  (T, N, "logging", ["alarm", "cam-role"]),
    "2.10": (T, N, "logging", ["alarm", "cloud-firewall"]),
    "2.11": (T, N, "logging", ["alarm", "route"]),
    "2.12": (T, N, "logging", ["alarm", "vpc"]),
    "2.13": (T, N, "logging", ["alarm", "cos"]),
    "2.14": (T, N, "logging", ["alarm", "cdb"]),
    "2.15": (T, N, "logging", ["alarm", "mfa", "console"]),
    "2.16": (T, N, "logging", ["alarm", "root"]),
    "2.17": (T, N, "logging", ["alarm", "kms"]),
    "2.18": (T, N, "logging", ["alarm", "cos"]),
    "2.19": (T, N, "logging", ["alarm", "security-group"]),
    "2.20": (T, T, "logging", ["cls", "retention"]),

    # ---- 3 Networking -----------------------------------------------------
    "3.1":  (T, T, "network", ["security-group", "remote-access"]),
    "3.2":  (T, N, "network", ["flow-log", "vpc"]),
    "3.3":  (N, T, "network", ["route", "peering", "least-access"]),
    "3.4":  (T, T, "network", ["security-group", "fine-grained"]),
    "3.5":  (T, T, "network", ["security-group", "ssh", "ingress"]),
    "3.6":  (T, T, "network", ["security-group", "rdp", "ingress"]),
    "3.7":  (T, N, "network", ["clb", "security-group"]),

    # ---- 4 Storage --------------------------------------------------------
    "4.1":  (T, T, "storage", ["cos", "public-access"]),
    "4.2":  (N, T, "storage", ["cos", "public-access", "object"]),
    "4.3":  (T, N, "storage", ["cos", "logging"]),
    "4.4":  (T, N, "storage", ["cos", "tls", "bucket-policy"]),
    "4.5":  (T, N, "storage", ["cos", "network-acl", "bucket-policy"]),
    "4.6":  (T, N, "storage", ["cos", "encryption", "sse-cos"]),
    "4.7":  (T, N, "storage", ["cos", "encryption", "sse-kms"]),
    "4.8":  (N, T, "storage", ["cbs", "encryption", "unattached"]),
    "4.9":  (N, T, "storage", ["cbs", "encryption", "cvm"]),

    # ---- 5 TencentDB for MySQL -------------------------------------------
    "5.1":  (T, N, "database", ["mysql", "ssl"]),
    "5.2":  (T, T, "database", ["mysql", "public-access"]),
    "5.3":  (T, N, "database", ["mysql", "audit"]),
    "5.4":  (T, N, "database", ["mysql", "audit", "retention"]),
    "5.5":  (T, N, "database", ["mysql", "tde", "encryption"]),
    "5.6":  (T, N, "database", ["mysql", "tde", "byok", "kms"]),

    # ---- 6 Kubernetes Engine ---------------------------------------------
    # Cluster Audit is only settable through the `cluster_audit` block of
    # tencentcloud_kubernetes_cluster. There is no standalone resource, so
    # hardening an *existing* cluster would mean importing the whole cluster
    # into state - unacceptable blast radius for a compliance tool. MANUAL.
    "6.1":  (N, N, None, ["tke", "audit"]),
    "6.2":  (T, N, "kubernetes", ["tke", "monitoring"]),
    "6.3":  (N, N, None, ["tke", "rbac"]),
    "6.4":  (N, N, None, ["tke", "health-check"]),
    "6.5":  (N, N, None, ["tke", "dashboard"]),
    "6.6":  (N, N, None, ["tke", "basic-auth"]),
    "6.7":  (T, N, "kubernetes", ["tke", "network-policy", "addon"]),
    "6.8":  (N, T, "kubernetes", ["tke", "vpc-cni"]),
    "6.9":  (T, T, "kubernetes", ["tke", "public-access"]),

    # ---- 7 Cloud Security Center -----------------------------------------
    # Provider exposes no SSA/CSC resources (only csip_risk_center).
    "7.1":  (N, N, None, ["csc", "edition"]),
    "7.2":  (N, N, None, ["csc", "api-monitoring"]),
    "7.3":  (N, N, None, ["csc", "multi-account"]),
    "7.4":  (N, N, None, ["csc", "scheduled-check"]),
    "7.5":  (N, N, None, ["csc", "notification"]),
    "7.6":  (N, N, None, ["csc", "log-analysis"]),

    # ---- 8 Cloud Workload Protection Platform ----------------------------
    "8.1":  (N, T, "iam", ["cwpp", "agent"]),
    "8.2":  (N, T, "iam", ["cwpp", "agent", "edition"]),
    "8.3":  (N, N, None, ["cwpp", "app-protection"]),
    "8.4":  (N, N, None, ["cwpp", "self-protection"]),
    "8.5":  (N, N, None, ["cwpp", "notification"]),
    "8.6":  (N, N, None, ["cwpp", "log-analysis"]),

    # ---- 9 Tencent Container Security Service ----------------------------
    "9.1":  (N, N, None, ["tcss", "protection"]),
    "9.2":  (N, N, None, ["tcss", "image-scan"]),
    "9.3":  (N, N, None, ["tcss", "app-protection"]),
    "9.4":  (N, N, None, ["tcss", "agent"]),
    "9.5":  (N, N, None, ["tcss", "image-scan", "schedule"]),
    "9.6":  (N, N, None, ["tcss", "cluster-check"]),
    "9.7":  (N, N, None, ["tcss", "vulnerability"]),
    "9.8":  (N, N, None, ["tcss", "baseline"]),
    "9.9":  (N, N, None, ["tcss", "virus-scan"]),
    "9.10": (N, N, None, ["tcss", "interception"]),
    "9.11": (N, N, None, ["tcss", "notification"]),
    "9.12": (N, N, None, ["tcss", "log-analysis"]),
}

# ---- hashicorp/aws ~> 5.0 ---------------------------------------------------
# detect = an enumerable data source exists (aws_instances, aws_db_instances,
# aws_security_groups, aws_vpc_security_group_rules, aws_ebs_encryption_by_default).
# remediate = a resource exists and apply does not delete user resources or
# force a destructive replacement (importing existing resources is a documented
# operator prerequisite).
AWS_MAPPING = {
    # ---- 2 Identity and Access Management -------------------------------
    # Organizations governance (2.1.x) is a human judgement - Terraform can
    # read structure but not decide if it is "correct".
    "2.1.1": (N, N, None, ["orgs", "governance"]),
    "2.1.2": (N, N, None, ["orgs", "guardrails"]),
    "2.1.3": (N, N, None, ["orgs", "root-usage"]),
    "2.1.4": (N, N, None, ["orgs", "ou-structure"]),
    "2.1.5": (N, N, None, ["orgs", "delegated-admin"]),
    "2.1.6": (N, N, None, ["orgs", "delegated-admin"]),
    "2.2":   (N, N, None, ["account", "contact"]),
    "2.3":   (N, N, None, ["account", "security-contact"]),
    # No data source exposes root-user access keys or MFA state.
    "2.4":   (N, N, None, ["root", "access-key"]),
    "2.5":   (N, N, None, ["root", "mfa"]),
    "2.6":   (N, N, None, ["root", "mfa", "hardware"]),
    "2.7":   (N, N, None, ["root", "usage"]),
    # aws_iam_account_password_policy resource writes the account policy; the
    # provider has no data source for it, so detect stays none.
    "2.8":   (T, N, "iam", ["password-policy", "length"]),
    "2.9":   (T, N, "iam", ["password-policy", "reuse"]),
    # No data source exposes per-user MFA or login-profile state.
    "2.10":  (N, N, None, ["mfa", "console-password"]),
    # aws_iam_access_keys returns ids only - no create/last-used dates.
    "2.11":  (N, N, None, ["access-key", "unused"]),
    "2.12":  (N, N, None, ["access-key", "rotation"]),
    # No way to enumerate direct (non-group) user policy attachments.
    "2.13":  (N, N, None, ["iam", "groups-only"]),
    # aws_iam_policy reads one known policy; there is no aws_iam_policies list.
    "2.14":  (N, N, None, ["iam", "admin-policy"]),
    "2.15":  (N, N, None, ["iam", "support-role"]),
    # aws_instances + aws_instance.iam_instance_profile: every instance must
    # carry a role. Remediation would mean attaching roles to existing
    # instances - destructive, reported instead.
    "2.16":  (N, T, "iam", ["iam", "instance-role"]),
    # aws_iam_server_certificate reads one named cert; no list source.
    "2.17":  (N, N, None, ["iam", "certificate"]),
    # aws_accessanalyzer_analyzer resource creates the analyzer; no data source
    # to detect it (existing analyzers need import).
    "2.18":  (T, N, "iam", ["analyzer", "iam"]),
    "2.19":  (N, N, None, ["iam", "federation"]),
    "2.20":  (N, N, None, ["iam", "cloudshell"]),

    # ---- 3 Storage ---------------------------------------------------------
    # aws_s3_bucket_policy resource can enforce the deny-HTTP statement on
    # operator-listed buckets; there is no aws_s3_buckets list to scan from.
    "3.1.1": (T, N, "storage", ["s3", "tls", "bucket-policy"]),
    "3.1.2": (N, N, None, ["s3", "mfa-delete"]),
    "3.1.3": (N, N, None, ["s3", "discovery"]),
    # aws_db_instances + aws_db_instance: encryption is settable but flipping
    # storage_encrypted on an existing instance forces replacement - report.
    "3.2.1": (N, T, "database", ["rds", "encryption"]),
    "3.2.2": (T, T, "database", ["rds", "minor-upgrade"]),
    "3.2.3": (T, T, "database", ["rds", "public-access"]),

    # ---- 4 Logging ---------------------------------------------------------
    # No aws_cloudtrail data source; multi-region judgement is manual.
    "4.1":   (N, N, None, ["cloudtrail", "multi-region"]),
    # aws_cloudtrail resource updates enable_log_file_validation in place;
    # an existing trail must be imported first.
    "4.2":   (T, N, "logging", ["cloudtrail", "validation"]),
    # No data source for the recorder; standing it up needs role + delivery
    # channel - out of scope for this tool.
    "4.3":   (N, N, None, ["config", "recorder"]),
    "4.4":   (N, N, None, ["cloudtrail", "s3-logging"]),
    "4.5":   (N, N, None, ["cloudtrail", "kms"]),
    # aws_kms_key rotation needs the operator to hand over every CMK arn;
    # no aws_kms_keys list source exists to detect against.
    "4.6":   (N, N, None, ["kms", "rotation"]),
    # No flow-log data source; creating flow logs needs VPC + role wiring.
    "4.7":   (N, N, None, ["flow-log", "vpc"]),
    "4.8":   (N, N, None, ["cloudtrail", "object-write"]),
    "4.9":   (N, N, None, ["cloudtrail", "object-read"]),

    # ---- 5 Monitoring ------------------------------------------------------
    # All 5.x are CloudWatch alarm policies - Terraform could create alarms,
    # but "is monitored" is an operational decision, not a resource state.
    "5.1":   (N, N, None, ["monitoring", "unauthorized-api"]),
    "5.2":   (N, N, None, ["monitoring", "console-mfa"]),
    "5.3":   (N, N, None, ["monitoring", "root-usage"]),
    "5.4":   (N, N, None, ["monitoring", "iam-changes"]),
    "5.5":   (N, N, None, ["monitoring", "cloudtrail-changes"]),
    "5.6":   (N, N, None, ["monitoring", "console-auth-failures"]),
    "5.7":   (N, N, None, ["monitoring", "cmk-deletion"]),
    "5.8":   (N, N, None, ["monitoring", "s3-policy-changes"]),
    "5.9":   (N, N, None, ["monitoring", "config-changes"]),
    "5.10":  (N, N, None, ["monitoring", "security-group-changes"]),
    "5.11":  (N, N, None, ["monitoring", "nacl-changes"]),
    "5.12":  (N, N, None, ["monitoring", "network-gateway-changes"]),
    "5.13":  (N, N, None, ["monitoring", "route-table-changes"]),
    "5.14":  (N, N, None, ["monitoring", "vpc-changes"]),
    "5.15":  (N, N, None, ["monitoring", "orgs-changes"]),

    # ---- 6 Networking ------------------------------------------------------
    # Account-level default: aws_ebs_encryption_by_default is both readable
    # and writable, no import needed.
    "6.1.1": (T, T, "storage", ["ebs", "encryption"]),
    "6.1.2": (N, N, None, ["ec2", "cifs"]),
    # aws_network_acls lists ids but there is no single-ACL data source to read
    # rules from.
    "6.2":   (N, N, None, ["nacl", "admin-ports"]),
    # aws_security_groups + aws_vpc_security_group_rules + ..._rule can read
    # every rule; revoking one from an existing group is an import-first
    # operation - detected, not enforced.
    "6.3":   (N, T, "network", ["security-group", "admin-ports", "ipv4"]),
    "6.4":   (N, T, "network", ["security-group", "admin-ports", "ipv6"]),
    "6.5":   (N, T, "network", ["security-group", "default"]),
    "6.6":   (N, N, None, ["vpc", "peering"]),
    # aws_instance.metadata_options.http_tokens readable; changing it on a
    # running instance restarts it - detected, not enforced.
    "6.7":   (N, T, "network", ["ec2", "imdsv2"]),
    "6.8":   (N, N, None, ["vpc", "endpoints"]),
}


# ---- hashicorp/azurerm ~> 4.0 ------------------------------------------------
# azurerm data sources are name-based, not list-based: there is no
# azurerm_network_security_groups / azurerm_storage_accounts enumerator. So
# `detect` means "checkable given operator-supplied inventory" (see the audit
# stack variables); `remediate` means a resource exists and apply does not
# delete user resources or force a destructive replacement.
AZURE_MAPPING = {
    # ---- 2 Analytics (Azure Databricks) ----------------------------------
    # custom_parameters.virtual_network_id non-empty == customer-managed VNet.
    "2.1.1":  (N, T, "databricks", ["databricks", "vnet"]),
    "2.1.2":  (N, N, None, ["databricks", "nsg"]),
    "2.1.3":  (N, N, None, ["databricks", "encryption"]),
    "2.1.4":  (N, N, None, ["databricks", "identity"]),
    "2.1.5":  (N, N, None, ["databricks", "unity-catalog"]),
    "2.1.6":  (N, N, None, ["databricks", "pat"]),
    "2.1.7":  (N, N, None, ["databricks", "diagnostics"]),
    "2.1.8":  (N, N, None, ["databricks", "cmk"]),
    "2.1.9":  (N, T, "databricks", ["databricks", "no-public-ip"]),
    # no_public_ip covers 2.1.9; the workspace data source does not expose a
    # public-network-access flag.
    "2.1.10": (N, N, None, ["databricks", "public-network-access"]),
    "2.1.11": (N, N, None, ["databricks", "private-endpoint"]),

    # ---- 5 Identity --------------------------------------------------------
    # Entra ID security defaults / MFA / directory settings have no surface in
    # the azurerm provider (that is the separate azuread provider).
    "5.1.1":  (N, N, None, ["entra", "security-defaults"]),
    "5.1.2":  (N, N, None, ["entra", "mfa"]),
    "5.1.3":  (N, N, None, ["entra", "mfa"]),
    "5.3.1":  (N, N, None, ["entra", "admin-usage"]),
    "5.3.2":  (N, N, None, ["entra", "guest-review"]),
    "5.3.3":  (N, N, None, ["rbac", "user-access-admin"]),
    "5.3.4":  (N, N, None, ["rbac", "privileged-review"]),
    "5.3.5":  (N, N, None, ["entra", "disabled-accounts"]),
    "5.3.6":  (N, N, None, ["entra", "tenant-creator"]),
    "5.3.7":  (N, N, None, ["rbac", "non-privileged-review"]),
    # Judging "custom administrator role" requires parsing role definitions.
    "5.4":    (N, N, None, ["rbac", "custom-admin-role"]),
    "5.5":    (N, N, None, ["rbac", "resource-lock-role"]),
    "5.6":    (N, N, None, ["entra", "tenant-migration"]),

    # ---- 6 Monitoring ------------------------------------------------------
    "6.1.4":  (N, N, None, ["monitor", "diagnostics"]),
    "6.1.5":  (N, N, None, ["monitor", "sku"]),

    # ---- 7 Networking --------------------------------------------------------
    # NSG rules are read from azurerm_network_security_group for each
    # operator-listed group.
    "7.1":    (N, T, "network", ["nsg", "rdp"]),
    "7.2":    (N, T, "network", ["nsg", "ssh"]),
    "7.3":    (N, T, "network", ["nsg", "udp"]),
    "7.4":    (N, T, "network", ["nsg", "http-https"]),
    # No flow-log data source in azurerm.
    "7.5":    (N, N, None, ["nsg", "flow-log-retention"]),
    # azurerm_network_watcher is created by this stack; one per listed region.
    "7.6":    (T, N, "network", ["network-watcher"]),
    "7.7":    (N, N, None, ["public-ip", "review"]),
    "7.8":    (N, N, None, ["vnet", "flow-log"]),
    "7.9":    (N, N, None, ["vpn", "auth"]),
    # Application Gateway checks read waf_configuration / ssl_policy.
    "7.10":   (N, T, "network", ["waf", "app-gateway"]),
    # Subnet -> NSG association is readable per subnet; wiring every subnet is
    # operator inventory, enforcement would take over the association.
    "7.11":   (N, N, None, ["subnet", "nsg"]),
    "7.12":   (N, T, "network", ["app-gateway", "tls"]),
    # http2_enabled is not exposed by the app gateway data source.
    "7.13":   (N, N, None, ["app-gateway", "http2"]),
    "7.14":   (N, T, "network", ["waf", "body-inspection"]),
    # Bot protection is not exposed by the app gateway data source.
    "7.15":   (N, N, None, ["waf", "bot-protection"]),

    # ---- 8 Defender / Key Vault ---------------------------------------------
    "8.1.10": (N, N, None, ["defender", "vm-updates"]),
    "8.1.11": (N, N, None, ["defender", "mcsb"]),
    "8.1.12": (N, N, None, ["defender", "owner-notify"]),
    # azurerm_security_center_contact resource creates the contact; there is no
    # data source to read it back.
    "8.1.13": (T, N, "security", ["defender", "security-contact"]),
    "8.1.14": (N, N, None, ["defender", "alert-severity"]),
    "8.1.15": (N, N, None, ["defender", "attack-paths"]),
    # Key/secret expiry needs per-key enumeration - no list source.
    "8.3.1":  (N, N, None, ["keyvault", "expiry"]),
    "8.3.2":  (N, N, None, ["keyvault", "expiry"]),
    "8.3.3":  (N, N, None, ["keyvault", "expiry"]),
    "8.3.4":  (N, N, None, ["keyvault", "expiry"]),
    # purge_protection is read-only after creation - detect only.
    "8.3.5":  (N, T, "security", ["keyvault", "purge-protection"]),
    "8.3.6":  (N, T, "security", ["keyvault", "rbac"]),
    "8.3.7":  (N, T, "security", ["keyvault", "public-network"]),
    "8.3.8":  (N, N, None, ["keyvault", "private-endpoint"]),
    "8.3.9":  (N, N, None, ["keyvault", "rotation"]),
    "8.3.10": (N, N, None, ["keyvault", "hsm"]),
    # No list source and a 404 on a missing host aborts the audit - Manual.
    "8.4.1":  (N, N, None, ["bastion", "exists"]),

    # ---- 9 Storage -----------------------------------------------------------
    # File-share soft delete is settable on azurerm_storage_account but not
    # readable back from the data source.
    "9.1.1":  (T, N, "storage", ["storage", "file-share-soft-delete"]),
    "9.1.2":  (N, N, None, ["storage", "smb-version"]),
    "9.2.1":  (T, N, "storage", ["storage", "blob-soft-delete"]),
    "9.2.2":  (T, N, "storage", ["storage", "container-soft-delete"]),
    "9.3.4":  (T, T, "storage", ["storage", "secure-transfer"]),
    # Setting bypass requires flipping the account to Deny-by-default - a
    # network behaviour change this tool should not make silently.
    "9.3.5":  (N, N, None, ["storage", "trusted-microsoft"]),
    "9.3.6":  (T, T, "storage", ["storage", "min-tls"]),
    "9.3.7":  (T, N, "storage", ["storage", "cross-tenant-replication"]),
    "9.3.8":  (T, T, "storage", ["storage", "blob-anonymous"]),
    "9.3.9":  (N, N, None, ["storage", "delete-lock"]),
    "9.3.10": (N, N, None, ["storage", "readonly-lock"]),
    "9.3.11": (T, T, "storage", ["storage", "redundancy"]),
}

CLOUD_CONFIG = {
    "tencent": {
        "mapping": TENCENT_MAPPING,
        "catalog": os.path.join(ROOT, "benchmarks", "tencent", "catalog.json"),
        "out": os.path.join(ROOT, "config", "controls.yml"),
        "section_notes": {
            1: "CAM password policy (1.7-1.11, 1.13) has no Terraform resource - reported as MANUAL.\n  # 1.12 (prevent password reuse) and 1.14 (account lockout) are classified as Automated.",
            7: "Cloud Security Center has no Terraform resources - whole section is MANUAL.",
            9: "TCSS exposes only cluster_access / image_registry - whole section is MANUAL.",
        },
    },
    "aws": {
        "mapping": AWS_MAPPING,
        "catalog": os.path.join(ROOT, "benchmarks", "aws", "catalog.json"),
        "out": os.path.join(ROOT, "config", "aws", "controls.yml"),
        "section_notes": {
            5: "CloudWatch monitoring recommendations are operational decisions, not resource state - whole section is MANUAL.",
        },
    },
    "azure": {
        "mapping": AZURE_MAPPING,
        "catalog": os.path.join(ROOT, "benchmarks", "azure", "catalog.json"),
        "out": os.path.join(ROOT, "config", "azure", "controls.yml"),
        "section_notes": {
            5: "Entra ID settings have no surface in the azurerm provider - whole section is MANUAL.",
        },
    },
}


def yaml_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cloud", choices=sorted(CLOUD_CONFIG), default="tencent")
    args = ap.parse_args(argv)

    cfg = CLOUD_CONFIG[args.cloud]
    with open(cfg["catalog"], encoding="utf-8") as fh:
        catalog = json.load(fh)

    controls = catalog["controls"]
    ids = {c["id"] for c in controls}
    mapped = set(cfg["mapping"])
    if ids != mapped:
        print(f"ERROR: {args.cloud} catalog/mapping mismatch", file=sys.stderr)
        print(f"  missing from MAPPING: {sorted(ids - mapped)}", file=sys.stderr)
        print(f"  extra in MAPPING:     {sorted(mapped - ids)}", file=sys.stderr)
        return 1

    key = lambda k: [int(p) for p in k.split(".")]
    lines = [
        f"# {catalog['benchmark']} {catalog['version']} - control registry",
        "#",
        "# GENERATED by tools/generate_controls.py --cloud "
        + args.cloud
        + " - do not reformat by hand.",
        "# You SHOULD edit the `enabled:` flags; that is what this file is for.",
        "#",
        "# Fields",
        "#   id         CIS recommendation number",
        "#   title      recommendation title, verbatim from the benchmark",
        "#   assessment Automated | Manual  (as classified by CIS)",
        "#   profile    Level 1 | Level 2   (as classified by CIS)",
        "#   enabled    whether this control participates in scan / apply",
        "#   remediate  terraform | none - can `cis apply` enforce it",
        "#   detect     terraform | none - can `cis scan` evaluate it",
        "#   stack      Terraform stack that owns it (null when unsupported)",
        "#   tags       free-form selectors for `cis --tag`",
        "#",
        f"benchmark: \"{catalog['benchmark']}\"",
        f"version: \"{catalog['version']}\"",
        f"released: \"{catalog['date']}\"",
        "",
        "sections:",
    ]
    for sid in sorted(catalog["sections"], key=key):
        lines.append(f'  "{sid}": "{yaml_escape(catalog["sections"][sid])}"')
    lines.append("")
    lines.append("controls:")

    current_section = None
    for c in controls:
        remediate, detect, stack, tags = cfg["mapping"][c["id"]]
        sec = int(c["section"])
        if sec != current_section:
            current_section = sec
            lines.append("")
            lines.append(f"  # === {sec} {catalog['sections'][str(sec)]} ===")
            if sec in cfg["section_notes"]:
                lines.append(f"  # {cfg['section_notes'][sec]}")
        lines.append(f'  - id: "{c["id"]}"')
        lines.append(f'    title: "{yaml_escape(c["title"])}"')
        lines.append(f'    assessment: {c["assessment"]}')
        lines.append(f'    profile: "{c["profile"]}"')
        lines.append(f"    enabled: true")
        lines.append(f"    remediate: {remediate}")
        lines.append(f"    detect: {detect}")
        lines.append(f'    stack: {stack if stack else "null"}')
        lines.append(f'    tags: [{", ".join(tags)}]')

    os.makedirs(os.path.dirname(cfg["out"]), exist_ok=True)
    with open(cfg["out"], "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    n_rem = sum(1 for v in cfg["mapping"].values() if v[0] == T)
    n_det = sum(1 for v in cfg["mapping"].values() if v[1] == T)
    n_man = sum(1 for v in cfg["mapping"].values() if v[0] == N and v[1] == N)
    print(f"wrote {cfg['out']}")
    print(f"  controls        : {len(controls)}")
    print(f"  remediable (tf) : {n_rem}")
    print(f"  detectable (tf) : {n_det}")
    print(f"  manual only     : {n_man}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
