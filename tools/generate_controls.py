#!/usr/bin/env python3
"""Regenerate config/controls.yml.

Two inputs are combined:

1. tools/catalog.json  - facts extracted from the CIS PDF (id, title, assessment,
   profile). Produced by tools/extract_catalog.py. Never hand-edited.
2. MAPPING below       - how each control maps onto the tencentcloud Terraform
   provider. Derived from `terraform providers schema -json` of
   tencentcloudstack/tencentcloud v1.83.19 and hand-verified.

`remediate` / `detect` values:
    terraform  - a provider resource / data source really exists for this
    none       - the provider has no support; the control is reported as MANUAL

Run:  python3 tools/generate_controls.py
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CATALOG = os.path.join(HERE, "catalog.json")
OUT = os.path.join(ROOT, "config", "controls.yml")

T, N = "terraform", "none"

# id: (remediate, detect, stack, tags)
MAPPING = {
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

SECTION_STACK_NOTE = {
    1: "CAM password policy (1.7-1.14) has no Terraform resource - reported as MANUAL.",
    7: "Cloud Security Center has no Terraform resources - whole section is MANUAL.",
    9: "TCSS exposes only cluster_access / image_registry - whole section is MANUAL.",
}


def yaml_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def main() -> int:
    with open(CATALOG, encoding="utf-8") as fh:
        catalog = json.load(fh)

    controls = catalog["controls"]
    ids = {c["id"] for c in controls}
    mapped = set(MAPPING)
    if ids != mapped:
        print(f"ERROR: catalog/mapping mismatch", file=sys.stderr)
        print(f"  missing from MAPPING: {sorted(ids - mapped)}", file=sys.stderr)
        print(f"  extra in MAPPING:     {sorted(mapped - ids)}", file=sys.stderr)
        return 1

    lines = [
        "# CIS Tencent Cloud Foundation Benchmark v1.0.0 - control registry",
        "#",
        "# GENERATED by tools/generate_controls.py - do not reformat by hand.",
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
        "#   stack      Terraspace stack that owns it (null when unsupported)",
        "#   tags       free-form selectors for `cis --tag`",
        "#",
        f"benchmark: \"{catalog['benchmark']}\"",
        f"version: \"{catalog['version']}\"",
        f"released: \"{catalog['date']}\"",
        "",
        "sections:",
    ]
    for sid in sorted(catalog["sections"], key=int):
        lines.append(f'  "{sid}": "{yaml_escape(catalog["sections"][sid])}"')
    lines.append("")
    lines.append("controls:")

    current_section = None
    for c in controls:
        remediate, detect, stack, tags = MAPPING[c["id"]]
        sec = int(c["section"])
        if sec != current_section:
            current_section = sec
            lines.append("")
            lines.append(f"  # === {sec} {catalog['sections'][str(sec)]} ===")
            if sec in SECTION_STACK_NOTE:
                lines.append(f"  # {SECTION_STACK_NOTE[sec]}")
        lines.append(f'  - id: "{c["id"]}"')
        lines.append(f'    title: "{yaml_escape(c["title"])}"')
        lines.append(f'    assessment: {c["assessment"]}')
        lines.append(f'    profile: "{c["profile"]}"')
        lines.append(f"    enabled: true")
        lines.append(f"    remediate: {remediate}")
        lines.append(f"    detect: {detect}")
        lines.append(f'    stack: {stack if stack else "null"}')
        lines.append(f'    tags: [{", ".join(tags)}]')

    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    n_rem = sum(1 for v in MAPPING.values() if v[0] == T)
    n_det = sum(1 for v in MAPPING.values() if v[1] == T)
    n_man = sum(1 for v in MAPPING.values() if v[0] == N and v[1] == N)
    print(f"wrote {OUT}")
    print(f"  controls        : {len(controls)}")
    print(f"  remediable (tf) : {n_rem}")
    print(f"  detectable (tf) : {n_det}")
    print(f"  manual only     : {n_man}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
