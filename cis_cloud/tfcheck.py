"""Pre-deployment CIS checks against Terraform definitions, Steampipe-style.

`cis-cloud check --tf DIR --cloud aws` parses the .tf files in DIR (no cloud
credentials, no terraform run), finds each resource block of interest and
verifies the arguments CIS requires are present. A control is PASS when every
matching resource satisfies its rule, FAIL when one does not.

This is deliberately heuristic: a brace-paired scan of the source, not a full
HCL semantic model.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from . import get_catalog as _catalog_mod
from . import cloud as _cloud
from . import severity as _severity

# control -> {"resource": ..., "args": {arg: expectation}}
# expectation: int (minimum), str (exact), bool, list (any of), dict (nested
# block), None (presence only), re.Pattern (regex match)
RULES: dict[str, dict[str, dict]] = {
    "tencent": {
        "4.1": {"resource": "tencentcloud_cos_bucket", "args": {"acl": "private"}},
        "2.1": {"resource": "tencentcloud_cloud_audit", "args": {"audit_switch": True}},
        "5.2": {"resource": "tencentcloud_mysql_instance", "args": {"vip": None, "publicly_accessible": [False]}},
    },
    "aws": {
        "2.8":   {"resource": "aws_iam_account_password_policy", "args": {"minimum_password_length": 14}},
        "2.9":   {"resource": "aws_iam_account_password_policy", "args": {"password_reuse_prevention": 24}},
        "4.2":   {"resource": "aws_cloudtrail", "args": {"enable_log_file_validation": True}},
        "3.2.2": {"resource": "aws_db_instance", "args": {"auto_minor_version_upgrade": [True, None]}},
        "3.2.3": {"resource": "aws_db_instance", "args": {"publicly_accessible": [False, None]}},
        "6.1.1": {"resource": "aws_ebs_encryption_by_default", "args": {"enabled": True}},
        "6.7":   {"resource": "aws_instance", "args": {"metadata_options": {"http_tokens": "required"}}},
    },
    "azure": {
        "9.3.4": {"resource": "azurerm_storage_account", "args": {"https_traffic_only_enabled": True}},
        "9.3.6": {"resource": "azurerm_storage_account", "args": {"min_tls_version": "TLS1_2"}},
        "9.3.8": {"resource": "azurerm_storage_account", "args": {"allow_nested_items_to_be_public": False}},
        "8.3.6": {"resource": "azurerm_key_vault", "args": {"enable_rbac_authorization": True}},
        "7.6":   {"resource": "azurerm_network_watcher", "args": {}},
    },
    "gcp": {
        "2.3":  {"resource": "google_logging_project_sink", "args": {"filter": re.compile(r"cloudaudit")}},
        "2.13": {"resource": "google_dns_policy", "args": {"enable_logging": True}},
        "6.4":  {"resource": "google_sql_database_instance", "args": {"require_ssl": True, "inside_settings": True}},
        "4.4":  {"resource": "google_compute_project_metadata", "args": {"enable-oslogin": "TRUE"}},
    },
    "alibaba": {
        "1.11": {"resource": "alicloud_ram_account_password_policy", "args": {"minimum_password_length": 14}},
        "2.1":  {"resource": "alicloud_actiontrail", "args": {"status": "Enable"}},
        "6.1":  {"resource": "alicloud_db_instance", "args": {"ssl_action": "Open"}},
    },
}


@dataclass
class Finding:
    id: str
    status: str
    severity: str
    title: str
    evidence: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "status": self.status,
            "severity": self.severity,
            "title": self.title,
            "evidence": self.evidence,
        }


def scan(dir_: str | Path, cloud: str, catalog=None) -> list[Finding]:
    rules = RULES.get(cloud, {})
    if not rules:
        return []

    d = Path(dir_)
    files = [f for f in d.rglob("*.tf")
             if "/.terraform/" not in str(f) and "/.git/" not in str(f)]
    blocks: list[dict] = []
    for f in files:
        blocks.extend(_extract_blocks(f.read_text(encoding="utf-8", errors="replace"), str(f)))

    cat = catalog
    if cat is None and _cloud() == cloud:
        cat = _catalog_mod()

    out = []
    for cid, rule in rules.items():
        matching = [b for b in blocks if b["type"] == rule["resource"]]
        violations = [b for b in matching if not _args_ok(rule["args"], b["body"])]
        ctl = next((c for c in (cat.controls if cat else []) if c.id == cid), None)
        if violations:
            evidence = f"{rule['resource']}: " + "; ".join(_missing(b, rule["args"]) for b in violations)
            status = "FAIL"
        else:
            evidence = f"{rule['resource']}: {len(matching)} block(s) comply"
            status = "PASS"
        out.append(Finding(
            id=cid,
            severity=_severity.of(ctl.tags if ctl else []),
            title=ctl.title if ctl else cid,
            status=status,
            evidence=evidence,
        ))
    return out


# ---- parsing -------------------------------------------------------------

def _extract_blocks(src: str, path: str) -> list[dict]:
    blocks = []
    offset = 0
    m = re.search(r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{', src[offset:])
    while m:
        abs_start = offset + m.start()
        open_idx = offset + m.end() - 1
        depth = 1
        i = open_idx + 1
        while i < len(src) and depth > 0:
            if src[i] == "{":
                depth += 1
            elif src[i] == "}":
                depth -= 1
            i += 1
        body = src[open_idx + 1:i - 1]
        blocks.append({"type": m.group(1), "name": m.group(2), "body": body, "file": path})
        offset = i
        m = re.search(r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{', src[offset:])
    return blocks


# ---- argument checks -----------------------------------------------------

def _args_ok(args: dict, body: str) -> bool:
    return all(_arg_ok(arg, expected, body) for arg, expected in args.items())


def _arg_ok(arg: str, expected: Any, body: str) -> bool:
    if isinstance(expected, dict):
        block = _nested_block(body, arg)
        return block is not None and _args_ok(expected, block)
    if isinstance(expected, re.Pattern):
        value = _extract_arg(body, arg)
        return value is not None and expected.search(str(value)) is not None
    if expected is None:
        return re.search(rf"^\s*{re.escape(arg)}\s*=", body, re.MULTILINE) is not None
    if isinstance(expected, list):
        value = _extract_arg(body, arg)
        return value in expected or (value is None and None in expected)
    if isinstance(expected, int) and not isinstance(expected, bool):
        value = _extract_arg(body, arg)
        return value is not None and int(value) >= expected
    if isinstance(expected, float):
        value = _extract_arg(body, arg)
        return value is not None and float(value) >= float(expected)
    return _extract_arg(body, arg) == expected


def _extract_arg(body: str, arg: str):
    m = re.search(rf'^\s*{re.escape(arg)}\s*=\s*("([^"]*)"|(\d+(?:\.\d+)?)|(true|false))',
                  body, re.MULTILINE)
    if not m:
        return None
    if m.group(2) is not None:
        return m.group(2)
    if m.group(3) is not None:
        return float(m.group(3)) if "." in m.group(3) else int(m.group(3))
    if m.group(4) is not None:
        return m.group(4) == "true"
    return None


def _nested_block(body: str, arg: str) -> Optional[str]:
    m = re.search(rf"^\s*{re.escape(arg)}\s*{{", body, re.MULTILINE)
    if not m:
        return None
    open_idx = m.end() - 1
    depth = 1
    i = open_idx + 1
    while i < len(body) and depth > 0:
        if body[i] == "{":
            depth += 1
        elif body[i] == "}":
            depth -= 1
        i += 1
    return body[open_idx + 1:i - 1]


def _missing(block: dict, args: dict) -> str:
    bad = [arg for arg, expected in args.items() if not _arg_ok(arg, expected, block["body"])]
    return f"{block['type']}.{block['name']} ({Path(block['file']).name}) missing/weak: {', '.join(bad)}"
