"""Risk severity for findings, inferred from a control's tags.

CIS benchmarks do not grade severity; this is a conservative mapping over the
existing tag vocabulary so it costs nothing to maintain and never contradicts
the registry.
"""

from __future__ import annotations

LEVELS = ["critical", "high", "medium", "low"]

RULES = [
    ("critical", ["root", "mfa", "admin", "access-key", "public", "public-access",
                  "public-ip", "admin-ports", "cloudshell", "bastion"]),
    ("high", ["password-policy", "encryption", "ssl", "tls", "ingress", "security-group",
              "network", "keyvault", "databricks", "rds", "sql", "disk", "nacl"]),
    ("medium", ["logging", "audit", "monitoring", "retention", "sink", "trail",
                "flow-log", "actiontrail", "defender", "kms", "alert"]),
]


def of(tags) -> str:
    for level, keys in RULES:
        if set(tags) & set(keys):
            return level
    return "low"
