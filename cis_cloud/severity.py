"""Risk severity for findings, inferred from a control's tags.

CIS benchmarks do not grade severity; this is a conservative mapping over the
existing tag vocabulary so it costs nothing to maintain and never contradicts
the registry.
"""

from __future__ import annotations

LEVELS = ["critical", "high", "medium", "low"]

# Numeric weight per severity, so findings can be triaged by expected impact
# (Prowler ThreatScore-style, kept deliberately small).
SCORES = {
    "critical": 100,
    "high": 70,
    "medium": 40,
    "low": 10,
}

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


def score(severity: str) -> int:
    """Numeric weight for a severity string (unknown -> low)."""
    return SCORES.get(str(severity).strip().lower(), SCORES["low"])


def weighted(findings) -> int:
    """Sum of severity weights for the FAIL findings in a list."""
    return sum(score(f.get("severity")) for f in findings
               if str(f.get("status", "")).upper() == "FAIL")
