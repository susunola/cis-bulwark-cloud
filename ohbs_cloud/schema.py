"""Canonical result schema for findings.

Every finding dict flowing through ohbs-cloud — whether from a live `scan`
(runner), an IaC `check` (tfcheck) or a `compliance` aggregate — carries the
same set of keys. Centralising them here keeps renderers, suppression and the
schema test in one place, so a new field is added once and flows everywhere.

Normalised finding keys:
    id            control id (str)
    title         control title (str)
    status        PASS | FAIL | MANUAL | SKIPPED | SUPPRESSED (uppercased)
    severity      critical | high | medium | low
    score         numeric weight for the severity (int)
    evidence      human-readable detail (str)
    evidence_detail  optional structured list of {resource,attribute,...}
    resource      specific resource that failed (str, may be "")
    remediation   human-readable fix guidance (str, may be "")
"""

from __future__ import annotations

from .severity import SCORES

STATUSES = ["FAIL", "PASS", "MANUAL", "SKIPPED", "SUPPRESSED"]
SEVERITIES = ["critical", "high", "medium", "low"]
SCORE_MAP = SCORES

# Every normalised finding has these keys (in this order).
FINDING_KEYS = [
    "id",
    "title",
    "status",
    "severity",
    "score",
    "evidence",
    "evidence_detail",
    "resource",
    "remediation",
]

_SEVERITY_BY_TAG = None  # lazy import to avoid a cycle


def severity_for(control, default: str = "low") -> str:
    """Severity inferred from a control's tags (falls back to default)."""
    tags = getattr(control, "tags", None) or (control or {}).get("tags", [])
    global _SEVERITY_BY_TAG
    if _SEVERITY_BY_TAG is None:
        from .severity import of as _of
        _SEVERITY_BY_TAG = _of
    return _SEVERITY_BY_TAG(tags) or default


def normalize_finding(f: dict, control=None) -> dict:
    """Return a copy of ``f`` guaranteed to carry every FINDING_KEYS key.

    Missing keys are filled with sensible defaults; existing values pass
    through. ``control`` (a Control or None) is used to derive title, severity
    and score when the finding omits them.
    """
    cid = str(f.get("id", ""))
    title = f.get("title") or (control.title if control else None) or cid
    sev = str(f.get("severity") or (severity_for(control) if control else "low")).lower()
    if sev not in SEVERITIES:
        sev = "low"
    score = f.get("score")
    if score is None:
        score = SCORE_MAP.get(sev, SCORE_MAP["low"])
    return {
        "id": cid,
        "title": title,
        "status": str(f.get("status", "")).upper(),
        "severity": sev,
        "score": score,
        "evidence": str(f.get("evidence", "")),
        "evidence_detail": f.get("evidence_detail"),
        "resource": str(f.get("resource", "") or ""),
        "remediation": str(f.get("remediation", "") or ""),
    }
