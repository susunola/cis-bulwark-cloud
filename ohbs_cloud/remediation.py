"""Remediation guidance for findings, from derived rules.

CIS controls are grouped into coarse families; rather than hand-editing all 387
auto-generated registry entries, remediation is expressed as a small rule file
keyed by cloud + control id (or glob). Lookup order:

    exact control id  ->  glob match  ->  generic per-capability fallback

The generic fallback guarantees every finding still gets a usable hint, even
when the rule file has no entry for its exact id.

Rule file schema (config/remediation.yml)::

    tencent:
      "4.1":
        remediation: "Set the bucket ACL to private."
        reference: "https://console.cloud.tencent.com/cos/bucket"
      "4.*":
        remediation: "Review storage access and enable SSE-COS where possible."
    aws:
      "6.1.1":
        remediation: "Enable EBS encryption by default for the account."

A control is resolved against the rules for its own cloud only.
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml

from . import get_root as _root_mod
from . import cloud as _cloud

_DEFAULT_FILE = "config/remediation.yml"

# Cache per load so a changed file / env is picked up after `reset()`.
_resolver_cache: dict = {}


def _rules() -> dict:
    """Return the per-cloud rule map, loaded lazily and cached."""
    if "data" not in _resolver_cache:
        override = os.environ.get("CIS_REMEDIATION")
        path = Path(override) if override else _root_mod() / _DEFAULT_FILE
        data = {}
        if path.exists():
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            if isinstance(raw, dict):
                data = raw
        _resolver_cache["data"] = data
    return _resolver_cache["data"]


def reset() -> None:
    """Clear the cached rules so a changed file is reloaded."""
    _resolver_cache.pop("data", None)


def _entry(cloud: str, cid: str) -> dict | None:
    """Best rule for (cloud, cid): exact id, then first glob match."""
    rules = _rules().get(cloud)
    if not isinstance(rules, dict):
        return None
    exact = rules.get(cid)
    if isinstance(exact, dict):
        return exact
    for pattern, rule in rules.items():
        if isinstance(rule, dict) and _glob_match(pattern, cid):
            return rule
    return None


def _glob_match(pattern: str, value: str) -> bool:
    import fnmatch
    return fnmatch.fnmatchcase(value, pattern)


def for_control(cloud: str, control, default: str = "") -> str:
    """Remediation text for a control, or a generic hint when nothing is known.

    ``control`` may be a Control instance or a dict-like with id/remediate/
    stack/detect. Falls back to a capability-driven generic message so a FAIL
    always carries a path forward.
    """
    cid = _attr(control, "id")
    rule = _entry(cloud, cid)
    if rule and rule.get("remediation"):
        return str(rule["remediation"])
    return default or _generic(control)


def reference_for(cloud: str, control) -> str:
    """Reference URL from the rule for a control, or ''."""
    cid = _attr(control, "id")
    rule = _entry(cloud, cid)
    if rule:
        return str(rule.get("reference") or "")
    return ""


def _attr(control, name) -> str:
    """Read an attribute from a Control-like object or a dict, safely."""
    if isinstance(control, dict):
        return str(control.get(name) or "")
    return str(getattr(control, name, "") or "")


def _generic(control) -> str:
    """Capability/stack-driven generic remediation message."""
    rem = _attr(control, "remediate")
    stack = _attr(control, "stack")
    if rem == "terraform":
        base = "Run `ohbs-cloud plan` then `ohbs-cloud apply` to enforce"
        return f"{base} (stack {stack})." if stack else f"{base}."
    return "Verify in the cloud console and apply the CIS recommendation manually."


def resolve_cloud() -> str:
    """Cloud used for resolution (normally the active cloud)."""
    return _cloud()
