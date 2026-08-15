"""Compare two cis-cloud scan JSON reports and summarise the change.

`cis-cloud diff baseline.json current.json` keys findings by control id and
classifies each id's movement:

    NEW       failing now, not failing (or absent) in the baseline
    STILL     failing in both
    FIXED     was failing, now not (PASS / MANUAL / absent)
    CLEAR     not failing in either (informational, omitted from the list)
    DROPPED   was in the baseline selection but absent from the current run

The command is read-only: it never touches a cloud or Terraform.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional


def load_scan(path: os.PathLike | str) -> dict:
    """Parse one scan JSON file, raising a clear error when malformed."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"scan file not found: {p}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError(f"could not parse scan file {p}: {e}") from e
    findings = data.get("findings")
    if not isinstance(findings, list):
        raise ValueError(f"scan file {p} has no 'findings' list")
    return data


def _status_of(f) -> str:
    return str((f or {}).get("status", "")).upper()


def diff(base: dict, cur: dict) -> dict:
    """Return the id-keyed movement between two scan payloads."""
    base_by_id = {str(f.get("id", "")): f for f in base.get("findings", [])}
    cur_by_id = {str(f.get("id", "")): f for f in cur.get("findings", [])}

    base_fail = {cid for cid, f in base_by_id.items() if _status_of(f) == "FAIL"}
    cur_fail = {cid for cid, f in cur_by_id.items() if _status_of(f) == "FAIL"}

    all_ids = sorted(set(base_by_id) | set(cur_by_id))
    moves = {"new": [], "still": [], "fixed": [], "dropped": []}

    for cid in all_ids:
        b_fail = cid in base_fail
        c_fail = cid in cur_fail
        if b_fail and c_fail:
            moves["still"].append(cid)
        elif c_fail and not b_fail:
            moves["new"].append(cid)
        elif b_fail and not c_fail:
            moves["fixed"].append(cid)
        elif cid in base_by_id and cid not in cur_by_id:
            moves["dropped"].append(cid)

    # Summary counts, derived from the movement lists.
    summary = {k: len(v) for k, v in moves.items()}
    return {
        "baseline": {
            "path": base.get("_path"),
            "version": base.get("version"),
            "total_fail": len(base_fail),
        },
        "current": {
            "path": cur.get("_path"),
            "version": cur.get("version"),
            "total_fail": len(cur_fail),
        },
        "summary": summary,
        "detail": {
            "new": [{"id": cid, "title": _title(cur_by_id.get(cid))} for cid in moves["new"]],
            "still": [{"id": cid, "title": _title(cur_by_id.get(cid))} for cid in moves["still"]],
            "fixed": [{"id": cid, "title": _title(cur_by_id.get(cid))} for cid in moves["fixed"]],
            "dropped": [{"id": cid, "title": _title(base_by_id.get(cid))} for cid in moves["dropped"]],
        },
    }


def _title(f) -> str:
    return str((f or {}).get("title") or "")


def render_diff(d: dict, format_: str = "table") -> str:
    """Render a diff dict as text or JSON."""
    if format_ == "json":
        return json.dumps(d, indent=2, ensure_ascii=False)

    s = d["summary"]
    lines = [
        "Scan diff",
        f"  baseline: {d['baseline']['path'] or '?'}  fail={d['baseline']['total_fail']}",
        f"  current : {d['current']['path'] or '?'}  fail={d['current']['total_fail']}",
        "",
        f"  new     {s['new']:>3}   now failing, not in baseline",
        f"  still   {s['still']:>3}   failing in both",
        f"  fixed   {s['fixed']:>3}   was failing, now clean",
        f"  dropped {s['dropped']:>3}   in baseline selection, absent now",
        "",
    ]
    if s["new"]:
        lines.append(f"NEW ({s['new']}):")
        lines += [f"  {x['id']:<8} {x['title']}" for x in d["detail"]["new"]]
        lines.append("")
    if s["still"]:
        lines.append(f"STILL FAILING ({s['still']}):")
        lines += [f"  {x['id']:<8} {x['title']}" for x in d["detail"]["still"]]
        lines.append("")
    if s["fixed"]:
        lines.append(f"FIXED ({s['fixed']}):")
        lines += [f"  {x['id']:<8} {x['title']}" for x in d["detail"]["fixed"]]
        lines.append("")
    return "\n".join(lines)
