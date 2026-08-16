"""Baseline drift detection.

`ohbs-cloud check-drift` compares a baseline scan against a fresh scan and flags
regressions — controls that were not failing (PASS / MANUAL / absent) in the
baseline but are failing now. This is the lightweight foundation for continuous
monitoring on top of the point-in-time `scan`.

Drift reuses `diff.diff` for the movement classification and defines a
regression as any control now FAILing that was not FAILing in the baseline
(i.e. the `new` bucket). `still` failures are persistent and not counted as a
new drift event.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from .diff import diff as compute_diff, load_scan


def drift(base: dict, cur: dict) -> dict:
    """Return the drift between a baseline and a current scan payload.

    Regression = a control that is FAIL now but was not FAIL in the baseline.
    """
    d = compute_diff(base, cur)
    regressions = [
        {"id": x["id"], "title": x["title"]}
        for x in d["detail"]["new"]
    ]
    return {
        "baseline": d["baseline"],
        "current": d["current"],
        "summary": {
            "regressions": len(regressions),
            "still_failing": d["summary"]["still"],
            "fixed": d["summary"]["fixed"],
        },
        "regressions": regressions,
    }


def check_drift(base_path: str, cur_path: str) -> dict:
    """Convenience wrapper loading both scan files and computing drift."""
    base = load_scan(base_path)
    cur = load_scan(cur_path)
    base["_path"] = base_path
    cur["_path"] = cur_path
    return drift(base, cur)


def render_drift(d: dict, format_: str = "table") -> str:
    """Render a drift dict as text or JSON."""
    if format_ == "json":
        return json.dumps(d, indent=2, ensure_ascii=False)
    s = d["summary"]
    lines = [
        "Drift check",
        f"  baseline: {d['baseline']['path'] or '?'}  fail={d['baseline']['total_fail']}",
        f"  current : {d['current']['path'] or '?'}  fail={d['current']['total_fail']}",
        "",
        f"  regressions   {s['regressions']:>3}   now failing, were not in baseline",
        f"  still failing {s['still_failing']:>3}   failing in both (persistent)",
        f"  fixed         {s['fixed']:>3}   were failing, now clean",
        "",
    ]
    if s["regressions"]:
        lines.append(f"REGRESSIONS ({s['regressions']}):")
        lines += [f"  {x['id']:<8} {x['title']}" for x in d["regressions"]]
        lines.append("")
    return "\n".join(lines)
