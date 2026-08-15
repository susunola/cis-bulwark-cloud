"""Cross-cloud compliance posture, Prowler-style.

`cis-cloud --cloud X scan --format json -o scans/X.json` saves per-cloud
findings; `cis-cloud compliance --dir scans` reads every such file and rolls
them into one view: per-cloud status cards, a global tally and the full
failing-control list ordered by severity.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from .severity import weighted as _weighted

CLOUD_HINTS = {
    "tencent": ["tencent"],
    "aws": ["amazon"],
    "azure": ["azure"],
    "gcp": ["google"],
    "alibaba": ["alibaba"],
}

STATUS_ORDER = ["FAIL", "PASS", "MANUAL", "SKIPPED", "SUPPRESSED"]
SEVERITY_ORDER = ["critical", "high", "medium", "low"]


class Compliance:
    def __init__(self, entries: list[dict]):
        self.entries = entries

    @classmethod
    def load_dir(cls, dir_: os.PathLike | str) -> "Compliance":
        d = Path(dir_)
        files = sorted(d.glob("*.json"))
        entries = [e for f in files if (e := cls._parse_file(f)) is not None]
        return cls(entries)

    @classmethod
    def _parse_file(cls, path: Path) -> Optional[dict]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
        findings = data.get("findings")
        if not isinstance(findings, list):
            return None
        return {
            "cloud": cls._infer_cloud(data, path),
            "path": str(path),
            "benchmark": data.get("benchmark"),
            "version": data.get("version"),
            "summary": data.get("summary") or {},
            "findings": findings,
        }

    @classmethod
    def _infer_cloud(cls, data: dict, path: Path) -> str:
        haystack = " ".join([
            str(data.get("benchmark") or ""),
            str((data.get("account") or {}).get("cloud") or ""),
            path.name,
        ]).lower()
        for cloud, hints in CLOUD_HINTS.items():
            if any(h in haystack for h in hints):
                return cloud
        return path.stem

    def is_empty(self) -> bool:
        return not self.entries

    @property
    def clouds(self) -> list[str]:
        return [e["cloud"] for e in self.entries]

    def per_cloud(self) -> dict:
        out = {}
        for e in self.entries:
            findings = e["findings"]
            fails = [f for f in findings if f.get("status") == "FAIL"]
            out[e["cloud"]] = {
                "benchmark": e["benchmark"],
                "version": e["version"],
                "path": e["path"],
                "summary": e["summary"],
                "status": self._tally(findings),
                "fail_by_severity": {
                    lv: sum(1 for f in fails if f.get("severity") == lv)
                    for lv in SEVERITY_ORDER
                },
                "risk_score": _weighted(findings),
                "assessed": len(findings),
            }
        return out

    def global_(self) -> dict:
        all_ = [f for e in self.entries for f in e["findings"]]
        fails = [f for f in all_ if f.get("status") == "FAIL"]
        fails_sorted = sorted(
            fails,
            key=lambda f: (SEVERITY_ORDER.index(f.get("severity")) if f.get("severity") in SEVERITY_ORDER else 99,
                           str(f.get("id", ""))),
        )
        return {
            "status": self._tally(all_),
            "fail_by_severity": {
                lv: sum(1 for f in fails if f.get("severity") == lv)
                for lv in SEVERITY_ORDER
            },
            "risk_score": _weighted(all_),
            "failing": fails_sorted,
        }

    def _tally(self, findings: list[dict]) -> dict:
        return {s: sum(1 for f in findings if f.get("status") == s) for s in STATUS_ORDER}
