"""Operator-declared exclusions, read from config/suppress.yml."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

import yaml

from . import get_root


class Suppressions:
    def __init__(self, rules: list):
        self.rules = rules

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "Suppressions":
        path = path or (get_root() / "config" / "suppress.yml")
        rules = []
        if path.exists():
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            rules = list(data.get("suppress") or [])
        return cls(rules)

    def apply(self, findings: list[dict], cloud: str) -> list[dict]:
        out = []
        for f in findings:
            if not self.match(f, cloud):
                out.append(f)
                continue
            reason = self.reason_for(f, cloud)
            out.append({
                **f,
                "status": "SUPPRESSED",
                "suppressed": True,
                "evidence": f"{f.get('evidence', '')} [suppressed: {reason}]",
            })
        return out

    def match(self, finding: dict, cloud: str) -> bool:
        return any(self._rule_hits(r, finding, cloud) for r in self.rules)

    def _rule_hits(self, rule: dict, finding: dict, cloud: str) -> bool:
        if rule.get("cloud") != "*" and rule.get("cloud") != cloud:
            return False
        if not self._glob_match(rule.get("control"), str(finding.get("id", ""))):
            return False
        res = rule.get("resource")
        if res is None or res == "":
            return True
        # Prefer the structured `resource` field when present; fall back to
        # matching against the evidence text.
        return (res in str(finding.get("resource", "") or "")
                or res in str(finding.get("evidence", ""))
                or res in str(finding.get("id", "")))

    def reason_for(self, finding: dict, cloud: str) -> str:
        for r in self.rules:
            if self._rule_hits(r, finding, cloud):
                return r.get("reason") or "suppressed in config/suppress.yml"
        return "suppressed in config/suppress.yml"

    @staticmethod
    def _glob_match(pattern, value: str) -> bool:
        if pattern is None or pattern == "*":
            return True
        if not isinstance(pattern, str):
            return False
        re_src = r"^" + pattern.replace(".", r"\.").replace("*", ".*") + r"$"
        return re.match(re_src, value) is not None
