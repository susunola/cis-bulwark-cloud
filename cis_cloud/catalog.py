"""The parsed config/controls.yml, i.e. every recommendation in the benchmark."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

import yaml

from . import Error
from .control import Control


class Catalog:
    def __init__(self, raw: dict):
        self.benchmark = raw.get("benchmark")
        self.version = raw.get("version")
        self.released = raw.get("released")
        self.sections = raw.get("sections") or {}
        self.controls = [Control(h) for h in (raw.get("controls") or [])]
        self.controls.sort(key=lambda c: c.sort_key())
        self._index: Optional[dict[str, Control]] = None
        self._assert_unique_ids()

    @classmethod
    def load(cls, path: os.PathLike | str) -> "Catalog":
        p = Path(path)
        if not p.exists():
            raise Error(f"control registry not found: {p}")
        raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        return cls(raw)

    def __getitem__(self, cid: str) -> Optional[Control]:
        if self._index is None:
            self._index = {c.id: c for c in self.controls}
        return self._index.get(str(cid))

    @property
    def ids(self) -> list[str]:
        return [c.id for c in self.controls]

    def section_title(self, sid: str) -> str:
        return self.sections.get(str(sid)) or f"Section {sid}"

    @property
    def size(self) -> int:
        return len(self.controls)

    def _assert_unique_ids(self) -> None:
        seen = {}
        for c in self.controls:
            seen[c.id] = seen.get(c.id, 0) + 1
        dupes = [cid for cid, n in seen.items() if n > 1]
        if dupes:
            raise Error(f"duplicate control ids in registry: {', '.join(dupes)}")
