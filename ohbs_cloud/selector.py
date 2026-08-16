"""Turns filter expressions into a concrete set of controls.

Filters are read from the environment so that the CLI and the terraform
stacks resolve to the same selection.

    CIS_ONLY      comma separated id globs, e.g. "3.5,4.*"   (authoritative)
    CIS_EXCLUDE   comma separated id globs, applied last
    CIS_SECTIONS  comma separated section numbers, e.g. "3,4"
    CIS_TAGS      comma separated tags, matches if the control has ANY of them
    CIS_PROFILE   level1 | level2

Precedence: CIS_ONLY replaces the `enabled:` baseline entirely; the other
filters narrow whatever baseline is in play; CIS_EXCLUDE always wins.
"""

from __future__ import annotations

import fnmatch
import os
from typing import Optional

from . import Error, hardening_stacks
from .catalog import Catalog
from .control import Control


class Selector:
    def __init__(self, catalog: Catalog, only=None, exclude=None, sections=None,
                 tags=None, profile: Optional[str] = None, framework: Optional[str] = None):
        self.catalog = catalog
        self.only = list(only or [])
        self.exclude = list(exclude or [])
        self.sections = [str(s) for s in (sections or [])]
        self.tags = list(tags or [])
        self.profile = self._normalize_profile(profile)
        self.framework = self._normalize_framework(framework)
        self._selected: Optional[list[Control]] = None
        self._validate()

    # ---- construction -----------------------------------------------------

    @classmethod
    def from_env(cls, catalog: Catalog, env=None) -> "Selector":
        env = os.environ if env is None else env
        return cls(
            catalog,
            only=cls.split(env.get("CIS_ONLY")),
            exclude=cls.split(env.get("CIS_EXCLUDE")),
            sections=cls.split(env.get("CIS_SECTIONS")),
            tags=cls.split(env.get("CIS_TAGS")),
            profile=env.get("CIS_PROFILE"),
            framework=env.get("CIS_FRAMEWORK"),
        )

    @staticmethod
    def split(value) -> list[str]:
        return [s.strip() for s in str(value or "").split(",") if s.strip()]

    # ---- selection --------------------------------------------------------

    @property
    def selected(self) -> list[Control]:
        if self._selected is None:
            if self.only:
                base = [c for c in self.catalog.controls if self._glob_any(c.id, self.only)]
            else:
                base = [c for c in self.catalog.controls if c.enabled]
            if self.sections:
                base = [c for c in base if c.section in self.sections]
            if self.tags:
                base = [c for c in base if set(c.tags) & set(self.tags)]
            if self.profile is not None:
                base = [c for c in base if c.level <= self.profile]
            if self.framework:
                from .frameworks import is_in as _fw_in
                base = [c for c in base if _fw_in(self.catalog, c, self.framework)]
            if self.exclude:
                base = [c for c in base if not self._glob_any(c.id, self.exclude)]
            base.sort(key=lambda c: c.sort_key())
            self._selected = base
        return self._selected

    @property
    def remediable(self) -> list[Control]:
        return [c for c in self.selected if c.remediable()]

    @property
    def detectable(self) -> list[Control]:
        return [c for c in self.selected if c.detectable()]

    @property
    def not_remediable(self) -> list[Control]:
        return [c for c in self.selected if not c.remediable()]

    @property
    def not_detectable(self) -> list[Control]:
        return [c for c in self.selected if not c.detectable()]

    @property
    def ids(self) -> list[str]:
        return [c.id for c in self.selected]

    def is_empty(self) -> bool:
        return not self.selected

    @property
    def stacks_for_apply(self) -> list[str]:
        remediable_stacks = {c.stack for c in self.remediable if c.stack}
        return [s for s in hardening_stacks() if s in remediable_stacks]

    @property
    def summary(self) -> dict:
        return {
            "selected": len(self.selected),
            "of": self.catalog.size,
            "remediable": len(self.remediable),
            "detectable": len(self.detectable),
            "manual": sum(1 for c in self.selected if c.manual()),
            "stacks": self.stacks_for_apply,
            "framework": self.framework,
        }

    # Reproduce this selection in a child process.
    @property
    def to_env(self) -> dict:
        return {
            "CIS_ONLY": ",".join(self.only),
            "CIS_EXCLUDE": ",".join(self.exclude),
            "CIS_SECTIONS": ",".join(self.sections),
            "CIS_TAGS": ",".join(self.tags),
            "CIS_PROFILE": f"level{self.profile}" if self.profile else "",
            "CIS_FRAMEWORK": self.framework or "",
        }

    # ---- helpers ----------------------------------------------------------

    @staticmethod
    def _glob_any(cid: str, patterns) -> bool:
        return any(p == cid or fnmatch.fnmatchcase(cid, p) for p in patterns)

    @staticmethod
    def _normalize_profile(value) -> Optional[int]:
        if value is None or str(value).strip() == "":
            return None
        v = str(value).strip().lower()
        if v in ("1", "l1", "level1", "level 1", "level-1"):
            return 1
        if v in ("2", "l2", "level2", "level 2", "level-2"):
            return 2
        raise Error(f"unknown profile {value!r}; expected level1 or level2")

    @staticmethod
    def _normalize_framework(value) -> Optional[str]:
        if value is None or str(value).strip() == "":
            return None
        from .frameworks import normalize as fw_normalize
        key = fw_normalize(value)
        if key is None:
            from .frameworks import FRAMEWORKS
            raise Error(f"unknown framework {value!r}; choose from {', '.join(sorted(FRAMEWORKS))}")
        return key

    def _validate(self) -> None:
        known = self.catalog.ids
        for pattern in self.only + self.exclude:
            if not any(cid == pattern or fnmatch.fnmatchcase(cid, pattern) for cid in known):
                raise Error(f"filter {pattern!r} matches no control in the benchmark")
        for sid in self.sections:
            if not any(cid.split(".")[0] == sid for cid in known):
                raise Error(f"unknown section {sid!r}")
        for tag in self.tags:
            if not any(tag in c.tags for c in self.catalog.controls):
                raise Error(f"unknown tag {tag!r}")
