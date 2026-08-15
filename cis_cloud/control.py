"""A single CIS recommendation plus how it maps onto the Terraform provider."""

from __future__ import annotations

import re

from . import Error

_ID_RE = re.compile(r"^\d+(\.\d+){1,2}$")
_STACK_RE = re.compile(r"^[a-z][a-z0-9_-]*$")


class Control:
    def __init__(self, hash_: dict):
        self.id = str(hash_.get("id"))
        self.title = str(hash_.get("title"))
        self.assessment = str(hash_.get("assessment", "Manual"))
        self.profile = str(hash_.get("profile", "Level 1"))
        self.enabled = bool(hash_.get("enabled", True))
        self.remediate = str(hash_.get("remediate", "none"))
        self.detect = str(hash_.get("detect", "none"))
        raw_stack = hash_.get("stack")
        self.stack = None if raw_stack is None or raw_stack == "null" else str(raw_stack)
        self.tags = [str(t) for t in (hash_.get("tags") or [])]
        self._validate()

    def __repr__(self) -> str:
        return f"<Control {self.id} {self.title!r}>"

    @property
    def section(self) -> str:
        return self.id.split(".")[0]

    def sort_key(self) -> list[int]:
        """Sortable key: "3.10" must come after "3.9"."""
        return [int(part) for part in self.id.split(".")]

    def remediable(self) -> bool:
        return self.remediate == "terraform"

    def detectable(self) -> bool:
        return self.detect == "terraform"

    def manual(self) -> bool:
        """Neither enforceable nor assessable by Terraform."""
        return not self.remediable() and not self.detectable()

    @property
    def level(self) -> int:
        m = re.search(r"\d+", self.profile)
        return int(m.group(0)) if m else 0

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "assessment": self.assessment,
            "profile": self.profile,
            "enabled": self.enabled,
            "remediate": self.remediate,
            "detect": self.detect,
            "stack": self.stack,
            "tags": self.tags,
        }

    def _validate(self) -> None:
        # 1.1 (tencent) and 1.1.1 (AWS/Alibaba/GCP/Azure) ids are both valid.
        if not _ID_RE.match(self.id):
            raise Error(
                "control id must look like '<section>.<n>' or "
                f"'<section>.<group>.<n>', got {self.id!r}"
            )
        if self.remediate not in ("terraform", "none"):
            raise Error(f"{self.id}: remediate must be terraform|none, got {self.remediate!r}")
        if self.detect not in ("terraform", "none"):
            raise Error(f"{self.id}: detect must be terraform|none, got {self.detect!r}")
        if self.remediable() and self.stack is None:
            raise Error(f"{self.id}: remediate=terraform requires a stack")
        if self.detectable() and self.stack is None:
            raise Error(f"{self.id}: detect=terraform requires a stack")
        if self.stack and not _STACK_RE.match(self.stack):
            raise Error(f"{self.id}: malformed stack name {self.stack!r}")
