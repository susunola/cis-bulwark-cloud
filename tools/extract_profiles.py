#!/usr/bin/env python3
"""Extract 'Profile Applicability: Level N' per recommendation and merge into catalog.json.

Body headings wrap across lines, e.g.

    1.3 Ensure Multi-factor Authentication is enabled for the "root"
    account (Manual)
    Profile Applicability:

    • Level 1

So: anchor on 'Profile Applicability:', scan backwards for the nearest
'<id> ...' heading start, and forwards for 'Level N'.
"""
import json
import re
import unicodedata


def clean(s: str) -> str:
    return "".join(
        c for c in s if c != "\f" and unicodedata.category(c) != "Co"
    ).rstrip()


lines = [clean(l) for l in open("/tmp/cis_extract/cis_tc.txt", encoding="utf-8")]
catalog = json.load(open("/tmp/cis_extract/catalog.json"))
known = {c["id"] for c in catalog["controls"]}

HEAD_START = re.compile(r"^(\d+\.\d+)\s+\S")
LEVEL = re.compile(r"^\s*[•\-\*]?\s*Level\s+([12])\s*$")

profiles = {}
for i, line in enumerate(lines):
    if line.strip() != "Profile Applicability:":
        continue
    cid = None
    for back in range(1, 7):  # heading is at most a few lines above
        m = HEAD_START.match(lines[i - back])
        if m and m.group(1) in known:
            cid = m.group(1)
            break
    if not cid:
        continue
    for fwd in range(1, 7):
        lm = LEVEL.match(lines[i + fwd])
        if lm:
            profiles.setdefault(cid, f"Level {lm.group(1)}")
            break

missing = sorted(known - set(profiles), key=lambda x: [int(p) for p in x.split(".")])
print(f"profiles found: {len(profiles)}/{len(known)}")
print("missing:", missing or "none")

for c in catalog["controls"]:
    if c["id"] in profiles:
        c["profile"] = profiles[c["id"]]

json.dump(
    catalog,
    open("/tmp/cis_extract/catalog.json", "w", encoding="utf-8"),
    indent=2,
    ensure_ascii=False,
)

from collections import Counter

print(Counter(c.get("profile") for c in catalog["controls"]))
