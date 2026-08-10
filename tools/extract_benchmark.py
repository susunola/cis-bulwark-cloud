#!/usr/bin/env python3
"""Extract a CIS cloud benchmark Summary Table + profile applicability into a
structured catalog (JSON), one per cloud.

This is the multi-cloud successor to the earlier Tencent-only parsing scripts.
It reads the pdftotext
(-layout) output of any CIS benchmark PDF that follows the standard appendix
layout:

    Appendix: Summary Table
        <id>  <title>                     Set Correctly?  Yes  No
        1.1.1 Ensure ... (Manual)             o            o
        ...
    Appendix: CIS Controls v7 IG 1 ...

Handled across the cloud variants:

  * ids can be 1, 1.1 or 1.1.1 (section / group / control)
  * checkbox glyphs differ: some PDFs render "o", others use private-use
    area glyphs; a row with a checkbox is a *control*, a row without one is a
    *section* or a *group* heading
  * multi-line titles continue on indented lines
  * profile applicability is "Profile Applicability:" followed by "• Level N"

Usage:  python3 tools/extract_benchmark.py
"""
import json
import os
import re
import sys
import unicodedata
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# cloud -> (pdftotext input, benchmark name, version, release date)
CLOUDS = {
    "aws": (
        "/tmp/cis_extract/aws.txt",
        "CIS Amazon Web Services Foundations Benchmark",
        "v7.0.0",
        "03-25-2026",
    ),
    "alibaba": (
        "/tmp/cis_extract/alibaba.txt",
        "CIS Alibaba Cloud Foundation Benchmark",
        "v2.0.0",
        "06-23-2025",
    ),
    "gcp": (
        "/tmp/cis_extract/gcp.txt",
        "CIS Google Cloud Platform Foundation Benchmark",
        "v5.0.0",
        "05-09-2026",
    ),
    "azure": (
        "/tmp/cis_extract/azure.txt",
        "CIS Microsoft Azure Foundations Benchmark",
        "v6.0.0",
        "04-19-2026",
    ),
}

ID_LINE = re.compile(r"^\s*(\d+(?:\.\d+){0,2})\s{2,}(\S.*)$")
CONT = re.compile(r"^\s{3,}\S")            # indented continuation line
STATUS = re.compile(r"\((Automated|Manual)\)\s*$")
PAGE = re.compile(r"^\s*Page \d+\s*$")
YESNO = re.compile(r"^\s*Yes\s+No\s*$")
NOISE_FRAGMENTS = ("CIS Benchmark Recommendation", "Correctly", "Set")
O_CB = re.compile(r"\s+o(?:\s+o)?\s*$")    # AWS-style checkbox
HEAD_START = re.compile(r"^\s*(\d+(?:\.\d+){1,2})\s+\S")
LEVEL = re.compile(r"^\s*[•\-\*]?\s*Level\s+([12])\s*$")


def clean(s: str) -> str:
    """Drop private-use checkbox glyphs and form feeds; keep layout spacing."""
    return "".join(
        c for c in s if c != "\f" and unicodedata.category(c) != "Co"
    ).rstrip()


def has_checkbox(raw: str) -> bool:
    """True when a summary-table row ends in a Set-Correctly checkbox.

    Some PDFs emit "o", others private-use glyphs (category Co) that clean()
    strips - so detect on the raw line, before cleaning.
    """
    tail = raw[-12:]
    if any(unicodedata.category(ch) == "Co" for ch in tail):
        return True
    return bool(O_CB.search(raw))


def is_noise(line: str) -> bool:
    s = line.strip()
    if not s or PAGE.match(line) or YESNO.match(line):
        return True
    stripped = s
    for frag in NOISE_FRAGMENTS:
        stripped = stripped.replace(frag, "")
    return not stripped.strip()


def parse_table(lines):
    """Return (sections, controls) parsed from the Summary Table."""
    starts = [i for i, l in enumerate(lines) if l.strip() == "Appendix: Summary Table"]
    if not starts:
        raise SystemExit("no 'Appendix: Summary Table' found")
    start = starts[-1]
    ends = [
        i for i in range(start + 1, len(lines))
        if lines[i].lstrip().startswith("Appendix:")
    ]
    end = ends[0] if ends else len(lines)
    body = lines[start + 1 : end]

    sections, controls, cur = {}, [], None
    for line in body:
        cb = has_checkbox(line)
        line = clean(line)
        if is_noise(line):
            continue
        m = ID_LINE.match(line)
        if m:
            cid = m.group(1)
            title = O_CB.sub("", m.group(2)).strip()
            if cb:
                if cur:
                    controls.append(cur)
                cur = {"id": cid, "title": title}
            else:
                # section (1) or group (1.1) heading - no checkbox
                sections.setdefault(cid, title)
                cur = None
        elif cur is not None and CONT.match(line):
            cur["title"] += " " + line.strip()
    if cur:
        controls.append(cur)

    for c in controls:
        c["title"] = re.sub(r"\s+", " ", c["title"]).strip()
        m = STATUS.search(c["title"])
        c["section"] = c["id"].split(".")[0]
        c["assessment"] = m.group(1) if m else "Unknown"
        c["title"] = STATUS.sub("", c["title"]).strip()
        # group heading for 3-level ids, e.g. 1.1.1 -> 1.1
        parts = c["id"].split(".")
        if len(parts) > 2 and ".".join(parts[:-1]) in sections:
            c["group"] = sections[".".join(parts[:-1])]
    controls.sort(key=lambda c: [int(p) for p in c["id"].split(".")])
    return sections, controls


def parse_profiles(lines, known):
    """Anchor on 'Profile Applicability:' and find '<id> ...' heading + 'Level N'."""
    profiles = {}
    for i, line in enumerate(lines):
        if line.strip() != "Profile Applicability:":
            continue
        cid = None
        for back in range(1, 20):
            if i - back < 0:
                break
            m = HEAD_START.match(clean(lines[i - back]))
            if m and m.group(1) in known:
                cid = m.group(1)
                break
        if not cid:
            continue
        for fwd in range(1, 8):
            lm = LEVEL.match(lines[i + fwd])
            if lm:
                lvl = f"Level {lm.group(1)}"
                old = profiles.get(cid)
                if old is None or (old == "Level 1" and lvl == "Level 2"):
                    profiles[cid] = lvl
                break
    return profiles


def main() -> int:
    failed = 0
    for cloud, (src, name, version, date) in CLOUDS.items():
        if not os.path.exists(src):
            print(f"!! {cloud}: input missing: {src}")
            failed = 1
            continue
        lines = open(src, encoding="utf-8").read().split("\n")
        sections, controls = parse_table(lines)
        known = {c["id"] for c in controls}
        profiles = parse_profiles([l.rstrip() for l in lines], known)

        missing_p = sorted(known - set(profiles), key=lambda x: [int(p) for p in x.split(".")])
        unknown = [c["id"] for c in controls if c["assessment"] == "Unknown"]
        for c in controls:
            if c["id"] in profiles:
                c["profile"] = profiles[c["id"]]

        # sanity: no duplicate ids; for purely two-level sections, ids must run
        # 1..N with no gaps (three-level sections like 2.1.x are checked for
        # duplicates only, their "continuity" is structural)
        key = lambda k: [int(p) for p in k.split(".")]
        for sid in sorted(sections, key=key):
            ids = [c["id"] for c in controls if c["section"] == sid]
            dups = sorted({i for i in ids if ids.count(i) > 1}, key=key)
            if dups:
                print(f"  !! {cloud} section {sid} duplicate ids: {dups}")
            if all(len(i.split(".")) == 2 for i in ids):
                nums = sorted(int(i.split(".")[1]) for i in ids)
                if nums != list(range(1, len(nums) + 1)):
                    print(f"  !! {cloud} section {sid} gap: {nums}")

        out = os.path.join(ROOT, "benchmarks", cloud, "catalog.json")
        os.makedirs(os.path.dirname(out), exist_ok=True)
        key = lambda k: [int(p) for p in k.split(".")]
        catalog = {
            "benchmark": name,
            "version": version,
            "date": date,
            "sections": dict(sorted(sections.items(), key=lambda kv: key(kv[0]))),
            "controls": controls,
        }
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(catalog, fh, indent=2, ensure_ascii=False)

        print(f"{cloud}: wrote {out}")
        print(f"  controls={len(controls)}  sections={len(sections)}  "
              f"profiles={dict(Counter(c.get('profile') for c in controls))}")
        print(f"  missing-profile={len(missing_p)}  unknown-status={len(unknown)}")
        if missing_p:
            print(f"    missing: {missing_p}")
        if unknown:
            print(f"    unknown: {unknown}")
    return failed


if __name__ == "__main__":
    sys.exit(main())
