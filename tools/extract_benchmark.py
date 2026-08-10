#!/usr/bin/env python3
"""Extract a CIS cloud benchmark Summary Table + profile applicability into a
structured catalog (JSON), one per cloud.

This is the multi-cloud successor to the earlier Tencent-only parsing scripts.
It reads the pdftotext (-layout) output of any CIS benchmark PDF that follows
the standard appendix layout:

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
  * hyphenated line breaks inside titles ("customer- managed") are re-joined
  * profile applicability is "Profile Applicability:" followed by "• Level N"

Usage:
  python3 tools/extract_benchmark.py                 # all clouds
  python3 tools/extract_benchmark.py aws gcp         # named clouds only
  python3 tools/extract_benchmark.py --txt aws /path/to/aws.txt
  python3 tools/extract_benchmark.py --all
"""
import argparse
import json
import os
import re
import sys
import unicodedata
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# cloud -> (default pdftotext input, benchmark name, version, release date)
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
BREAK_HYPHEN = re.compile(r"(\S)- ([a-z])")  # hyphenated line break re-join


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


def normalize_title(title: str) -> str:
    """Collapse whitespace and re-join hyphenated line breaks."""
    t = re.sub(r"\s+", " ", title).strip()
    t = BREAK_HYPHEN.sub(r"\1-\2", t)
    return t.strip()


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
        c["title"] = normalize_title(c["title"])
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


def validate(cloud, sections, controls):
    """Return a list of (kind, message) problems; empty means clean."""
    issues = []
    ids = [c["id"] for c in controls]
    key = lambda k: [int(p) for p in k.split(".")]
    for dup in sorted({i for i in ids if ids.count(i) > 1}, key=key):
        issues.append(("duplicate-id", f"{dup} appears {ids.count(dup)}x"))
    for c in controls:
        if c["assessment"] not in ("Automated", "Manual"):
            issues.append(("assessment", f"{c['id']} assessment={c['assessment']!r}"))
        if c.get("profile") not in ("Level 1", "Level 2"):
            issues.append(("profile", f"{c['id']} profile={c.get('profile')!r}"))
        t = c["title"]
        if BREAK_HYPHEN.search(t):
            issues.append(("title-hyphen", f"{c['id']}: {t!r}"))
        if "  " in t:
            issues.append(("title-space", f"{c['id']}: {t!r}"))
        if re.search(r"\bo\s+o\b", t):
            issues.append(("title-checkbox", f"{c['id']}: {t!r}"))
        if any(unicodedata.category(ch) == "Co" for ch in t):
            issues.append(("title-private-use", f"{c['id']}: {t!r}"))
        parts = c["id"].split(".")
        if len(parts) > 2:
            gid = ".".join(parts[:-1])
            if c.get("group") != sections.get(gid):
                issues.append(("group", f"{c['id']} group={c.get('group')!r} != sections[{gid}]"))
    for sid in sorted(sections, key=key):
        sub = [c["id"] for c in controls if c["section"] == sid]
        if all(len(i.split(".")) == 2 for i in sub):
            nums = sorted(int(i.split(".")[1]) for i in sub)
            if nums != list(range(1, len(nums) + 1)):
                issues.append(("section-gap", f"section {sid}: {nums}"))
    return issues


def extract_cloud(cloud, txt):
    if not os.path.exists(txt):
        print(f"!! {cloud}: input missing: {txt}")
        return 1
    lines = open(txt, encoding="utf-8").read().split("\n")
    sections, controls = parse_table(lines)
    known = {c["id"] for c in controls}
    profiles = parse_profiles([l.rstrip() for l in lines], known)
    for c in controls:
        if c["id"] in profiles:
            c["profile"] = profiles[c["id"]]

    issues = validate(cloud, sections, controls)

    key = lambda k: [int(p) for p in k.split(".")]
    catalog = {
        "benchmark": CLOUDS[cloud][1],
        "version": CLOUDS[cloud][2],
        "date": CLOUDS[cloud][3],
        "sections": dict(sorted(sections.items(), key=lambda kv: key(kv[0]))),
        "controls": controls,
    }
    out = os.path.join(ROOT, "benchmarks", cloud, "catalog.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(catalog, fh, indent=2, ensure_ascii=False)

    prof = Counter(c.get("profile") for c in controls)
    print(f"{cloud}: wrote {out}")
    print(f"  controls={len(controls)}  sections={len(sections)}  profiles={dict(prof)}")
    if issues:
        print(f"  !! {len(issues)} issue(s):")
        for kind, msg in issues:
            print(f"     [{kind}] {msg}")
        return 1
    print("  clean: ids unique, ids continuous, titles residue-free")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Extract CIS benchmark catalogs for all clouds.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  %(prog)s                    # all clouds (default inputs)\n"
            "  %(prog)s aws gcp            # named clouds\n"
            "  %(prog)s --txt aws /path/to/aws.txt\n"
        ),
    )
    ap.add_argument("clouds", nargs="*", choices=sorted(CLOUDS),
                    help="clouds to extract (default: all)")
    ap.add_argument("--txt", nargs=2, metavar=("CLOUD", "PATH"),
                    help="override the pdftotext input for one cloud")
    args = ap.parse_args(argv)

    if args.txt:
        cloud, path = args.txt
        if cloud not in CLOUDS:
            ap.error(f"unknown cloud {cloud!r}; choose from {sorted(CLOUDS)}")
        return extract_cloud(cloud, path)

    clouds = args.clouds or sorted(CLOUDS)
    failed = 0
    for cloud in clouds:
        failed |= extract_cloud(cloud, CLOUDS[cloud][0])
    return failed


if __name__ == "__main__":
    sys.exit(main())
