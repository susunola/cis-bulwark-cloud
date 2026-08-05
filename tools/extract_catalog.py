#!/usr/bin/env python3
"""Parse the CIS Tencent Cloud Foundation Benchmark v1.0.0 Summary Table
into a structured catalog (JSON)."""
import json
import re
import unicodedata

SRC = "/tmp/cis_extract/cis_tc.txt"
OUT = "/tmp/cis_extract/catalog.json"


def clean(s: str) -> str:
    """Drop private-use checkbox glyphs and form feeds; keep layout spacing."""
    out = []
    for ch in s:
        if ch == "\f":
            continue
        if unicodedata.category(ch) == "Co":  # private use area
            continue
        out.append(ch)
    return "".join(out).rstrip()


with open(SRC, encoding="utf-8") as fh:
    lines = [clean(l) for l in fh.read().split("\n")]

start = next(i for i, l in enumerate(lines) if l.strip() == "Appendix: Summary Table")
end = next(
    i
    for i, l in enumerate(lines)
    if i > start and l.strip().startswith("Appendix: CIS Controls v7 IG 1")
)
body = lines[start + 1 : end]
print(f"[body] source lines {start + 2}..{end}")

# Repeated page furniture inside the table
NOISE_FRAGMENTS = (
    "CIS Benchmark Recommendation",
    "Correctly",
    "Set",
)
PAGE = re.compile(r"^\s*Page \d+\s*$")
YESNO = re.compile(r"^\s*Yes\s+No\s*$")
ID_LINE = re.compile(r"^(\d+(?:\.\d+)?)\s{2,}(\S.*)$")
STATUS = re.compile(r"\((Automated|Manual)\)\s*$")


def is_noise(line: str) -> bool:
    s = line.strip()
    if not s or PAGE.match(line) or YESNO.match(line):
        return True
    # Header row may be split across columns: "CIS Benchmark Recommendation   Set"
    stripped = s
    for frag in NOISE_FRAGMENTS:
        stripped = stripped.replace(frag, "")
    return not stripped.strip()


records, cur = [], None
for line in body:
    if is_noise(line):
        continue
    m = ID_LINE.match(line)
    if m:
        if cur:
            records.append(cur)
        cur = {"id": m.group(1), "title": m.group(2).strip()}
    elif cur is not None and re.match(r"^\s{3,}\S", line):
        cur["title"] += " " + line.strip()

if cur:
    records.append(cur)

sections, controls = {}, []
for rec in records:
    cid = rec["id"]
    title = re.sub(r"\s+", " ", rec["title"]).strip()
    if "." not in cid:
        sections[cid] = title
        continue
    m = STATUS.search(title)
    controls.append(
        {
            "id": cid,
            "section": cid.split(".")[0],
            "title": STATUS.sub("", title).strip(),
            "assessment": m.group(1) if m else "Unknown",
        }
    )

controls.sort(key=lambda c: [int(p) for p in c["id"].split(".")])

catalog = {
    "benchmark": "CIS Tencent Cloud Foundation Benchmark",
    "version": "v1.0.0",
    "date": "11-12-2025",
    "sections": sections,
    "controls": controls,
}
with open(OUT, "w", encoding="utf-8") as fh:
    json.dump(catalog, fh, indent=2, ensure_ascii=False)

print(f"sections: {len(sections)}  controls: {len(controls)}")
for sid in sorted(sections, key=int):
    grp = [c for c in controls if c["section"] == sid]
    auto = sum(1 for c in grp if c["assessment"] == "Automated")
    print(f"  {sid}. {sections[sid]:<42} total={len(grp):<3} automated={auto}")

unknown = [c["id"] for c in controls if c["assessment"] == "Unknown"]
print("unknown-status:", unknown or "none")

# Contiguity check: ids within each section must run 1..N with no gaps
for sid in sorted(sections, key=int):
    ids = sorted(
        (int(c["id"].split(".")[1]) for c in controls if c["section"] == sid)
    )
    expected = list(range(1, len(ids) + 1))
    if ids != expected:
        print(f"  !! section {sid} gap: {ids}")
