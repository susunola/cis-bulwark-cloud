"""Port of CisTest::Hcl from test/test_helper.rb — heuristic HCL inspection.

Not a full HCL semantic model: masks strings/comments then brace-pairs to find
top-level blocks, list literals, object keys and locals. Enough to enforce the
registry <-> Terraform contract.
"""

from __future__ import annotations

import re

BLOCK_HEAD = re.compile(r"^([a-z_]+)((?:[ \t]+\"[^\"]*\")*)[ \t]*\{", re.MULTILINE)


def read(path):
    return open(path).read()


def mask(src: str) -> str:
    out = list(src)
    n = len(src)
    i = 0
    while i < n:
        ch = src[i]
        if ch == '"':
            j = i + 1
            while j < n and not (src[j] == '"' and src[j - 1] != "\\"):
                j += 1
            j = min(j, n - 1)
            for k in range(i + 1, j):
                out[k] = " "
            i = j + 1
        elif ch == "#":
            j = src.find("\n", i)
            if j == -1:
                j = n
            for k in range(i, j):
                out[k] = " "
            i = j
        elif ch == "/":
            if i + 1 < n and src[i + 1] == "/":
                j = src.find("\n", i)
                if j == -1:
                    j = n
                for k in range(i, j):
                    out[k] = " "
                i = j
            elif i + 1 < n and src[i + 1] == "*":
                j = src.find("*/", i)
                if j == -1:
                    j = n - 2
                else:
                    j += 2
                for k in range(i, j):
                    if src[k] != "\n":
                        out[k] = " "
                i = j
            else:
                i += 1
        else:
            i += 1
    return "".join(out)


def depth_map(masked: str) -> list[int]:
    depth = 0
    out = []
    for ch in masked:
        out.append(depth)
        if ch in "{[": 
            depth += 1
        elif ch in "}]":
            depth -= 1
    return out


def match_delimiter(masked: str, open_: int) -> int:
    pairs = {"{": "}", "[": "]"}
    closer = pairs[masked[open_]]
    depth = 0
    i = open_
    while i < len(masked):
        if masked[i] == masked[open_]:
            depth += 1
        elif masked[i] == closer:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise ValueError(f"unbalanced {masked[open_]} at offset {open_}")


def string_list(src: str, name: str):
    masked = mask(src)
    m = re.search(rf"\b{re.escape(name)}\s*=\s*\[", masked)
    if not m:
        return None
    open_ = masked.index("[", m.start())
    close = match_delimiter(masked, open_)
    return re.findall(r'"([^"]*)"', src[open_ + 1:close])


def object_keys(src: str, name: str):
    masked = mask(src)
    m = re.search(rf"\b{re.escape(name)}\s*=\s*\{{", masked)
    if not m:
        return None
    open_ = masked.index("{", m.start())
    close = match_delimiter(masked, open_)
    depths = depth_map(masked)
    base = depths[open_] + 1

    keys = []
    for mm in re.finditer(r'"([^"]*)"\s*=', src):
        at = mm.start()
        if not (open_ < at < close):
            continue
        if depths[at] != base:
            continue
        keys.append(mm.group(1))
    return keys


def top_blocks(src: str) -> list[dict]:
    masked = mask(src)
    depths = depth_map(masked)
    blocks = []
    for m in BLOCK_HEAD.finditer(masked):
        if depths[m.start()] != 0:
            continue
        open_ = masked.index("{", m.start())
        close = match_delimiter(masked, open_)
        header = src[m.start():open_]
        blocks.append({
            "type": m.group(1),
            "labels": re.findall(r'"([^"]*)"', header),
            "header": header.strip(),
            "body": src[open_ + 1:close],
            "body_begin": open_ + 1,
            "body_end": close,
        })
    return blocks


def locals_map(src: str) -> dict:
    masked = mask(src)
    depths = depth_map(masked)
    out = {}
    for block in top_blocks(src):
        if block["type"] != "locals":
            continue
        start = block["body_begin"]
        stop = block["body_end"]
        base = depths[start]

        starts = []
        for mm in re.finditer(r"^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=", src, re.MULTILINE):
            at = mm.start(1)
            if not (start <= at < stop):
                continue
            if depths[at] != base:
                continue
            starts.append([at, mm.group(1), mm.end(0)])
        for idx, (at, name, expr_begin) in enumerate(starts):
            expr_end = starts[idx + 1][0] if idx + 1 < len(starts) else stop
            out[name] = src[expr_begin:expr_end]
    return out
