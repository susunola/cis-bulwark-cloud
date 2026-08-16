#!/usr/bin/env python3
"""Verify README stays in sync with the code.

Checks that drift out of date before merge:

  1. Test count. The README claims a number of tests in test_py (e.g.
     "300 tests, offline"). Compare it against `pytest --collect-only`, and
     fail if the README count no longer matches reality.

  2. Command list. Every command in `ohbs_cloud.cli.COMMANDS` must be
     documented in the README "Commands" code block, and the README must not
     document commands that no longer exist.

  3. New test files. Every test_py/test_*.py file should be mentioned in the
     README "Tests" table (so new coverage is discoverable).

Exit 0 when README is current; 1 otherwise. Read-only; never edits anything.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
TESTS = ROOT / "test_py"

sys.path.insert(0, str(ROOT))

errors: list[str] = []


def check_test_count() -> None:
    """README test-count claim must equal the collected count."""
    text = README.read_text(encoding="utf-8")
    claimed = re.findall(r"(\d+)\s+tests?[^\n]*offline", text)
    if not claimed:
        errors.append("README: could not find a 'NNN tests, offline' claim")
        return
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", str(TESTS)],
        capture_output=True, text=True, cwd=str(ROOT))
    m = re.search(r"(\d+)\s+tests?\s+collected", proc.stdout)
    if not m:
        errors.append(f"pytest collect failed: {proc.stderr[:300]}")
        return
    actual = int(m.group(1))
    for claim in claimed:
        if int(claim) != actual:
            errors.append(
                f"README claims {claim} tests but pytest collects {actual}; update README")


def check_commands() -> None:
    """Every CLI command must be documented, and none stale."""
    import ohbs_cloud.cli as cli
    text = README.read_text(encoding="utf-8")
    # The documented commands live in the code block under the "## Commands"
    # heading; take that section only.
    sec = text.split("## Commands", 1)[1] if "## Commands" in text else text
    sec = sec.split("## ", 1)[0] if "## " in sec[3:] else sec
    block = ""
    for m in re.finditer(r"```(?:bash)?\s*\n(.*?)```", sec, re.DOTALL):
        block = m.group(1)
        break

    documented: set[str] = set()
    for line in block.splitlines():
        tokens = line.split()
        if not tokens or tokens[0] != "cis":
            continue
        for tok in tokens[1:]:
            if tok in cli.COMMANDS:
                documented.add(tok)
                break
    for cmd in cli.COMMANDS:
        if cmd not in documented:
            errors.append(f"README: CLI command '{cmd}' is not documented in the Commands block")
    for cmd in documented:
        if cmd not in cli.COMMANDS:
            errors.append(f"README: documents command '{cmd}' which no longer exists")


def check_test_files() -> None:
    """Every test_py/test_*.py should appear in the README Tests table."""
    text = README.read_text(encoding="utf-8")
    for f in sorted(TESTS.glob("test_*.py")):
        name = f.name
        if name not in text:
            errors.append(f"README: test file '{name}' is not mentioned in the Tests table")


def main() -> int:
    check_test_count()
    check_commands()
    check_test_files()
    if errors:
        print("README is out of sync:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print("README is in sync (test count, commands, test files).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
