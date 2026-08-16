#!/usr/bin/env python3
"""Compute a reproducible cache fingerprint for the CI dependency file.

GitHub Actions cache keys for this repo are derived from `pyproject.toml`
content, so a dependency change produces a different key and the stale cache
is not reused. This script prints the fingerprint used by the `cache-health`
CI job (a self-contained check of the cache lifecycle).

Deterministic: `python scripts/cache_fingerprint.py` always prints the same
value for an unchanged pyproject.toml, and a different value after an edit.

Usage:
    python3 scripts/cache_fingerprint.py            # prints e.g. dep-<sha256>
    python3 scripts/cache_fingerprint.py --file X  # fingerprint a different file
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def fingerprint(path: str | Path) -> str:
    """Content-based fingerprint: `dep-` + sha256 of the file bytes."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"dependency file not found: {p}")
    digest = hashlib.sha256(p.read_bytes()).hexdigest()
    return f"dep-{digest}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="cache_fingerprint")
    ap.add_argument("--file", default=str(ROOT / "pyproject.toml"),
                    help="dependency file to fingerprint (default pyproject.toml)")
    args = ap.parse_args(argv)
    try:
        print(fingerprint(args.file))
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
