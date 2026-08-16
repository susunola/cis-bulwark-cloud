"""Tests for the CI cache fingerprint (scripts/cache_fingerprint.py).

These lock in the expiration/cleanup contract the CI `cache-health` job relies
on:

- deterministic key for an unchanged dependency file  -> cache can be reused
- content change produces a new key                  -> stale cache is evicted
- missing file errors cleanly                        -> CI fails loudly instead
  of silently seeding a bad/empty cache
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from cache_fingerprint import fingerprint  # noqa: E402


def test_fingerprint_is_deterministic(tmp_path):
    f = tmp_path / "pyproject.toml"
    f.write_text("deps = ['PyYAML']\n", encoding="utf-8")
    assert fingerprint(f) == fingerprint(f)


def test_fingerprint_changes_when_content_changes(tmp_path):
    f = tmp_path / "pyproject.toml"
    f.write_text("deps = ['PyYAML']\n", encoding="utf-8")
    before = fingerprint(f)
    f.write_text("deps = ['PyYAML>=6.0']\n", encoding="utf-8")
    after = fingerprint(f)
    assert before != after, "a dependency change must invalidate the cache key"


def test_fingerprint_is_prefix_stable(tmp_path):
    # The prefix marks it as a dependency key so it never collides with other
    # cache types, and the full value is the content hash.
    f = tmp_path / "pyproject.toml"
    f.write_text("x\n", encoding="utf-8")
    assert fingerprint(f).startswith("dep-")


def test_fingerprint_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        fingerprint(tmp_path / "does-not-exist.toml")


def test_fingerprint_missing_file_exits_nonzero(tmp_path):
    # CLI path: a missing dependency file must fail the run (exit != 0), not
    # silently produce a usable-looking key that would seed an empty cache.
    from cache_fingerprint import main as fp_main
    assert fp_main(["--file", str(tmp_path / "nope.toml")]) == 1


def test_fingerprint_cli_prints_key(tmp_path):
    from cache_fingerprint import main as fp_main
    import io
    import contextlib

    f = tmp_path / "pyproject.toml"
    f.write_text("deps = ['PyYAML']\n", encoding="utf-8")
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fp_main(["--file", str(f)])
    assert buf.getvalue().strip().startswith("dep-")
    assert buf.getvalue().strip() == fingerprint(f)
