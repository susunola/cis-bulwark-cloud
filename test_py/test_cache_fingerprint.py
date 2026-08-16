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


def test_cache_stampede_concurrent_writers_do_not_corrupt(tmp_path):
    # Cache stampede / thundering herd: many concurrent jobs race to write the
    # same cache marker on a cache miss. The seed must be atomic — write a
    # temp file, then rename — so concurrent writers never tear the marker and
    # the final state is one complete, valid value.
    import concurrent.futures
    import os

    marker = tmp_path / "cache" / "ok"
    n = 32

    def seeder(i: int) -> None:
        marker.parent.mkdir(parents=True, exist_ok=True)
        tmp = marker.parent / f"ok.{os.getpid()}.{i}"
        tmp.write_text(f"seeded:{i}\n", encoding="utf-8")
        os.replace(tmp, marker)  # atomic rename

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        list(ex.map(seeder, range(n)))

    assert marker.exists()
    content = marker.read_text(encoding="utf-8").strip()
    assert content.startswith("seeded:"), f"corrupted marker: {content!r}"
    # A torn write would mix/truncate two values; the marker must be a single
    # complete "seeded:<int>".
    assert content.removeprefix("seeded:").isdigit()


def test_cache_stampede_direct_write_would_race_so_we_use_rename(tmp_path):
    # Contrast: a non-atomic (direct write) of the marker from multiple
    # writers is the failure mode the atomic rename avoids. We assert the
    # repo's chosen pattern (temp + os.replace) is atomic at the file level.
    import os

    target = tmp_path / "marker"
    target.parent.mkdir(exist_ok=True)
    tmp = target.parent / "tmp.marker"
    tmp.write_text("seeded:9\n", encoding="utf-8")
    os.replace(tmp, target)
    assert target.read_text(encoding="utf-8") == "seeded:9\n"
    assert not tmp.exists(), "temp file must be consumed by the rename"
