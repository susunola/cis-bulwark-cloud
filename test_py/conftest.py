"""Shared test helpers — port of Ruby test/test_helper.rb."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

import cis_cloud as C

ROOT = Path(C.get_root()).parent.parent  # repo root (data root is <repo>/cis_cloud/data)
FILTER_ENV = ["CIS_ONLY", "CIS_EXCLUDE", "CIS_SECTIONS", "CIS_TAGS", "CIS_PROFILE"]


@pytest.fixture(autouse=True)
def _clean_env():
    """Save/restore filter env around every test, mirroring CisTestCase."""
    saved = {k: os.environ.get(k) for k in FILTER_ENV}
    saved["CIS_CLOUD"] = os.environ.get("CIS_CLOUD")
    for k in FILTER_ENV:
        os.environ.pop(k, None)
    C.reset()
    yield
    for k in FILTER_ENV:
        if saved[k] is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = saved[k]
    if saved["CIS_CLOUD"] is None:
        os.environ.pop("CIS_CLOUD", None)
    else:
        os.environ["CIS_CLOUD"] = saved["CIS_CLOUD"]
    C.reset()


@pytest.fixture
def catalog():
    return C.get_catalog()


def select(**kwargs):
    from cis_cloud.selector import Selector

    return Selector(C.get_catalog(), **kwargs)


def run_cli(*args, env: dict | None = None):
    """Run the CLI in a subprocess, like the Ruby run_cli."""
    child_env = {k: None for k in FILTER_ENV}
    if env:
        for k, v in env.items():
            if v is None:
                child_env[k] = None
            else:
                child_env[k] = str(v)

    full_env = {k: v for k, v in os.environ.items() if v is not None}
    # ensure cis_cloud is importable regardless of cwd
    full_env["PYTHONPATH"] = str(ROOT) + os.pathsep + full_env.get("PYTHONPATH", "")
    for k, v in child_env.items():
        if v is None:
            full_env.pop(k, None)
        else:
            full_env[k] = v

    proc = subprocess.run(
        [sys.executable, "-m", "cis_cloud", *args],
        capture_output=True, text=True, cwd=str(ROOT), env=full_env,
    )
    return proc


def stack_path(stack: str, *parts) -> Path:
    return Path(C.get_root()) / "stacks" / stack / "/".join(parts)


def module_path(mod: str, *parts) -> Path:
    return Path(C.get_root()) / "modules" / mod / "/".join(parts)
