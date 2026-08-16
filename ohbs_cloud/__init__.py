"""ohbs-cloud — multi-cloud CIS foundation benchmarks, plain Terraform.

A Python port of the original Ruby implementation. The data layer (per-cloud
control registries under config/, self-contained Terraform stacks under
stacks/, shared modules under modules/) ships inside the package, so a plain
``pip install ohbs-cloud`` gives you the whole benchmark offline.

The active cloud is selected with CIS_CLOUD (default: tencent); the CLI
``ohbs-cloud --cloud aws ...`` sets it for one run.

    CIS_CLOUD=aws ohbs-cloud list       show the AWS control registry
    ohbs-cloud scan                     read-only assessment (audit stack)
    ohbs-cloud plan                     show what `apply` would change
    ohbs-cloud apply                    enforce the selected controls
    ohbs-cloud destroy STACK            roll back one hardening stack
"""

from __future__ import annotations

import os
from pathlib import Path

# Data root: package-bundled data by default, overridable at runtime for
# development against a checkout. The root is the directory that holds
# config/ stacks/ modules/ directly - i.e. ohbs_cloud/data in a checkout, NOT
# the repository root (the repo root has no such directories).
_ROOT = Path(os.environ.get("CIS_CLOUD_ROOT") or (Path(__file__).parent / "data"))

# Clouds with a full scan/apply implementation (registry + stacks).
IMPLEMENTED_CLOUDS = ["tencent", "aws", "azure", "gcp", "alibaba"]
# Kept as an empty list so the reference-only guard stays in place for future
# benchmarks.
REFERENCE_CLOUDS: list[str] = []

AUDIT_STACK = "audit"

# Stacks that write, per cloud. Order is stable so runs are reproducible.
# tencent keeps its legacy layout (stacks/<name>); later clouds live under
# stacks/<cloud>/<name>.
HARDENING_STACKS = {
    "tencent": ["iam", "logging", "network", "storage", "database", "kubernetes"],
    # network has no remediable control in AWS v7.0.0 (6.3/6.4/6.5/6.7 are
    # detect-only), so it is not a hardening stack.
    "aws": ["iam", "logging", "storage", "database"],
    # azure: remediable controls live in network (7.6 watcher), security
    # (8.1.13 contact) and storage (9.x).
    "azure": ["network", "security", "storage"],
    "gcp": ["logging", "network", "compute"],
    "alibaba": ["iam", "logging"],
}


class Error(Exception):
    """Base error for ohbs-cloud."""


def get_root() -> Path:
    """Return the data root directory."""
    return _ROOT


def cloud() -> str:
    """Active cloud, from CIS_CLOUD. Raises for reference-only clouds."""
    name = os.environ.get("CIS_CLOUD") or "tencent"
    if name in IMPLEMENTED_CLOUDS:
        return name
    if name in REFERENCE_CLOUDS:
        raise Error(
            f"{name!r} is a reference-only benchmark (catalog published, "
            f"no Terraform mapping yet); supported: {', '.join(IMPLEMENTED_CLOUDS)}"
        )
    raise Error(
        f"unknown cloud {name!r}; expected one of "
        f"{', '.join(IMPLEMENTED_CLOUDS + REFERENCE_CLOUDS)}"
    )


def hardening_stacks() -> list[str]:
    return list(HARDENING_STACKS[cloud()])


def catalog_path() -> Path:
    root = get_root()
    if cloud() == "tencent":
        return root / "config" / "controls.yml"
    return root / "config" / cloud() / "controls.yml"


def stack_dir(stack: str) -> Path:
    root = get_root()
    if cloud() == "tencent":
        return root / "stacks" / stack
    return root / "stacks" / cloud() / stack


# --- lazy singletons (reset! clears them so a changed env is picked up) ---

_catalog = None
_selector = None


def get_catalog():
    global _catalog
    if _catalog is None:
        import importlib

        Catalog = importlib.import_module(".catalog", __package__).Catalog
        _catalog = Catalog.load(catalog_path())
    return _catalog


def get_selector():
    global _selector
    if _selector is None:
        import importlib

        Selector = importlib.import_module(".selector", __package__).Selector
        _selector = Selector.from_env(get_catalog())
    return _selector


def reset() -> None:
    global _catalog, _selector
    _catalog = None
    _selector = None
    try:
        from . import remediation as _remediation
        _remediation.reset()
    except ImportError:
        pass


def controls_for_stack(stack: str) -> list[str]:
    return [c.id for c in get_selector().remediable if c.stack == stack]


def controls_for_audit() -> list[str]:
    return [c.id for c in get_selector().detectable]


__all__ = [
    "Error",
    "IMPLEMENTED_CLOUDS",
    "REFERENCE_CLOUDS",
    "AUDIT_STACK",
    "HARDENING_STACKS",
    "get_root",
    "cloud",
    "hardening_stacks",
    "catalog_path",
    "stack_dir",
    "get_catalog",
    "get_selector",
    "reset",
    "controls_for_stack",
    "controls_for_audit",
]
