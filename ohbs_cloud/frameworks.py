"""Optional cross-framework mapping so a control set can be viewed through
other compliance lenses (NIST 800-53, PCI-DSS, 等保 2.0, ...).

The mapping is deliberately lightweight and data-driven: each framework maps
to a list of control-id globs (`3.5`, `4.*`). A control is "in" a framework
when its id matches any of that framework's globs. The CIS benchmark ids are
reasonably stable and the mappings below are conservative *supersets* so they
never silently drop a control that plausibly maps; operators can tighten them.

This is separate from the per-control `tags` in the registry, which drive
capability (remediate/detect) filtering. Framework selection is an
orthogonal view.

Usage::

    CIS_FRAMEWORK=nist ohbs-cloud list        # controls mapped to NIST 800-53
    ohbs-cloud list --framework pci           # PCI-DSS view
"""

from __future__ import annotations

import fnmatch

FRAMEWORKS = {
    # Name -> (title, ordered list of control-id globs)
    "nist": (
        "NIST SP 800-53 Rev 5",
        [
            # Access control (AC) + identification/authentication (IA) map to
            # the IAM-heavy section 1, logging to AU (2.*), networking to SC
            # (3.*). Storage (4.*) is SC-28 at-rest protection.
            "1.*", "2.*", "3.*", "4.*",
        ],
    ),
    "pci": (
        "PCI DSS v4.0",
        [
            # Requirement 1 (network), 2 (config), 3 (data), 4 (encryption),
            # 5 (malware), 7 (access), 8 (auth), 10 (logging)
            "3.*", "4.*", "5.*", "1.*", "2.*",
        ],
    ),
    "djcp": (
        "GB/T 22239-2019 等保 2.0 (网络安全等级保护)",
        [
            "1.*", "2.*", "3.*", "4.*", "5.*", "6.*",
        ],
    ),
}

# Title lookup (used by the reporter for --framework headers).
FRAMEWORK_TITLES = {name: title for name, (title, _) in FRAMEWORKS.items()}


def normalize(name) -> str | None:
    """Return the canonical framework name or None when unknown."""
    if name is None:
        return None
    v = str(name).strip().lower()
    if v in FRAMEWORKS:
        return v
    # Accept short aliases / spaces: "nist80053", "NIST SP 800-53", "pci dss".
    for key in FRAMEWORKS:
        if key in v or v.replace(" ", "") in key.replace(" ", ""):
            return key
    return None


def controls_for(catalog, name) -> list:
    """Return the controls whose ids fall in the named framework."""
    key = normalize(name)
    if key is None:
        return []
    globs = FRAMEWORKS[key][1]
    return [c for c in catalog.controls if any(fnmatch.fnmatchcase(c.id, g) for g in globs)]


def is_in(catalog, control, name) -> bool:
    """Whether a single control maps to the named framework."""
    key = normalize(name)
    if key is None:
        return False
    return any(fnmatch.fnmatchcase(control.id, g) for g in FRAMEWORKS[key][1])
