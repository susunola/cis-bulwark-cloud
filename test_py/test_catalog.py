"""Port of test/catalog_test.rb — registry integrity against the benchmark."""

from __future__ import annotations

import os

import pytest

import ohbs_cloud as C

# Straight from CIS Tencent Cloud Foundation Benchmark v1.0.0.
TOTAL = 91
SECTION_SIZES = {"1": 16, "2": 20, "3": 7, "4": 9, "5": 6, "6": 9, "7": 6, "8": 6, "9": 12}
LEVEL1 = 67
LEVEL2 = 24
AUTOMATED = 25
MANUAL_ASSESS = 66

# What cis can do about them.
REMEDIABLE = 39
DETECTABLE = 20
NOT_ACTIONABLE = 43


def test_registry_covers_the_whole_benchmark(catalog):
    assert catalog.size == TOTAL


def test_section_sizes_match_the_benchmark(catalog):
    actual = {}
    for c in catalog.controls:
        actual[c.section] = actual.get(c.section, 0) + 1
    assert actual == SECTION_SIZES


def test_every_section_has_a_title(catalog):
    for sid, title in catalog.sections.items():
        assert title is not None and str(title).strip() != ""
        assert not str(title).startswith("Section "), f"section {sid} fell back to a placeholder"
    assert sorted(catalog.sections.keys()) == sorted(SECTION_SIZES.keys())


def test_ids_are_unique(catalog):
    ids = catalog.ids
    assert len(ids) == len(set(ids))


def test_ids_are_well_formed_and_belong_to_their_section(catalog):
    import re

    for c in catalog.controls:
        assert re.match(r"^\d+(\.\d+){1,2}$", c.id), f"malformed id {c.id}"
        assert c.id.split(".")[0] == c.section


def test_controls_are_sorted_numerically_not_lexically(catalog):
    keys = [c.sort_key() for c in catalog.controls]
    assert keys == sorted(keys)


def test_every_control_has_a_title(catalog):
    for c in catalog.controls:
        assert c.title and str(c.title).strip(), f"{c.id} has no title"


def test_profiles_and_assessments_use_the_benchmark_vocabulary(catalog):
    for c in catalog.controls:
        assert c.profile in ("Level 1", "Level 2"), f"{c.id}: profile {c.profile!r}"
        assert c.assessment in ("Manual", "Automated"), f"{c.id}: assessment {c.assessment!r}"
    levels = [c.level for c in catalog.controls]
    assert levels.count(1) == LEVEL1
    assert levels.count(2) == LEVEL2
    automated = [c for c in catalog.controls if c.assessment == "Automated"]
    manual = [c for c in catalog.controls if c.assessment == "Manual"]
    assert len(automated) == AUTOMATED
    assert len(manual) == MANUAL_ASSESS


def test_capability_counts_are_what_the_readme_promises(catalog):
    assert len([c for c in catalog.controls if c.remediable()]) == REMEDIABLE
    assert len([c for c in catalog.controls if c.detectable()]) == DETECTABLE
    assert len([c for c in catalog.controls if c.manual()]) == NOT_ACTIONABLE


def test_remediable_and_detectable_controls_name_a_real_stack(catalog):
    known = set(C.HARDENING_STACKS["tencent"])
    for c in catalog.controls:
        if c.remediable() or c.detectable():
            assert c.stack is not None, f"{c.id}: actionability requires a stack"
            assert c.stack in known, f"{c.id}: stack {c.stack} not in registry"


def test_manual_controls_do_not_pretend_to_own_a_stack(catalog):
    for c in catalog.controls:
        if c.manual():
            assert c.stack is None, f"{c.id}: manual control must not own a stack"


def test_every_control_carries_at_least_one_tag(catalog):
    for c in catalog.controls:
        assert len(c.tags) >= 1, f"{c.id} has no tags"


def test_tags_are_lowercase_kebab_case(catalog):
    import re

    for c in catalog.controls:
        for tag in c.tags:
            assert re.match(r"^[a-z0-9]+(-[a-z0-9]+)*$", tag), f"{c.id}: tag {tag!r}"


def test_lookup_by_id(catalog):
    assert catalog["4.1"].title == catalog["4.1"].title
    assert catalog["9.99"] is None


def test_enabled_is_the_default_baseline(catalog):
    assert len([c for c in catalog.controls if c.enabled]) == catalog.size


def test_duplicate_ids_are_rejected_at_load_time():
    raw = {
        "benchmark": "x", "version": "v1", "sections": {"1": "One"},
        "controls": [
            {"id": "1.1", "title": "a"},
            {"id": "1.1", "title": "b"},
        ],
    }
    from ohbs_cloud.catalog import Catalog

    with pytest.raises(C.Error, match="duplicate control ids"):
        Catalog(raw)


def test_a_remediable_control_without_a_stack_is_rejected():
    raw = {
        "benchmark": "x", "version": "v1", "sections": {"1": "One"},
        "controls": [{"id": "1.1", "title": "a", "remediate": "terraform"}],
    }
    from ohbs_cloud.catalog import Catalog

    with pytest.raises(C.Error, match="requires a stack"):
        Catalog(raw)


def test_a_malformed_stack_name_is_rejected():
    raw = {
        "benchmark": "x", "version": "v1", "sections": {"1": "One"},
        "controls": [{"id": "1.1", "title": "a", "remediate": "terraform", "stack": "Bad Name"}],
    }
    from ohbs_cloud.catalog import Catalog

    with pytest.raises(C.Error, match="malformed stack"):
        Catalog(raw)


def test_a_malformed_id_is_rejected():
    raw = {
        "benchmark": "x", "version": "v1", "sections": {"1": "One"},
        "controls": [{"id": "1", "title": "a"}],
    }
    from ohbs_cloud.catalog import Catalog

    with pytest.raises(C.Error, match="control id must look like"):
        Catalog(raw)


def test_a_missing_registry_is_reported_clearly():
    from ohbs_cloud.catalog import Catalog

    with pytest.raises(C.Error, match="control registry not found"):
        Catalog.load("/nonexistent/controls.yml")
