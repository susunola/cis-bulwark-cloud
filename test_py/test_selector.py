"""Port of test/selector_test.rb — filter semantics and composition."""

from __future__ import annotations

import os

import pytest

import ohbs_cloud as C
from ohbs_cloud.catalog import Catalog
from ohbs_cloud.selector import Selector
from conftest import select


def test_no_filters_selects_the_whole_enabled_baseline(catalog):
    s = select()
    assert len(s.selected) == len([c for c in catalog.controls if c.enabled])
    assert len(s.selected) == catalog.size
    assert not s.is_empty()


def test_selection_is_always_sorted_numerically(catalog):
    s = select(sections=["2"])
    keys = [c.sort_key() for c in s.selected]
    assert keys == sorted(keys)


def test_only_takes_exact_ids():
    s = select(only=["3.5", "4.1"])
    assert s.ids == ["3.5", "4.1"]


def test_only_takes_globs(catalog):
    s = select(only=["4.*"])
    assert s.ids == [c.id for c in catalog.controls if c.section == "4"]


def test_only_replaces_the_enabled_baseline_rather_than_narrowing_it():
    raw = {
        "benchmark": "x", "version": "v1", "sections": {"1": "One"},
        "controls": [
            {"id": "1.1", "title": "on"},
            {"id": "1.2", "title": "off", "enabled": False},
        ],
    }
    cat = Catalog(raw)
    assert Selector(cat).ids == ["1.1"]
    assert Selector(cat, only=["1.2"]).ids == ["1.2"]


def test_only_that_matches_nothing_is_an_error_not_an_empty_run():
    with pytest.raises(C.Error, match="matches no control"):
        select(only=["4.99"])


def test_exclude_drops_ids_and_globs(catalog):
    s = select(only=["4.*"], exclude=["4.6"])
    assert "4.6" not in s.ids
    assert "4.5" in s.ids
    all4 = len([c for c in catalog.controls if c.section == "4"])
    assert len(s.ids) == all4 - 1


def test_exclude_is_applied_last_and_beats_only():
    assert select(only=["4.1"], exclude=["4.1"]).ids == []


def test_exclude_beats_tag_and_section_too():
    s = select(sections=["3"], tags=["security-group"], exclude=["3.*"])
    assert s.ids == []


def test_exclude_that_matches_nothing_is_an_error():
    with pytest.raises(C.Error, match="matches no control"):
        select(exclude=["7.99"])


def test_section_narrows_to_whole_benchmark_sections():
    s = select(sections=["3", "4"])
    assert sorted({c.section for c in s.selected}) == ["3", "4"]
    assert len(s.ids) == 16  # 7 networking + 9 storage


def test_section_narrows_only_it_does_not_widen():
    s = select(only=["4.1", "5.1"], sections=["4"])
    assert s.ids == ["4.1"]


def test_unknown_section_is_an_error():
    with pytest.raises(C.Error, match="unknown section"):
        select(sections=["42"])


def test_tag_matches_any_of_the_given_tags():
    s = select(tags=["mfa"])
    assert len(s.ids) > 0
    for c in s.selected:
        assert "mfa" in c.tags


def test_multiple_tags_are_a_union_not_an_intersection():
    mfa = set(select(tags=["mfa"]).ids)
    tde = set(select(tags=["tde"]).ids)
    both = set(select(tags=["mfa", "tde"]).ids)
    assert both == mfa | tde
    assert len(both) > len(mfa)


def test_unknown_tag_is_an_error():
    with pytest.raises(C.Error, match="unknown tag"):
        select(tags=["nonsense"])


def test_profile_level1_keeps_level1_only(catalog):
    s = select(profile="level1")
    assert {c.level for c in s.selected} == {1}
    assert len(s.ids) == len([c for c in catalog.controls if c.level == 1])


def test_profile_level2_is_cumulative(catalog):
    assert len(select(profile="level2").ids) == catalog.size


def test_profile_spellings_are_forgiving():
    canonical = select(profile="level1").ids
    for spelling in ["1", "l1", "L1", "Level 1", "level-1", "LEVEL1"]:
        assert select(profile=spelling).ids == canonical, f"profile {spelling!r}"


def test_blank_profile_means_no_profile_filter(catalog):
    assert select(profile="").profile is None
    assert select(profile=None).profile is None
    assert len(select(profile="  ").ids) == catalog.size


def test_unknown_profile_is_an_error():
    with pytest.raises(C.Error, match="unknown profile"):
        select(profile="level3")


def test_filters_compose():
    s = select(sections=["3", "4"], exclude=["4.6"], profile="level1")
    assert sorted({c.section for c in s.selected}) == ["3", "4"]
    assert "4.6" not in s.ids
    assert {c.level for c in s.selected} == {1}


def test_a_filter_combination_may_legitimately_select_nothing():
    s = select(only=["4.1"], tags=["mfa"])
    assert s.ids == []
    assert s.is_empty()


def test_selected_splits_cleanly_into_capabilities():
    s = select()
    assert len(s.selected) == len(s.remediable) + len(s.not_remediable)
    assert len(s.selected) == len(s.detectable) + len(s.not_detectable)
    manual = [c for c in s.selected if c.manual()]
    assert len(s.selected) == len(set(s.remediable) | set(s.detectable)) + len(manual)


def test_manual_controls_survive_filtering_so_scan_can_report_the_gap():
    s = select()
    manual = [c for c in s.selected if c.manual()]
    assert len(manual) == 43
    assert len([c for c in s.not_remediable if c.manual()]) == 43


def test_summary_is_internally_consistent(catalog):
    s = select(sections=["4"])
    sm = s.summary
    assert sm["selected"] == len(s.selected)
    assert sm["of"] == catalog.size
    assert sm["remediable"] == len(s.remediable)
    assert sm["detectable"] == len(s.detectable)
    assert sm["manual"] == len([c for c in s.selected if c.manual()])
    assert sm["stacks"] == ["storage"]


def test_stacks_for_apply_follows_the_declared_run_order():
    s = select()
    assert s.stacks_for_apply == C.hardening_stacks()


def test_stacks_for_apply_only_lists_stacks_with_work_to_do():
    assert select(only=["4.*"]).stacks_for_apply == ["storage"]
    assert select(sections=["3", "4"]).stacks_for_apply == ["network", "storage"]


def test_stacks_for_apply_ignores_controls_terraform_cannot_enforce():
    assert select(only=["4.2"]).stacks_for_apply == []
    assert len(select(only=["4.2"]).detectable) > 0


def test_from_env_reads_every_filter(catalog):
    env = {
        "CIS_ONLY": "3.*,4.1", "CIS_EXCLUDE": "3.7",
        "CIS_SECTIONS": "3,4", "CIS_TAGS": "security-group,public-access",
        "CIS_PROFILE": "level1",
    }
    s = Selector.from_env(catalog, env)
    assert s.only == ["3.*", "4.1"]
    assert s.exclude == ["3.7"]
    assert s.sections == ["3", "4"]
    assert s.tags == ["security-group", "public-access"]
    assert s.profile == 1


def test_from_env_tolerates_whitespace_and_empty_entries(catalog):
    s = Selector.from_env(catalog, {"CIS_ONLY": " 3.5 , ,4.1 "})
    assert s.only == ["3.5", "4.1"]


def test_to_env_reproduces_the_same_selection(catalog):
    original = select(sections=["3", "4"], exclude=["4.6"], profile="level1", tags=["cos", "ssh"])
    rebuilt = Selector.from_env(catalog, original.to_env)
    assert original.ids == rebuilt.ids


def test_to_env_of_an_unfiltered_selection_is_all_blank():
    assert set(select().to_env.values()) == {""}


def test_controls_for_stack_is_remediable_and_owned():
    os.environ["CIS_SECTIONS"] = "4"
    C.reset()
    ids = C.controls_for_stack("storage")
    assert ids == ["4.1", "4.3", "4.4", "4.5", "4.6", "4.7"]
    assert "4.2" not in ids, "4.2 is detect-only and must never be handed to a hardening stack"
    assert C.controls_for_stack("network") == []


def test_controls_for_audit_is_the_detectable_slice():
    os.environ["CIS_SECTIONS"] = "4"
    C.reset()
    assert C.controls_for_audit() == ["4.1", "4.2", "4.8", "4.9"]


def test_hardening_stacks_are_known_for_apply():
    os.environ["CIS_ONLY"] = "4.*"
    C.reset()
    assert C.get_selector().stacks_for_apply == ["storage"]


def test_scan_of_a_purely_manual_selection_returns_no_apply_stacks():
    os.environ["CIS_SECTIONS"] = "9"
    C.reset()
    assert C.get_selector().stacks_for_apply == []


def test_reset_picks_up_a_changed_environment(catalog):
    assert len(C.get_selector().selected) == catalog.size
    os.environ["CIS_SECTIONS"] = "4"
    assert len(C.get_selector().selected) == catalog.size, "selector should be memoised"
    C.reset()
    assert len(C.get_selector().selected) == 9
