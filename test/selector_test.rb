# frozen_string_literal: true

require_relative "test_helper"

# Filtering is the first design requirement: an operator must be able
# to say exactly which CIS items get hardened. These tests pin the semantics of
# every flag and, more importantly, of their interaction.
class SelectorTest < CisTestCase
  # ---- baseline -----------------------------------------------------------

  def test_no_filters_selects_the_whole_enabled_baseline
    s = select
    assert_equal catalog.controls.count(&:enabled), s.selected.size
    assert_equal catalog.size, s.selected.size
    refute s.empty?
  end

  def test_selection_is_always_sorted_numerically
    s = select(sections: %w[2])
    assert_equal s.selected.map(&:sort_key).sort, s.selected.map(&:sort_key)
  end

  # ---- --only -------------------------------------------------------------

  def test_only_takes_exact_ids
    s = select(only: %w[3.5 4.1])
    assert_equal %w[3.5 4.1], s.ids
  end

  def test_only_takes_globs
    s = select(only: %w[4.*])
    assert_equal catalog.controls.select { |c| c.section == "4" }.map(&:id), s.ids
  end

  def test_only_replaces_the_enabled_baseline_rather_than_narrowing_it
    # A control switched off in the registry must still be reachable when the
    # operator names it explicitly - that is what "authoritative" means here.
    raw = {
      "benchmark" => "x", "version" => "v1", "sections" => { "1" => "One" },
      "controls" => [
        { "id" => "1.1", "title" => "on" },
        { "id" => "1.2", "title" => "off", "enabled" => false }
      ]
    }
    cat = Cis::Catalog.new(raw)
    assert_equal %w[1.1], Cis::Selector.new(cat).ids
    assert_equal %w[1.2], Cis::Selector.new(cat, only: %w[1.2]).ids
  end

  def test_only_that_matches_nothing_is_an_error_not_an_empty_run
    err = assert_raises(Cis::Error) { select(only: %w[4.99]) }
    assert_match(/matches no control/, err.message)
  end

  # ---- --exclude ----------------------------------------------------------

  def test_exclude_drops_ids_and_globs
    s = select(only: %w[4.*], exclude: %w[4.6])
    refute_includes s.ids, "4.6"
    assert_includes s.ids, "4.5"

    all4 = catalog.controls.count { |c| c.section == "4" }
    assert_equal all4 - 1, s.ids.size
  end

  def test_exclude_is_applied_last_and_beats_only
    assert_empty select(only: %w[4.1], exclude: %w[4.1]).ids
  end

  def test_exclude_beats_tag_and_section_too
    s = select(sections: %w[3], tags: %w[security-group], exclude: %w[3.*])
    assert_empty s.ids
  end

  def test_exclude_that_matches_nothing_is_an_error
    assert_raises(Cis::Error) { select(exclude: %w[7.99]) }
  end

  # ---- --section ----------------------------------------------------------

  def test_section_narrows_to_whole_benchmark_sections
    s = select(sections: %w[3 4])
    assert_equal %w[3 4], s.selected.map(&:section).uniq.sort
    assert_equal 16, s.ids.size # 7 networking + 9 storage
  end

  def test_section_narrows_only_it_does_not_widen
    s = select(only: %w[4.1 5.1], sections: %w[4])
    assert_equal %w[4.1], s.ids
  end

  def test_unknown_section_is_an_error
    err = assert_raises(Cis::Error) { select(sections: %w[42]) }
    assert_match(/unknown section/, err.message)
  end

  # ---- --tag --------------------------------------------------------------

  def test_tag_matches_any_of_the_given_tags
    s = select(tags: %w[mfa])
    refute_empty s.ids
    s.selected.each { |c| assert_includes c.tags, "mfa" }
  end

  def test_multiple_tags_are_a_union_not_an_intersection
    mfa = select(tags: %w[mfa]).ids
    tde = select(tags: %w[tde]).ids
    both = select(tags: %w[mfa tde]).ids
    assert_equal (mfa | tde).sort, both.sort
    assert_operator both.size, :>, mfa.size
  end

  def test_unknown_tag_is_an_error
    err = assert_raises(Cis::Error) { select(tags: %w[nonsense]) }
    assert_match(/unknown tag/, err.message)
  end

  # ---- --profile ----------------------------------------------------------

  def test_profile_level1_keeps_level1_only
    s = select(profile: "level1")
    assert_equal [1], s.selected.map(&:level).uniq
    assert_equal catalog.controls.count { |c| c.level == 1 }, s.ids.size
  end

  def test_profile_level2_is_cumulative
    # CIS profiles nest: an L2 baseline includes every L1 recommendation.
    assert_equal catalog.size, select(profile: "level2").ids.size
  end

  def test_profile_spellings_are_forgiving
    canonical = select(profile: "level1").ids
    ["1", "l1", "L1", "Level 1", "level-1", "LEVEL1"].each do |spelling|
      assert_equal canonical, select(profile: spelling).ids, "profile #{spelling.inspect}"
    end
  end

  def test_blank_profile_means_no_profile_filter
    assert_nil select(profile: "").profile
    assert_nil select(profile: nil).profile
    assert_equal catalog.size, select(profile: "  ").ids.size
  end

  def test_unknown_profile_is_an_error
    err = assert_raises(Cis::Error) { select(profile: "level3") }
    assert_match(/unknown profile/, err.message)
  end

  # ---- composition --------------------------------------------------------

  def test_filters_compose
    s = select(sections: %w[3 4], exclude: %w[4.6], profile: "level1")
    assert_equal %w[3 4], s.selected.map(&:section).uniq.sort
    refute_includes s.ids, "4.6"
    assert_equal [1], s.selected.map(&:level).uniq
  end

  def test_a_filter_combination_may_legitimately_select_nothing
    # Each filter is valid on its own, so this is not an error - but it must
    # be visible, which is what bin/cis-cloud checks with `selector.empty?`.
    s = select(only: %w[4.1], tags: %w[mfa])
    assert_empty s.ids
    assert s.empty?
  end

  # ---- capability partitioning -------------------------------------------

  def test_selected_splits_cleanly_into_capabilities
    s = select
    assert_equal s.selected.size, s.remediable.size + s.not_remediable.size
    assert_equal s.selected.size, s.detectable.size + s.not_detectable.size
    assert_equal s.selected.size, (s.remediable | s.detectable).size + s.selected.count(&:manual?)
  end

  def test_manual_controls_survive_filtering_so_scan_can_report_the_gap
    # Dropping them would turn a 43-control blind spot into a green report.
    s = select
    assert_equal 43, s.selected.count(&:manual?)
    assert_equal 43, s.not_remediable.count(&:manual?)
  end

  def test_summary_is_internally_consistent
    s = select(sections: %w[4])
    sm = s.summary
    assert_equal s.selected.size, sm["selected"]
    assert_equal catalog.size, sm["of"]
    assert_equal s.remediable.size, sm["remediable"]
    assert_equal s.detectable.size, sm["detectable"]
    assert_equal s.selected.count(&:manual?), sm["manual"]
    assert_equal %w[storage], sm["stacks"]
  end

  # ---- stack routing ------------------------------------------------------

  def test_stacks_for_apply_follows_the_declared_run_order
    s = select
    assert_equal hardening_stacks, s.stacks_for_apply
  end

  def test_stacks_for_apply_only_lists_stacks_with_work_to_do
    assert_equal %w[storage], select(only: %w[4.*]).stacks_for_apply
    assert_equal %w[network storage], select(sections: %w[3 4]).stacks_for_apply
  end

  def test_stacks_for_apply_ignores_controls_terraform_cannot_enforce
    # 4.2 is detect-only; selecting it alone must not schedule a write.
    assert_empty select(only: %w[4.2]).stacks_for_apply
    refute_empty select(only: %w[4.2]).detectable
  end

  # ---- env round trip -----------------------------------------------------

  def test_from_env_reads_every_filter
    env = {
      "CIS_ONLY" => "3.*,4.1", "CIS_EXCLUDE" => "3.7",
      "CIS_SECTIONS" => "3,4", "CIS_TAGS" => "security-group,public-access",
      "CIS_PROFILE" => "level1"
    }
    s = Cis::Selector.from_env(catalog, env)
    assert_equal %w[3.* 4.1], s.only
    assert_equal %w[3.7], s.exclude
    assert_equal %w[3 4], s.sections
    assert_equal %w[security-group public-access], s.tags
    assert_equal 1, s.profile
  end

  def test_from_env_tolerates_whitespace_and_empty_entries
    s = Cis::Selector.from_env(catalog, "CIS_ONLY" => " 3.5 , ,4.1 ")
    assert_equal %w[3.5 4.1], s.only
  end

  def test_to_env_reproduces_the_same_selection
    original = select(sections: %w[3 4], exclude: %w[4.6], profile: "level1", tags: %w[cos ssh])
    rebuilt  = Cis::Selector.from_env(catalog, original.to_env)
    assert_equal original.ids, rebuilt.ids
  end

  def test_to_env_of_an_unfiltered_selection_is_all_blank
    assert_equal [""], select.to_env.values.uniq
  end

  # ---- module-level wiring ------------------------------------------------

  def test_controls_for_stack_is_remediable_and_owned
    with_env("CIS_SECTIONS" => "4") do
      ids = Cis.controls_for_stack("storage")
      assert_equal %w[4.1 4.3 4.4 4.5 4.6 4.7], ids
      refute_includes ids, "4.2", "4.2 is detect-only and must never be handed to a hardening stack"
      assert_empty Cis.controls_for_stack("network")
    end
  end

  def test_controls_for_audit_is_the_detectable_slice
    with_env("CIS_SECTIONS" => "4") do
      assert_equal %w[4.1 4.2 4.8 4.9], Cis.controls_for_audit
    end
  end

  def test_hardening_stacks_are_known_for_apply
    with_env("CIS_ONLY" => "4.*") do
      assert_equal %w[storage], Cis.selector.stacks_for_apply
    end
  end

  def test_scan_of_a_purely_manual_selection_returns_no_apply_stacks
    with_env("CIS_SECTIONS" => "9") do
      assert_empty Cis.selector.stacks_for_apply
    end
  end

  def test_reset_picks_up_a_changed_environment
    with_env do
      assert_equal catalog.size, Cis.selector.selected.size
      ENV["CIS_SECTIONS"] = "4"
      assert_equal catalog.size, Cis.selector.selected.size, "selector should be memoised"
      Cis.reset!
      assert_equal 9, Cis.selector.selected.size
    end
  end
end
