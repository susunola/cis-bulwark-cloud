# frozen_string_literal: true

require_relative "test_helper"

# config/controls.yml is the spine of the project: the CLI filters it, the
# stacks are gated by it, and the audit stack reports against it. If it drifts
# from the published benchmark, everything downstream lies with confidence.
class CatalogTest < CisTestCase
  # Straight from CIS Tencent Cloud Foundation Benchmark v1.0.0.
  TOTAL           = 91
  SECTION_SIZES   = { "1" => 16, "2" => 20, "3" => 7, "4" => 9, "5" => 6,
                      "6" => 9, "7" => 6, "8" => 6, "9" => 12 }.freeze
  LEVEL1          = 67
  LEVEL2          = 24
  AUTOMATED       = 25
  MANUAL_ASSESS   = 66

  # What cis can do about them.
  REMEDIABLE      = 39
  DETECTABLE      = 20
  NOT_ACTIONABLE  = 43

  def test_registry_covers_the_whole_benchmark
    assert_equal TOTAL, catalog.size,
                 "the benchmark has #{TOTAL} recommendations"
  end

  def test_section_sizes_match_the_benchmark
    actual = catalog.controls.group_by(&:section).transform_values(&:size)
    assert_equal SECTION_SIZES, actual
  end

  def test_every_section_has_a_title
    catalog.sections.each do |id, title|
      refute_nil title
      refute_empty title.to_s.strip, "section #{id} has no title"
      refute_match(/\ASection /, title, "section #{id} fell back to a placeholder title")
    end
    assert_equal SECTION_SIZES.keys.sort, catalog.sections.keys.sort
  end

  def test_ids_are_unique
    dupes = catalog.ids.tally.select { |_, n| n > 1 }.keys
    assert_empty dupes, "duplicate control ids: #{dupes.join(', ')}"
  end

  def test_ids_are_well_formed_and_belong_to_their_section
    catalog.controls.each do |c|
      assert_match(/\A\d+\.\d+\z/, c.id)
      assert_includes SECTION_SIZES.keys, c.section, "#{c.id} is in an unknown section"
    end
  end

  def test_controls_are_sorted_numerically_not_lexically
    # "3.10" must land after "3.9"; a string sort would put it before "3.2".
    section3 = catalog.controls.select { |c| c.section == "2" }.map(&:id)
    assert_equal section3.sort_by { |id| id.split(".").map(&:to_i) }, section3
    assert_operator catalog.ids.index("2.20"), :>, catalog.ids.index("2.9"),
                    "2.20 sorted before 2.9 - sort_key is doing a string compare"
  end

  def test_every_control_has_a_title
    blank = catalog.controls.reject { |c| c.title.to_s.strip.length > 3 }
    assert_empty blank.map(&:id), "controls with an unusable title"
  end

  def test_profiles_and_assessments_use_the_benchmark_vocabulary
    assert_equal ["Level 1", "Level 2"], catalog.controls.map(&:profile).uniq.sort
    assert_equal %w[Automated Manual], catalog.controls.map(&:assessment).uniq.sort

    assert_equal LEVEL1, catalog.controls.count { |c| c.level == 1 }
    assert_equal LEVEL2, catalog.controls.count { |c| c.level == 2 }
    assert_equal AUTOMATED, catalog.controls.count { |c| c.assessment == "Automated" }
    assert_equal MANUAL_ASSESS, catalog.controls.count { |c| c.assessment == "Manual" }
  end

  def test_capability_counts_are_what_the_readme_promises
    assert_equal REMEDIABLE, catalog.controls.count(&:remediable?)
    assert_equal DETECTABLE, catalog.controls.count(&:detectable?)
    assert_equal NOT_ACTIONABLE, catalog.controls.count(&:manual?)

    # No control may be counted twice, and none may fall through the cracks.
    covered = catalog.controls.count { |c| c.remediable? || c.detectable? }
    assert_equal TOTAL, covered + NOT_ACTIONABLE
  end

  def test_remediable_and_detectable_controls_name_a_real_stack
    catalog.controls.each do |c|
      next if c.manual?
      refute_nil c.stack, "#{c.id} is actionable but has no stack"
      assert_includes hardening_stacks, c.stack, "#{c.id} names an unknown stack"
    end
  end

  def test_manual_controls_do_not_pretend_to_own_a_stack
    liars = catalog.controls.select { |c| c.manual? && c.stack }
    assert_empty liars.map(&:id),
                 "manual controls must not claim a stack - it implies coverage that is not there"
  end

  def test_every_control_carries_at_least_one_tag
    untagged = catalog.controls.select { |c| c.tags.empty? }
    assert_empty untagged.map(&:id), "--tag can never reach these"
  end

  def test_tags_are_lowercase_kebab_case
    bad = catalog.controls.flat_map(&:tags).uniq.reject { |t| t =~ /\A[a-z0-9]+(-[a-z0-9]+)*\z/ }
    assert_empty bad, "tags must be lowercase kebab-case so --tag is predictable"
  end

  def test_lookup_by_id
    c = catalog["4.1"]
    refute_nil c
    assert_equal "4.1", c.id
    assert_equal "storage", c.stack
    assert_nil catalog["4.99"]
  end

  def test_enabled_is_the_default_baseline
    # Nothing is switched off out of the box: an operator who runs `cis list`
    # with no flags must see the entire benchmark.
    assert_equal TOTAL, catalog.controls.count(&:enabled)
  end

  # ---- the loader itself --------------------------------------------------

  def test_duplicate_ids_are_rejected_at_load_time
    raw = {
      "benchmark" => "x", "version" => "v1", "sections" => { "1" => "One" },
      "controls" => [
        { "id" => "1.1", "title" => "a" },
        { "id" => "1.1", "title" => "b" }
      ]
    }
    err = assert_raises(Cis::Error) { Cis::Catalog.new(raw) }
    assert_match(/duplicate control ids/, err.message)
  end

  def test_a_remediable_control_without_a_stack_is_rejected
    err = assert_raises(Cis::Error) do
      Cis::Control.new("id" => "1.1", "title" => "a", "remediate" => "terraform")
    end
    assert_match(/requires a stack/, err.message)
  end

  def test_an_unknown_stack_is_rejected
    err = assert_raises(Cis::Error) do
      Cis::Control.new("id" => "1.1", "title" => "a", "stack" => "compute")
    end
    assert_match(/unknown stack/, err.message)
  end

  def test_a_malformed_id_is_rejected
    err = assert_raises(Cis::Error) { Cis::Control.new("id" => "1", "title" => "a") }
    assert_match(/must look like/, err.message)
  end

  def test_a_missing_registry_is_reported_clearly
    err = assert_raises(Cis::Error) { Cis::Catalog.load("/nope/controls.yml") }
    assert_match(/control registry not found/, err.message)
  end
end
