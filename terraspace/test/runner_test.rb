# frozen_string_literal: true

require "stringio"
require_relative "test_helper"

# The exit-code contract and the shape of the report. CI gates on these, so
# they are pinned here rather than left to whatever the code happens to do.
#
#   0  clean, or nothing to do
#   1  the scan found at least one failing control
#   2  the run itself broke (bad flags, terraspace failed)
class RunnerTest < CisTestCase
  # A Runner with terraspace and the state file stubbed out. Only the two
  # seams that touch the outside world are replaced; everything else is the
  # real code path.
  class FakeRunner < Cis::Runner
    attr_reader :commands

    def initialize(findings: [], exit_code: 0, **kwargs)
      super(**kwargs)
      @findings  = findings
      @exit_code = exit_code
      @commands  = []
    end

    private

    def terraspace(args, action:)
      @commands << { args: args, action: action }
      @exit_code
    end

    def read_findings
      @findings
    end
  end

  def build(selector:, findings: [], exit_code: 0, **options)
    @out = StringIO.new
    @err = StringIO.new
    FakeRunner.new(
      selector: selector, options: { format: "table", color: false }.merge(options),
      io: @out, err: @err, findings: findings, exit_code: exit_code
    )
  end

  def out
    @out.string
  end

  def err
    @err.string
  end

  def finding(id, status, evidence = "")
    { "id" => id, "title" => catalog[id].title, "status" => status, "evidence" => evidence }
  end

  # ---- exit codes ---------------------------------------------------------

  def test_a_clean_scan_exits_zero
    r = build(selector: select(only: %w[4.1]), findings: [finding("4.1", "PASS")])
    assert_equal Cis::Runner::EXIT_OK, r.scan
  end

  def test_a_failing_control_exits_one
    r = build(selector: select(only: %w[4.1]), findings: [finding("4.1", "FAIL", "bucket is public")])
    assert_equal Cis::Runner::EXIT_FINDING, r.scan
    assert_includes out, "FAIL"
    assert_includes out, "bucket is public"
  end

  def test_manual_rows_alone_do_not_fail_the_run
    # MANUAL is "we could not check", not "this is broken". Failing on it would
    # make the exit code useless for the 43 controls Terraform cannot assess.
    r = build(selector: select(only: %w[9.*]))
    assert_equal Cis::Runner::EXIT_OK, r.scan
    assert_includes out, "MANUAL"
    assert_empty r.commands, "a manual-only selection has nothing to deploy"
  end

  def test_a_broken_terraspace_run_exits_two
    r = build(selector: select(only: %w[4.1]), exit_code: 1)
    assert_equal Cis::Runner::EXIT_ERROR, r.scan
  end

  def test_a_failing_stack_stops_the_apply_and_exits_two
    r = build(selector: select(sections: %w[3 4]), exit_code: 1)
    assert_equal Cis::Runner::EXIT_ERROR, r.apply
    assert_equal 1, r.commands.size, "must not carry on to the next stack after a failure"
    assert_includes out, "stopping"
  end

  def test_destroy_of_an_unknown_stack_exits_two
    r = build(selector: select)
    assert_equal Cis::Runner::EXIT_ERROR, r.destroy("compute")
    assert_includes err, "is not a hardening stack"
  end

  # ---- what actually gets run --------------------------------------------

  def test_apply_issues_one_up_per_stack_in_order
    r = build(selector: select(sections: %w[3 4]))
    assert_equal Cis::Runner::EXIT_OK, r.apply
    # `terraspace up STACK` is the documented form - stack first, flags after.
    assert_equal [%w[up network -y], %w[up storage -y]], r.commands.map { |c| c[:args] }
    assert_equal %w[apply apply], r.commands.map { |c| c[:action] }
  end

  def test_apply_and_scan_agree_on_argument_order
    # A regression guard: these two were built by different code paths and
    # drifted apart once already.
    a = build(selector: select(sections: %w[4]))
    a.apply
    s = build(selector: select(sections: %w[4]), findings: [])
    s.scan
    assert_equal "up", a.commands.first[:args].first
    assert_equal "up", s.commands.first[:args].first
    assert_equal "-y", a.commands.first[:args].last
    assert_equal "-y", s.commands.first[:args].last
  end

  def test_plan_never_writes
    r = build(selector: select(sections: %w[4]))
    r.plan
    assert_equal [%w[plan storage]], r.commands.map { |c| c[:args] }
    refute_includes r.commands.flat_map { |c| c[:args] }, "up"
  end

  def test_scan_runs_the_audit_stack_and_nothing_else
    r = build(selector: select(sections: %w[4]), findings: [finding("4.1", "PASS")])
    r.scan
    assert_equal [%w[up audit -y]], r.commands.map { |c| c[:args] }
    assert_equal %w[scan], r.commands.map { |c| c[:action] }
  end

  def test_dry_run_issues_nothing
    %i[scan plan apply].each do |action|
      r = build(selector: select, dry_run: true)
      assert_equal Cis::Runner::EXIT_OK, r.public_send(action)
      assert_empty r.commands, "#{action} --dry-run reached terraspace"
    end
  end

  def test_the_child_environment_reproduces_the_selection
    sel = select(sections: %w[4], exclude: %w[4.6])
    r = build(selector: sel)
    r.apply
    # to_env is what bin/cis passes down; the tfvars ERB re-derives from it.
    assert_equal "4", sel.to_env["CIS_SECTIONS"]
    assert_equal "4.6", sel.to_env["CIS_EXCLUDE"]
    assert_equal %w[4.1 4.3 4.4 4.5 4.7],
                 Cis::Selector.from_env(catalog, sel.to_env).remediable.map(&:id)
  end

  # ---- honesty ------------------------------------------------------------

  def test_the_report_covers_every_selected_control_not_just_the_observable_ones
    sel = select(sections: %w[4])
    r = build(selector: sel, findings: %w[4.1 4.2 4.8 4.9].map { |id| finding(id, "PASS") })
    r.scan

    # 9 selected: 4 assessed, 5 accounted for as SKIPPED or MANUAL.
    catalog.controls.select { |c| c.section == "4" }.each do |c|
      assert_includes out, c.id, "#{c.id} vanished from the report"
    end
  end

  def test_controls_terraform_enforces_but_cannot_read_back_are_skipped_not_passed
    sel = select(only: %w[4.3])
    r = build(selector: sel)
    r.scan
    assert_includes out, "SKIPPED"
    # The table clips evidence at 34 columns, so assert the surviving prefix.
    assert_includes out, "enforced by `cis apply`, not read"
    refute_includes out, "PASS   "
  end

  def test_the_untruncated_evidence_survives_in_machine_output
    # Clipping is a rendering concern; json must carry the whole sentence.
    r = build(selector: select(only: %w[4.3]), format: "json")
    r.scan
    row = JSON.parse(out)["findings"].first
    assert_equal "SKIPPED", row["status"]
    assert_equal "enforced by `cis apply`, not readable", row["evidence"]
  end

  def test_apply_lists_the_controls_it_could_not_enforce
    r = build(selector: select(sections: %w[9]))
    assert_equal Cis::Runner::EXIT_OK, r.apply
    assert_includes out, "No selected control is enforceable by Terraform"
    assert_includes out, "Not enforced by Terraform (12)"
    assert_empty r.commands
  end

  def test_json_output_stays_parseable_because_prose_goes_to_stderr
    r = build(selector: select(sections: %w[9]), format: "json")
    r.scan
    payload = JSON.parse(out)
    assert_equal 12, payload["findings"].size
    refute_empty err, "the human-readable note should still be emitted, just not on stdout"
  end

  # ---- normalising whatever terraform gives us ---------------------------

  def test_findings_from_terraform_are_normalised_into_rows
    raw = { "4.1" => { "status" => "fail", "evidence" => "public" } }
    r = build(selector: select(only: %w[4.1]), findings: nil)
    rows = r.send(:normalize, raw)
    assert_equal 1, rows.size
    assert_equal "FAIL", rows.first["status"], "status must be upcased before it is compared"
    assert_equal catalog["4.1"].title, rows.first["title"], "titles come from the registry"
    assert_equal "public", rows.first["evidence"]
  end

  def test_an_unknown_id_from_terraform_does_not_crash_the_report
    r = build(selector: select(only: %w[4.1]))
    rows = r.send(:normalize, "9.99" => { "status" => "PASS" })
    assert_equal "(unknown control)", rows.first["title"]
  end
end
