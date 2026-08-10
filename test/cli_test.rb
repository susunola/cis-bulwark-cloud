# frozen_string_literal: true

require_relative "test_helper"

# End-to-end behaviour of bin/cis. Every test here uses --dry-run, so nothing
# reaches terraform or a cloud API - what is being asserted is the
# contract between the flags the operator types and the commands that would be
# issued on their behalf.
class CliTest < CisTestCase
  def cis(*args, **kwargs)
    CisTest.run_cli(*args, **kwargs)
  end

  # ---- plumbing -----------------------------------------------------------

  def test_help_lists_every_command_and_filter
    r = cis("--help")
    assert_equal 0, r.status, r
    %w[list scan plan apply destroy].each { |c| assert_includes r.stdout, c }
    %w[--only --exclude --section --tag --profile --dry-run --format].each do |flag|
      assert_includes r.stdout, flag
    end
  end

  def test_no_command_is_a_usage_error
    r = cis
    assert_equal 2, r.status
    assert_includes r.stderr, "Usage:"
  end

  def test_unknown_command_is_rejected
    r = cis("harden")
    assert_equal 2, r.status
    assert_includes r.stderr, "unknown command"
  end

  def test_unknown_flag_is_rejected
    r = cis("list", "--everything")
    assert_equal 2, r.status
    assert_includes r.stderr, "invalid option"
  end

  def test_an_invalid_format_is_rejected
    r = cis("list", "--format", "yaml")
    assert_equal 2, r.status
  end

  # ---- cis list -----------------------------------------------------------

  def test_list_shows_the_whole_benchmark_by_default
    r = cis("list")
    assert_equal 0, r.status, r
    assert_includes r.stdout, "CIS Tencent Cloud Foundation Benchmark v1.0.0"
    assert_includes r.stdout, "selected 91/91 controls"
    assert_includes r.stdout, "remediable 39  detectable 20  manual 43"
    assert_includes r.stdout, "stacks: iam, logging, network, storage, database, kubernetes"
  end

  def test_list_groups_by_section
    r = cis("list")
    assert_includes r.stdout, "1 Identity and Access Management"
    assert_includes r.stdout, "9 Tencent Container Security Service"
  end

  def test_list_json_is_machine_readable_and_self_consistent
    r = cis("list", "--format", "json", "--section", "4")
    assert_equal 0, r.status, r

    payload = r.json
    assert_equal "v1.0.0", payload["version"]
    assert_equal 9, payload["summary"]["selected"]
    assert_equal 91, payload["summary"]["of"]
    assert_equal 9, payload["controls"].size
    assert_equal %w[storage], payload["summary"]["stacks"]

    ids = payload["controls"].map { |c| c["id"] }
    assert_equal %w[4.1 4.2 4.3 4.4 4.5 4.6 4.7 4.8 4.9], ids

    # 4.2 is observable but not fixable; the report has to say so.
    detect_only = payload["controls"].find { |c| c["id"] == "4.2" }
    assert_equal "detect", detect_only["capability"]
    assert_equal "remediate+detect", payload["controls"].find { |c| c["id"] == "4.1" }["capability"]
  end

  def test_list_markdown_renders_a_table
    r = cis("list", "--format", "markdown", "--only", "4.1")
    assert_equal 0, r.status, r
    assert_includes r.stdout, "| ID | Profile | Assessment | Title | Capability | Stack |"
    assert_includes r.stdout, "| 4.1 |"
  end

  def test_list_is_the_one_command_that_tolerates_an_empty_selection
    r = cis("list", "--only", "4.1", "--tag", "mfa")
    assert_equal 0, r.status, r
    assert_includes r.stdout, "selected 0/91"
  end

  # ---- filtering ----------------------------------------------------------

  def test_only_filters_down_to_one_stack
    r = cis("apply", "--only", "4.*", "--dry-run")
    assert_equal 0, r.status, r
    assert_includes r.stdout, "terraform -chdir=stacks/storage"
    assert_includes r.stdout, "4.1, 4.3, 4.4, 4.5, 4.6, 4.7"
    refute_includes r.stdout, "network"
    # 4.2 and 4.8/4.9 are not remediable and must not be implied.
    refute_match(/storage.*4\.2/, r.stdout)
  end

  def test_section_and_exclude_compose
    r = cis("apply", "--section", "3,4", "--exclude", "4.6", "--dry-run")
    assert_equal 0, r.status, r
    assert_match(%r{terraform -chdir=stacks/network\s+apply}, r.stdout)
    assert_match(%r{terraform -chdir=stacks/storage\s+apply}, r.stdout)
    refute_includes r.stdout, "4.6"
  end

  def test_tag_can_span_stacks
    r = cis("apply", "--tag", "cos", "--dry-run")
    assert_equal 0, r.status, r
    assert_includes r.stdout, "terraform -chdir=stacks/logging"
    assert_includes r.stdout, "terraform -chdir=stacks/storage"
  end

  def test_profile_narrows_by_level
    r = cis("list", "--profile", "level1", "--format", "json")
    assert_equal 0, r.status, r
    assert_equal 67, r.json["summary"]["selected"]
    assert_equal ["Level 1"], r.json["controls"].map { |c| c["profile"] }.uniq
  end

  def test_a_filter_that_matches_nothing_fails_loudly
    r = cis("list", "--only", "4.99")
    assert_equal 2, r.status
    assert_includes r.stderr, "matches no control"
  end

  def test_a_selection_of_zero_controls_refuses_to_run
    r = cis("apply", "--only", "4.1", "--exclude", "4.1", "--dry-run")
    assert_equal 2, r.status
    assert_includes r.stderr, "select 0 controls"
  end

  def test_cli_flags_override_inherited_environment
    r = cis("list", "--format", "json", "--section", "4", env: { "CIS_SECTIONS" => "3" })
    assert_equal 0, r.status, r
    assert_equal %w[4], r.json["controls"].map { |c| c["id"].split(".").first }.uniq
  end

  def test_filters_can_come_from_the_environment_alone
    r = cis("list", "--format", "json", env: { "CIS_SECTIONS" => "5" })
    assert_equal 0, r.status, r
    assert_equal 6, r.json["summary"]["selected"]
  end

  # ---- cis plan / apply ---------------------------------------------------

  def test_plan_and_apply_differ_only_in_the_verb
    plan  = cis("plan", "--only", "4.*", "--dry-run")
    apply = cis("apply", "--only", "4.*", "--dry-run")
    assert_match(%r{stacks/storage\s+plan\b}, plan.stdout)
    assert_match(%r{stacks/storage\s+apply\b}, apply.stdout)
    assert_includes plan.stdout,  "Will plan:"
    assert_includes apply.stdout, "Will apply:"
  end

  def test_apply_runs_stacks_in_the_declared_order
    r = cis("apply", "--dry-run")
    assert_equal 0, r.status, r
    order = r.stdout.scan(%r{terraform -chdir=stacks/(\w+)\s+apply}).flatten
    assert_equal Cis.hardening_stacks, order,
                 "stack order must be deterministic so reruns are comparable"
  end

  def test_apply_prints_the_selection_summary_first
    r = cis("apply", "--dry-run")
    assert_match(/Selection: 91\/91 controls\s+\(remediable 39, detectable 20, manual 43\)/, r.stdout)
  end

  def test_apply_never_schedules_a_stack_for_a_detect_only_control
    r = cis("apply", "--only", "4.2", "--dry-run")
    assert_equal 0, r.status, r
    assert_includes r.stdout, "No selected control is enforceable by Terraform"
    refute_includes r.stdout, "terraform -chdir=stacks/"
  end

  def test_apply_names_the_controls_it_cannot_enforce
    r = cis("apply", "--only", "4.2", "--dry-run")
    assert_includes r.stdout, "Not enforced by Terraform (1)"
    assert_includes r.stdout, "4.2"
  end

  def test_a_purely_manual_selection_is_reported_not_silently_skipped
    r = cis("apply", "--section", "9", "--dry-run")
    assert_equal 0, r.status, r
    assert_includes r.stdout, "No selected control is enforceable by Terraform"
    assert_includes r.stdout, "Not enforced by Terraform (12)"
  end

  # ---- cis scan -----------------------------------------------------------

  def test_scan_targets_the_read_only_audit_stack
    r = cis("scan", "--only", "4.*", "--dry-run")
    assert_equal 0, r.status, r
    assert_includes r.stdout, "read-only"
    assert_includes r.stdout, "terraform -chdir=stacks/audit apply"
    assert_includes r.stdout, "4.1, 4.2, 4.8, 4.9"
    Cis.hardening_stacks.each { |s| refute_match(/-chdir=stacks\/#{s}\b/, r.stdout) }
  end

  def test_scan_assesses_only_what_the_provider_can_observe
    r = cis("scan", "--profile", "level1", "--dry-run")
    assert_equal 0, r.status, r
    ids = r.stdout[/# (.*)$/, 1].split(", ")
    assert_equal 15, ids.size
    ids.each { |id| assert_equal 1, catalog[id].level }
    assert ids.all? { |id| catalog[id].detectable? }
  end

  def test_scan_of_an_unobservable_selection_says_so_instead_of_reporting_pass
    r = cis("scan", "--section", "9", "--dry-run")
    assert_equal 0, r.status, r
    assert_includes r.stdout, "No selected control is machine-assessable"
    refute_includes r.stdout, "terraform -chdir"
  end

  def test_scan_reports_unassessable_controls_as_manual_not_pass
    # Section 9 is entirely manual, so the table must be MANUAL rows only.
    r = cis("scan", "--section", "9", "--dry-run", "--format", "json")
    assert_equal 0, r.status, r
    payload = r.json
    assert_equal 12, payload["summary"]["MANUAL"]
    assert_equal 0, payload["summary"]["PASS"]
    assert_equal 0, payload["summary"]["FAIL"]
    assert_equal 12, payload["findings"].size
    payload["findings"].each { |f| assert_equal "MANUAL", f["status"] }
  end

  # ---- html output / reports ---------------------------------------------

  def test_list_html_is_a_self_contained_document
    r = cis("list", "--format", "html", "--only", "4.1")
    assert_equal 0, r.status, r
    assert_includes r.stdout, "<!DOCTYPE html>"
    assert_includes r.stdout, "<title>"
    assert_includes r.stdout, "4.1"
    assert_includes r.stdout, "<table"
  end

  def test_scan_html_renders_manual_findings
    # Section 9 is entirely manual, so the HTML must carry MANUAL rows.
    r = cis("scan", "--section", "9", "--format", "html", "--dry-run")
    assert_equal 0, r.status, r
    assert_includes r.stdout, "<!DOCTYPE html>"
    assert_includes r.stdout, "MANUAL"
    assert_includes r.stdout, "9.1"
  end

  def test_scan_html_carries_account_header_and_filter
    # The report header must name the account (UIN / name) and ship a filter.
    r = cis("scan", "--section", "9", "--format", "html", "--dry-run",
            env: { "CIS_UIN" => "100012345678", "CIS_ACCOUNT_NAME" => "acme-prod" })
    assert_equal 0, r.status, r
    assert_includes r.stdout, "UIN"
    assert_includes r.stdout, "100012345678"
    assert_includes r.stdout, "Account name"
    assert_includes r.stdout, "acme-prod"
    # client-side filtering: button bar + per-row data attributes + script.
    assert_includes r.stdout, "filter-btn"
    assert_includes r.stdout, "Enforced"
    assert_includes r.stdout, "Not enforced"
    assert_includes r.stdout, "data-status=\"MANUAL\""
    assert_includes r.stdout, "applyFilter"
  end

  def test_output_writes_html_to_a_file
    path = File.join(Dir.tmpdir, "cis_list_#{Process.pid}.html")
    r = cis("list", "--format", "html", "--only", "4.1", "--output", path)
    assert_equal 0, r.status, r
    assert File.exist?(path), "report file not created"
    html = File.read(path)
    assert_includes html, "<!DOCTYPE html>"
    assert_includes html, "4.1"
  ensure
    File.unlink(path) if path && File.exist?(path)
  end

  def test_apply_report_writes_hardening_html
    path = File.join(Dir.tmpdir, "cis_harden_#{Process.pid}.html")
    r = cis("apply", "--only", "4.*", "--dry-run", "--report", path)
    assert_equal 0, r.status, r
    assert File.exist?(path), "hardening report not created"
    html = File.read(path)
    assert_includes html, "<!DOCTYPE html>"
    assert_includes html, "storage"      # the stack that owns the 4.* controls
    assert_includes html, "planned"      # dry-run => planned, not ok/fail
  ensure
    File.unlink(path) if path && File.exist?(path)
  end

  def test_hardening_report_carries_account_header
    path = File.join(Dir.tmpdir, "cis_harden_acct_#{Process.pid}.html")
    r = cis("apply", "--only", "4.*", "--dry-run", "--report", path,
            env: { "CIS_UIN" => "100099999888", "CIS_ACCOUNT_NAME" => "acme-root" })
    assert_equal 0, r.status, r
    html = File.read(path)
    assert_includes html, "UIN"
    assert_includes html, "100099999888"
    assert_includes html, "Account name"
    assert_includes html, "acme-root"
  ensure
    File.unlink(path) if path && File.exist?(path)
  end

  def test_apply_report_default_path_when_no_value
    path = nil
    r = cis("apply", "--only", "4.*", "--dry-run", "--report")
    assert_equal 0, r.status, r
    m = (r.stdout + r.stderr).match(%r{written to (cis-hardening-\d{8}-\d{6}\.html)})
    assert m, "no report path announced"
    path = File.join(CisTest::ROOT, m[1])
    assert File.exist?(path), "report not created at #{path}"
  ensure
    File.unlink(path) if path && File.exist?(path)
  end

  # ---- cis destroy --------------------------------------------------------

  def test_destroy_needs_a_stack
    r = cis("destroy")
    assert_equal 2, r.status
    assert_includes r.stderr, "needs a stack name"
  end

  def test_destroy_refuses_an_unknown_stack
    r = cis("destroy", "compute", "--dry-run")
    assert_equal 2, r.status
    assert_includes r.stdout + r.stderr, "is not a hardening stack"
  end

  def test_destroy_refuses_the_audit_stack
    # There is nothing to destroy in a read-only stack, and allowing it here
    # would suggest `cis destroy` is the way to undo a scan.
    r = cis("destroy", "audit", "--dry-run")
    assert_equal 2, r.status
  end

  def test_destroy_accepts_a_hardening_stack
    r = cis("destroy", "storage", "--dry-run")
    assert_equal 0, r.status, r
  end

  # ---- multi-cloud ---------------------------------------------------------

  def test_cloud_flag_selects_the_aws_registry
    r = cis("--cloud", "aws", "list", "--no-color")
    assert_equal 0, r.status, r
    assert_includes r.stdout, "CIS Amazon Web Services Foundations Benchmark v7.0.0"
    assert_includes r.stdout, "6.3"
  end

  def test_cis_cloud_environment_variable_also_selects_the_cloud
    r = cis("list", "--only", "6.3", "--no-color", env: { "CIS_CLOUD" => "aws" })
    assert_equal 0, r.status, r
    assert_includes r.stdout, "CIS Amazon Web Services Foundations Benchmark"
  end

  def test_aws_scan_dry_run_uses_the_aws_stack_layout
    r = cis("--cloud", "aws", "scan", "--section", "6", "--dry-run")
    assert_equal 0, r.status, r
    assert_includes r.stdout, "terraform -chdir=stacks/aws/audit apply"
  end

  def test_aws_apply_dry_run_uses_aws_hardening_stacks
    r = cis("--cloud", "aws", "apply", "--only", "2.8", "--dry-run")
    assert_equal 0, r.status, r
    assert_match(%r{terraform -chdir=stacks/aws/iam\s+apply}, r.stdout)
  end

  def test_alibaba_list_and_scan_dry_run
    r = cis("--cloud", "alibaba", "list", "--only", "5.1", "--no-color")
    assert_equal 0, r.status, r
    assert_includes r.stdout, "CIS Alibaba Cloud Foundation Benchmark v2.0.0"

    r2 = cis("--cloud", "alibaba", "scan", "--only", "5.1", "--dry-run")
    assert_equal 0, r2.status, r2
    assert_includes r2.stdout, "terraform -chdir=stacks/alibaba/audit apply"
  end

  def test_gcp_list_and_scan_dry_run
    r = cis("--cloud", "gcp", "list", "--only", "6.4", "--no-color")
    assert_equal 0, r.status, r
    assert_includes r.stdout, "CIS Google Cloud Platform Foundation Benchmark v5.0.0"

    r2 = cis("--cloud", "gcp", "scan", "--only", "6.4", "--dry-run")
    assert_equal 0, r2.status, r2
    assert_includes r2.stdout, "terraform -chdir=stacks/gcp/audit apply"
  end

  def test_unknown_cloud_is_refused
    r = cis("--cloud", "oracle", "list")
    assert_equal 2, r.status
    assert_includes r.stdout + r.stderr, "unknown cloud"
  end

  def test_azure_list_and_scan_dry_run
    r = cis("--cloud", "azure", "list", "--only", "9.3.6", "--no-color")
    assert_equal 0, r.status, r
    assert_includes r.stdout, "CIS Microsoft Azure Foundations Benchmark v6.0.0"

    r2 = cis("--cloud", "azure", "scan", "--only", "9.3.6", "--dry-run")
    assert_equal 0, r2.status, r2
    assert_includes r2.stdout, "terraform -chdir=stacks/azure/audit apply"
  end

  def test_azure_apply_dry_run_uses_azure_hardening_stacks
    r = cis("--cloud", "azure", "apply", "--only", "7.6", "--dry-run")
    assert_equal 0, r.status, r
    assert_match(%r{terraform -chdir=stacks/azure/network\s+apply}, r.stdout)
  end
end
