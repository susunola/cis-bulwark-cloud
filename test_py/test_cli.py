"""Port of test/cli_test.rb — end-to-end CLI behaviour (all --dry-run)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import cis_cloud as C
from conftest import ROOT, run_cli


def cis(*args, env=None):
    return run_cli(*args, env=env)


def test_help_lists_every_command_and_filter():
    r = cis("--help")
    assert r.returncode == 0
    for c in ["list", "scan", "plan", "apply", "destroy"]:
        assert c in r.stdout
    for flag in ["--only", "--exclude", "--section", "--tag", "--profile", "--dry-run", "--format"]:
        assert flag in r.stdout


def test_no_command_is_a_usage_error():
    r = cis()
    assert r.returncode == 2
    assert "usage:" in r.stderr.lower()


def test_unknown_command_is_rejected():
    r = cis("harden")
    assert r.returncode == 2
    assert "invalid choice" in r.stderr


def test_unknown_flag_is_rejected():
    r = cis("list", "--everything")
    assert r.returncode == 2
    assert "unrecognized arguments" in r.stderr


def test_an_invalid_format_is_rejected():
    r = cis("list", "--format", "yaml")
    assert r.returncode == 2


def test_list_shows_the_whole_benchmark_by_default():
    r = cis("list")
    assert r.returncode == 0, r.stderr
    assert "CIS Tencent Cloud Foundation Benchmark v1.0.0" in r.stdout
    assert "selected 91/91 controls" in r.stdout
    assert "remediable 39  detectable 20  manual 43" in r.stdout


def test_list_groups_by_section():
    r = cis("list")
    assert "1 Identity and Access Management" in r.stdout
    assert "4 Storage" in r.stdout


def test_list_json_is_machine_readable_and_self_consistent():
    r = cis("list", "--format", "json")
    payload = json.loads(r.stdout)
    assert payload["benchmark"] == "CIS Tencent Cloud Foundation Benchmark"
    assert payload["version"] == "v1.0.0"
    assert payload["summary"]["selected"] == 91
    assert len(payload["controls"]) == 91
    ids = [c["id"] for c in payload["controls"]]
    assert ids == sorted(ids, key=lambda i: [int(p) for p in i.split(".")])


def test_list_markdown_renders_a_table():
    r = cis("list", "--format", "markdown", "--only", "4.1")
    assert "| ID | Profile |" in r.stdout
    assert "4.1" in r.stdout


def test_list_is_the_one_command_that_tolerates_an_empty_selection():
    r = cis("list", "--only", "4.1", "--tag", "mfa")
    assert r.returncode == 0
    assert "selected 0/91" in r.stdout


def test_only_filters_down_to_one_stack():
    r = cis("apply", "--only", "4.*", "--dry-run")
    assert "stacks/storage" in r.stdout
    assert "stacks/network" not in r.stdout


def test_section_and_exclude_compose():
    r = cis("apply", "--section", "3,4", "--exclude", "4.6", "--dry-run")
    assert "stacks/network" in r.stdout
    assert "stacks/storage" in r.stdout
    assert "4.6" not in r.stdout.split("apply #")[-1] if "apply #" in r.stdout else True


def test_tag_can_span_stacks():
    r = cis("apply", "--tag", "encryption", "--dry-run")
    assert r.returncode == 0
    assert "stacks/" in r.stdout


def test_profile_narrows_by_level():
    r = cis("list", "--profile", "level1", "--format", "json")
    levels = {c["profile"] for c in json.loads(r.stdout)["controls"]}
    assert levels == {"Level 1"}


def test_a_filter_that_matches_nothing_fails_loudly():
    r = cis("apply", "--only", "4.99")
    assert r.returncode == 2
    assert "matches no control" in r.stderr


def test_a_selection_of_zero_controls_refuses_to_run():
    r = cis("apply", "--only", "4.1", "--tag", "mfa")
    assert r.returncode == 2
    assert "select 0 controls" in r.stderr


def test_cli_flags_override_inherited_environment():
    r = cis("list", "--only", "4.1", env={"CIS_ONLY": "3.5"})
    assert r.returncode == 0
    assert "4.1" in r.stdout
    assert "3.5" not in r.stdout


def test_filters_can_come_from_the_environment_alone():
    r = cis("list", env={"CIS_ONLY": "4.1"})
    assert "4.1" in r.stdout
    assert "3.5" not in r.stdout


def test_plan_and_apply_differ_only_in_the_verb():
    plan = cis("plan", "--only", "4.*", "--dry-run")
    apply = cis("apply", "--only", "4.*", "--dry-run")
    assert "stacks/storage" in plan.stdout
    assert "stacks/storage" in apply.stdout
    assert "Will plan:" in plan.stdout
    assert "Will apply:" in apply.stdout


def test_apply_runs_stacks_in_the_declared_order():
    r = cis("apply", "--dry-run")
    assert r.returncode == 0
    order = []
    for line in r.stdout.splitlines():
        if "terraform -chdir=stacks/" in line and "apply" in line:
            stack = line.split("stacks/")[1].split()[0]
            order.append(stack)
    assert order == C.hardening_stacks()


def test_apply_prints_the_selection_summary_first():
    r = cis("apply", "--dry-run")
    assert "Selection: 91/91 controls  (remediable 39, detectable 20, manual 43)" in r.stdout


def test_apply_never_schedules_a_stack_for_a_detect_only_control():
    r = cis("apply", "--only", "4.2", "--dry-run")
    assert r.returncode == 0
    assert "No selected control is enforceable by Terraform" in r.stdout
    assert "terraform -chdir=stacks/" not in r.stdout


def test_apply_names_the_controls_it_cannot_enforce():
    r = cis("apply", "--only", "4.2", "--dry-run")
    assert "Not enforced by Terraform (1)" in r.stdout
    assert "4.2" in r.stdout


def test_a_purely_manual_selection_is_reported_not_silently_skipped():
    r = cis("apply", "--section", "9", "--dry-run")
    assert r.returncode == 0
    assert "No selected control is enforceable by Terraform" in r.stdout
    assert "Not enforced by Terraform (12)" in r.stdout


def test_scan_targets_the_read_only_audit_stack():
    r = cis("scan", "--only", "4.*", "--dry-run")
    assert r.returncode == 0
    assert "read-only" in r.stdout
    assert "terraform -chdir=stacks/audit apply" in r.stdout
    assert "4.1, 4.2, 4.8, 4.9" in r.stdout
    for s in C.hardening_stacks():
        assert f"-chdir=stacks/{s}" not in r.stdout


def test_scan_assesses_only_what_the_provider_can_observe(catalog):
    r = cis("scan", "--profile", "level1", "--dry-run")
    assert r.returncode == 0
    ids = [i.strip() for i in r.stdout.split("# ")[-1].split(",")]
    assert len(ids) == 15
    for cid in ids:
        assert catalog[cid].level == 1
        assert catalog[cid].detectable()


def test_scan_of_an_unobservable_selection_says_so_instead_of_reporting_pass():
    r = cis("scan", "--section", "9", "--dry-run")
    assert r.returncode == 0
    assert "No selected control is machine-assessable" in r.stdout
    assert "terraform -chdir" not in r.stdout


def test_scan_reports_unassessable_controls_as_manual_not_pass():
    r = cis("scan", "--section", "9", "--dry-run", "--format", "json")
    assert r.returncode == 0
    payload = json.loads(r.stdout)
    assert payload["summary"]["MANUAL"] == 12
    assert payload["summary"]["PASS"] == 0
    assert payload["summary"]["FAIL"] == 0
    assert len(payload["findings"]) == 12
    assert all(f["status"] == "MANUAL" for f in payload["findings"])


def test_list_html_is_a_self_contained_document():
    r = cis("list", "--format", "html", "--only", "4.1")
    assert r.returncode == 0
    assert "<!DOCTYPE html>" in r.stdout
    assert "<title>" in r.stdout
    assert "4.1" in r.stdout
    assert "<table" in r.stdout


def test_scan_html_renders_manual_findings():
    r = cis("scan", "--section", "9", "--format", "html", "--dry-run")
    assert r.returncode == 0
    assert "<!DOCTYPE html>" in r.stdout
    assert "MANUAL" in r.stdout
    assert "9.1" in r.stdout


def test_scan_html_carries_account_header_and_filter():
    r = cis("scan", "--section", "9", "--format", "html", "--dry-run",
            env={"CIS_UIN": "100012345678", "CIS_ACCOUNT_NAME": "acme-prod"})
    assert r.returncode == 0
    assert "UIN" in r.stdout
    assert "100012345678" in r.stdout
    assert "Account name" in r.stdout
    assert "acme-prod" in r.stdout
    assert "filter-btn" in r.stdout
    assert "Enforced" in r.stdout
    assert "Not enforced" in r.stdout
    assert 'data-status="MANUAL"' in r.stdout
    assert "applyFilter" in r.stdout


def test_output_writes_html_to_a_file(tmp_path):
    out = tmp_path / "report.html"
    r = cis("scan", "--section", "9", "--format", "html", "--output", str(out), "--dry-run")
    assert r.returncode == 0
    assert out.exists()
    assert "<!DOCTYPE html>" in out.read_text()


def test_apply_report_writes_hardening_html(tmp_path):
    report = tmp_path / "hardening.html"
    r = cis("apply", "--only", "4.1", "--report", str(report), "--dry-run")
    assert r.returncode == 0
    assert report.exists()
    assert "Hardening Report" in report.read_text()


def test_hardening_report_carries_account_header(tmp_path):
    report = tmp_path / "h.html"
    r = cis("apply", "--only", "4.1", "--report", str(report), "--dry-run",
            env={"CIS_UIN": "100012345678"})
    assert r.returncode == 0
    assert "UIN" in report.read_text()


def test_apply_report_default_path_when_no_value(tmp_path, monkeypatch):
    import re

    monkeypatch.chdir(tmp_path)
    r = cis("apply", "--only", "4.*", "--dry-run", "--report")
    assert r.returncode == 0, r.stderr
    m = re.search(r"written to (cis-hardening-\d{8}-\d{6}\.html)", r.stdout + r.stderr)
    assert m, "no report path announced"
    path = ROOT / m.group(1)  # run_cli always runs with cwd=ROOT
    try:
        assert path.exists(), f"report not created at {path}"
    finally:
        if path.exists():
            path.unlink()


def test_destroy_needs_a_stack():
    r = cis("destroy")
    assert r.returncode == 2
    assert "needs a stack name" in r.stderr


def test_destroy_refuses_an_unknown_stack():
    r = cis("destroy", "compute", "--dry-run")
    assert r.returncode == 2
    assert "is not a hardening stack" in (r.stdout + r.stderr)


def test_destroy_refuses_the_audit_stack():
    r = cis("destroy", "audit", "--dry-run")
    assert r.returncode == 2


def test_destroy_accepts_a_hardening_stack():
    r = cis("destroy", "storage", "--dry-run")
    assert r.returncode == 0


def test_cloud_flag_selects_the_aws_registry():
    r = cis("--cloud", "aws", "list", "--no-color")
    assert r.returncode == 0
    assert "CIS Amazon Web Services Foundations Benchmark v7.0.0" in r.stdout
    assert "6.3" in r.stdout


def test_cis_cloud_environment_variable_also_selects_the_cloud():
    r = cis("list", "--only", "6.3", "--no-color", env={"CIS_CLOUD": "aws"})
    assert r.returncode == 0
    assert "CIS Amazon Web Services Foundations Benchmark" in r.stdout


def test_aws_scan_dry_run_uses_the_aws_stack_layout():
    r = cis("--cloud", "aws", "scan", "--section", "6", "--dry-run")
    assert r.returncode == 0
    assert "terraform -chdir=stacks/aws/audit apply" in r.stdout


def test_aws_apply_dry_run_uses_aws_hardening_stacks():
    r = cis("--cloud", "aws", "apply", "--only", "2.8", "--dry-run")
    assert "terraform -chdir=stacks/aws/iam" in r.stdout


def test_alibaba_list_and_scan_dry_run():
    r = cis("--cloud", "alibaba", "list", "--only", "5.1", "--no-color")
    assert r.returncode == 0
    assert "CIS Alibaba Cloud Foundation Benchmark v2.0.0" in r.stdout
    r2 = cis("--cloud", "alibaba", "scan", "--only", "5.1", "--dry-run")
    assert r2.returncode == 0
    assert "terraform -chdir=stacks/alibaba/audit apply" in r2.stdout


def test_gcp_list_and_scan_dry_run():
    r = cis("--cloud", "gcp", "list", "--only", "6.4", "--no-color")
    assert r.returncode == 0
    assert "CIS Google Cloud Platform Foundation Benchmark v5.0.0" in r.stdout
    r2 = cis("--cloud", "gcp", "scan", "--only", "6.4", "--dry-run")
    assert r2.returncode == 0
    assert "terraform -chdir=stacks/gcp/audit apply" in r2.stdout


def test_unknown_cloud_is_refused():
    r = cis("--cloud", "oracle", "list")
    assert r.returncode == 2
    assert "unknown cloud" in (r.stdout + r.stderr)


def test_azure_list_and_scan_dry_run():
    r = cis("--cloud", "azure", "list", "--only", "9.3.6", "--no-color")
    assert r.returncode == 0
    assert "CIS Microsoft Azure Foundations Benchmark v6.0.0" in r.stdout
    r2 = cis("--cloud", "azure", "scan", "--only", "9.3.6", "--dry-run")
    assert r2.returncode == 0
    assert "terraform -chdir=stacks/azure/audit apply" in r2.stdout


def test_azure_apply_dry_run_uses_azure_hardening_stacks():
    r = cis("--cloud", "azure", "apply", "--only", "7.6", "--dry-run")
    assert "terraform -chdir=stacks/azure/network" in r.stdout


def test_check_scans_tf_files_without_credentials():
    dir_ = ROOT / "test_py" / "fixtures" / "tf"
    r = cis("--cloud", "aws", "check", "--tf", str(dir_), "--no-color")
    assert r.returncode == 1  # fixture has a failing control (4.2)
    assert "aws_cloudtrail" in r.stdout


def test_check_needs_a_directory():
    r = cis("check")
    assert r.returncode == 2
    assert "--tf" in (r.stdout + r.stderr)


def test_compliance_aggregates_scan_jsons():
    dir_ = ROOT / "test_py" / "fixtures" / "scans"
    r = cis("compliance", "--dir", str(dir_), "--no-color")
    assert r.returncode == 0
    assert "Cross-cloud compliance" in r.stdout
    assert "aws" in r.stdout
    assert "azure" in r.stdout


def test_compliance_without_results_fails_cleanly():
    dir_ = ROOT / "test_py" / "fixtures" / "tf"
    r = cis("compliance", "--dir", str(dir_))
    assert r.returncode == 2
    assert "no scan results" in (r.stdout + r.stderr)
