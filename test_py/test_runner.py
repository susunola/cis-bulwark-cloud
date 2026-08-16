"""Port of test/runner_test.rb — Runner behaviour with a stubbed terraform."""

from __future__ import annotations

import io
import json

import pytest

import ohbs_cloud as C
from ohbs_cloud.runner import EXIT_ERROR, EXIT_FINDING, EXIT_OK, Runner
from conftest import select


class FakeRunner(Runner):
    def __init__(self, selector, findings=None, exit_code=0, io=None, err=None, **options):
        super().__init__(selector, options={"format": "table", "color": False, **options},
                         io=io, err=err)
        self._findings = findings or []
        self._exit_code = exit_code
        self.commands = []

    def _terraform(self, args, stack, action):
        self.commands.append({"args": args, "stack": stack, "action": action})
        return self._exit_code

    def _terraform_init(self, stack):
        return 0

    def _read_findings(self):
        return self._findings

    def _read_account(self):
        return None


def build(selector, findings=None, exit_code=0, **options):
    out, err = io.StringIO(), io.StringIO()
    r = FakeRunner(selector, findings=findings, exit_code=exit_code, io=out, err=err, **options)
    return r, out, err


def finding(catalog, cid, status, evidence=""):
    return {"id": cid, "title": catalog[cid].title, "status": status, "evidence": evidence}


def test_a_clean_scan_exits_zero(catalog):
    r, _, _ = build(select(only=["4.1"]), findings=[finding(catalog, "4.1", "PASS")])
    assert r.scan() == EXIT_OK


def test_a_failing_control_exits_one(catalog):
    r, out, _ = build(select(only=["4.1"]), findings=[finding(catalog, "4.1", "FAIL", "bucket is public")])
    assert r.scan() == EXIT_FINDING
    assert "FAIL" in out.getvalue()
    assert "bucket is public" in out.getvalue()


def test_manual_rows_alone_do_not_fail_the_run(catalog):
    r, out, _ = build(select(only=["9.*"]))
    assert r.scan() == EXIT_OK
    assert "MANUAL" in out.getvalue()
    assert r.commands == [], "a manual-only selection has nothing to deploy"


def test_a_broken_terraform_run_exits_two(catalog):
    r, _, _ = build(select(only=["4.1"]), exit_code=1)
    assert r.scan() == EXIT_ERROR


def test_a_failing_stack_stops_the_apply_and_exits_two(catalog):
    r, out, _ = build(select(sections=["3", "4"]), exit_code=1)
    assert r.apply() == EXIT_ERROR
    assert len(r.commands) == 1, "must not carry on to the next stack after a failure"
    assert "stopping" in out.getvalue()


def test_destroy_of_an_unknown_stack_exits_two(catalog):
    r, _, err = build(select())
    assert r.destroy("compute") == EXIT_ERROR
    assert "is not a hardening stack" in err.getvalue()


def test_apply_issues_one_apply_per_stack_in_order(catalog):
    r, _, _ = build(select(sections=["3", "4"]))
    assert r.apply() == EXIT_OK
    assert [c["stack"] for c in r.commands] == ["network", "storage"]
    assert [c["action"] for c in r.commands] == ["apply", "apply"]
    for c in r.commands:
        assert c["args"][0] == "apply"
        assert "-auto-approve" in c["args"]


def test_apply_and_scan_both_use_apply_subcommand(catalog):
    a, _, _ = build(select(sections=["4"]))
    a.apply()
    s, _, _ = build(select(sections=["4"]), findings=[])
    s.scan()
    assert a.commands[0]["args"][0] == "apply"
    assert s.commands[0]["args"][0] == "apply"


def test_plan_never_writes(catalog):
    r, _, _ = build(select(sections=["4"]))
    r.plan()
    assert r.commands[0]["args"][0] == "plan"
    assert "apply" not in [a for c in r.commands for a in c["args"]]


def test_scan_runs_the_audit_stack_and_nothing_else(catalog):
    r, _, _ = build(select(sections=["4"]), findings=[finding(catalog, "4.1", "PASS")])
    r.scan()
    assert [c["stack"] for c in r.commands] == ["audit"]
    assert [c["action"] for c in r.commands] == ["scan"]


def test_dry_run_issues_nothing(catalog):
    for action in ("scan", "plan", "apply"):
        r, _, _ = build(select(), dry_run=True)
        assert getattr(r, action)() == EXIT_OK
        assert r.commands == [], f"{action} --dry-run reached terraform"


def test_the_environment_reproduces_the_selection(catalog):
    sel = select(sections=["4"], exclude=["4.6"])
    r, _, _ = build(sel)
    r.apply()
    assert sel.to_env["CIS_SECTIONS"] == "4"
    assert sel.to_env["CIS_EXCLUDE"] == "4.6"
    from ohbs_cloud.selector import Selector

    rebuilt = Selector.from_env(catalog, sel.to_env)
    assert [c.id for c in rebuilt.remediable] == ["4.1", "4.3", "4.4", "4.5", "4.7"]


def test_the_report_covers_every_selected_control_not_just_the_observable_ones(catalog):
    sel = select(sections=["4"])
    r, out, _ = build(sel, findings=[finding(catalog, cid, "PASS") for cid in ["4.1", "4.2", "4.8", "4.9"]])
    r.scan()
    for c in catalog.controls:
        if c.section == "4":
            assert c.id in out.getvalue(), f"{c.id} vanished from the report"


def test_controls_terraform_enforces_but_cannot_read_back_are_skipped_not_passed(catalog):
    sel = select(only=["4.3"])
    r, out, _ = build(sel)
    r.scan()
    assert "SKIPPED" in out.getvalue()
    assert "enforced by `ohbs-cloud apply`, not re" in out.getvalue()
    assert "PASS   " not in out.getvalue()


def test_the_untruncated_evidence_survives_in_machine_output(catalog):
    r, out, _ = build(select(only=["4.3"]), format="json")
    r.scan()
    row = json.loads(out.getvalue())["findings"][0]
    assert row["status"] == "SKIPPED"
    assert row["evidence"] == "enforced by `ohbs-cloud apply`, not readable"


def test_apply_lists_the_controls_it_could_not_enforce(catalog):
    r, out, _ = build(select(sections=["9"]))
    assert r.apply() == EXIT_OK
    assert "No selected control is enforceable by Terraform" in out.getvalue()
    assert "Not enforced by Terraform (12)" in out.getvalue()
    assert r.commands == []


def test_json_output_stays_parseable_because_prose_goes_to_stderr(catalog):
    r, out, err = build(select(sections=["9"]), format="json")
    r.scan()
    payload = json.loads(out.getvalue())
    assert len(payload["findings"]) == 12
    assert err.getvalue() != "", "the human-readable note should still be emitted, just not on stdout"


def test_findings_from_terraform_are_normalised_into_rows(catalog):
    raw = {"4.1": {"status": "fail", "evidence": "public"}}
    r, _, _ = build(select(only=["4.1"]), findings=None)
    rows = r._normalize(raw)
    assert len(rows) == 1
    assert rows[0]["status"] == "FAIL", "status must be upcased before it is compared"
    assert rows[0]["title"] == catalog["4.1"].title, "titles come from the registry"
    assert rows[0]["evidence"] == "public"


def test_an_unknown_id_from_terraform_does_not_crash_the_report(catalog):
    r, _, _ = build(select(only=["4.1"]))
    rows = r._normalize({"9.99": {"status": "PASS"}})
    assert rows[0]["title"] == "(unknown control)"


def test_normalize_includes_structured_resource_from_evidence_detail(catalog):
    r, _, _ = build(select(only=["4.1"]))
    rows = r._normalize([{
        "id": "4.1", "status": "fail", "evidence": "bucket public",
        "evidence_detail": [{"resource": "tencentcloud_cos_bucket.demo", "attribute": "acl"}],
    }])
    assert rows[0]["resource"] == "tencentcloud_cos_bucket.demo"


def test_normalize_resource_falls_back_to_top_level_field(catalog):
    r, _, _ = build(select(only=["4.1"]))
    rows = r._normalize([{"id": "4.1", "status": "fail", "resource": "aws_s3_bucket.x"}])
    assert rows[0]["resource"] == "aws_s3_bucket.x"


def test_normalize_resource_empty_when_absent(catalog):
    r, _, _ = build(select(only=["4.1"]))
    rows = r._normalize([{"id": "4.1", "status": "fail"}])
    assert rows[0]["resource"] == ""


def test_check_drift_live_baseline_runs_a_scan_and_flags_regression(catalog, tmp_path):
    # baseline: 4.1 PASS; live scan will report 4.1 FAIL -> regression.
    base = tmp_path / "base.json"
    base.write_text(json.dumps({
        "findings": [{"id": "4.1", "title": "bucket", "status": "PASS", "evidence": ""}]
    }), encoding="utf-8")
    r, out, _ = build(select(only=["4.1"]), findings=[finding(catalog, "4.1", "FAIL", "public")])
    assert r.check_drift(str(base)) == EXIT_FINDING
    assert "REGRESSIONS" in out.getvalue()
    assert "4.1" in out.getvalue()
