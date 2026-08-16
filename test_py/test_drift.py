"""Tests for baseline drift detection (check-drift)."""

from __future__ import annotations

import json
from pathlib import Path

from ohbs_cloud.drift import drift, render_drift
from conftest import run_cli

FIXTURES = Path(__file__).parent / "fixtures"


def _scan(cloud, *findings):
    """Build a scan payload dict with the given status maps."""
    return {
        "cloud": cloud,
        "findings": [{"id": cid, "title": cid, "status": st, "evidence": ""}
                     for cid, st in findings],
    }


def test_drift_detects_regressions():
    base = _scan("aws", ("2.8", "PASS"), ("4.2", "FAIL"))
    cur = _scan("aws", ("2.8", "FAIL"), ("4.2", "FAIL"))
    d = drift(base, cur)
    # 2.8 was PASS, now FAIL -> regression. 4.2 still failing -> not a regression.
    assert [r["id"] for r in d["regressions"]] == ["2.8"]
    assert d["summary"]["regressions"] == 1
    assert d["summary"]["still_failing"] == 1


def test_drift_clean_has_no_regressions():
    base = _scan("aws", ("2.8", "PASS"), ("4.2", "FAIL"))
    cur = _scan("aws", ("2.8", "PASS"), ("4.2", "PASS"))
    d = drift(base, cur)
    assert d["regressions"] == []
    assert d["summary"]["fixed"] == 1


def test_drift_new_control_failing_is_regression():
    base = _scan("aws", ("2.8", "PASS"))
    cur = _scan("aws", ("2.8", "FAIL"), ("6.1.1", "FAIL"))
    d = drift(base, cur)
    assert sorted(r["id"] for r in d["regressions"]) == ["2.8", "6.1.1"]


def test_render_drift_table_lists_regressions():
    d = drift(_scan("aws", ("2.8", "PASS")), _scan("aws", ("2.8", "FAIL")))
    out = render_drift(d, "table")
    assert "REGRESSIONS" in out and "2.8" in out


def test_render_drift_json_is_parseable():
    d = drift(_scan("aws", ("2.8", "PASS")), _scan("aws", ("2.8", "FAIL")))
    payload = json.loads(render_drift(d, "json"))
    assert payload["summary"]["regressions"] == 1
    assert payload["regressions"][0]["id"] == "2.8"


def test_check_drift_missing_baseline_exits_two(tmp_path):
    r = run_cli("check-drift", str(tmp_path / "nope.json"), str(tmp_path / "cur.json"))
    assert r.returncode == 2
    assert "not found" in (r.stdout + r.stderr)


def test_check_drift_baseline_flag_parses_and_errors_cleanly(tmp_path):
    # --baseline triggers a live scan, which can't run offline; a missing
    # baseline must error (exit 2) before any scan is attempted.
    r = run_cli("check-drift", "--baseline", str(tmp_path / "missing-base.json"))
    assert r.returncode == 2
    assert "not found" in (r.stdout + r.stderr)


def test_check_drift_offline_cli():
    base = FIXTURES / "drift_base.json"
    cur = FIXTURES / "drift_cur.json"
    base.write_text(json.dumps(_scan("aws", ("2.8", "PASS"), ("4.2", "FAIL"))), encoding="utf-8")
    cur.write_text(json.dumps(_scan("aws", ("2.8", "FAIL"), ("4.2", "FAIL"))), encoding="utf-8")
    try:
        r = run_cli("check-drift", str(base), str(cur))
        assert r.returncode == 1, "regressions must exit 1"
        assert "2.8" in r.stdout
    finally:
        base.unlink(missing_ok=True)
        cur.unlink(missing_ok=True)


def test_check_drift_offline_clean_exits_zero():
    base = FIXTURES / "drift_clean_base.json"
    cur = FIXTURES / "drift_clean_cur.json"
    base.write_text(json.dumps(_scan("aws", ("2.8", "PASS"))), encoding="utf-8")
    cur.write_text(json.dumps(_scan("aws", ("2.8", "PASS"))), encoding="utf-8")
    try:
        r = run_cli("check-drift", str(base), str(cur))
        assert r.returncode == 0
    finally:
        base.unlink(missing_ok=True)
        cur.unlink(missing_ok=True)
