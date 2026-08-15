"""Tests for the canonical finding schema."""

from __future__ import annotations

from cis_cloud.schema import FINDING_KEYS, STATUSES, SEVERITIES, normalize_finding


class _Ctl:
    id = "4.1"
    title = "bucket"
    tags = ["cos", "public-access"]


def test_normalize_fills_all_keys():
    f = normalize_finding({"id": "4.1", "status": "fail", "evidence": "public"}, control=_Ctl)
    assert list(f.keys()) == FINDING_KEYS
    assert f["status"] == "FAIL"
    assert f["title"] == "bucket"
    assert f["severity"] == "critical"   # from public-access tag
    assert f["score"] == 100
    assert f["resource"] == ""
    assert f["remediation"] == ""


def test_normalize_preserves_existing_values():
    f = normalize_finding({
        "id": "4.1", "status": "PASS", "severity": "high", "score": 70,
        "title": "T", "evidence": "e", "resource": "r", "remediation": "fix",
    })
    assert f["severity"] == "high"
    assert f["score"] == 70
    assert f["resource"] == "r"
    assert f["remediation"] == "fix"


def test_normalize_unknown_severity_falls_back_to_low():
    f = normalize_finding({"id": "x", "status": "FAIL", "severity": "urgent"})
    assert f["severity"] == "low"
    assert f["score"] == 10


def test_normalize_derives_score_when_missing():
    f = normalize_finding({"id": "x", "status": "FAIL", "severity": "high"})
    assert f["score"] == 70


def test_schema_constants():
    assert set(STATUSES) == {"FAIL", "PASS", "MANUAL", "SKIPPED", "SUPPRESSED"}
    assert set(SEVERITIES) == {"critical", "high", "medium", "low"}


def test_scan_check_compliance_findings_all_carry_schema_keys():
    # SC6: scan and check producers emit FINDING_KEYS; a compliance finding
    # (read from a saved scan JSON) is normalisable to the full schema, so
    # downstream consumers can rely on the shape everywhere.
    from cis_cloud.runner import Runner
    from cis_cloud.tfcheck import scan as tfcheck_scan
    from cis_cloud.compliance import Compliance
    from conftest import select
    from pathlib import Path

    root = Path(__file__).parent

    # scan path -> runner._normalize
    r = Runner(select(only=["4.1"]), options={"format": "json"})
    scan_f = r._normalize({"4.1": {"status": "fail", "evidence": "public"}})[0]

    # check path -> tfcheck Finding.to_dict
    check_f = tfcheck_scan(root / "fixtures" / "tf", "aws")[0].to_dict()

    # compliance path -> a finding from a fixture scan JSON (minimal keys),
    # normalised through the schema so it exposes the full set.
    comp_raw = Compliance.load_dir(root / "fixtures" / "scans").entries[0]["findings"][0]
    comp_f = normalize_finding(comp_raw)

    for name, f in [("scan", scan_f), ("check", check_f), ("compliance", comp_f)]:
        assert set(FINDING_KEYS) <= set(f.keys()), f"{name} finding missing schema keys: {f.keys()}"
