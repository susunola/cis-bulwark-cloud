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
