"""Port of test/new_features_test.rb + tfcheck — severity, suppression, compliance."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import cis_cloud as C
from cis_cloud.compliance import Compliance
from cis_cloud.severity import of as severity_of
from cis_cloud.suppress import Suppressions
from cis_cloud.tfcheck import scan as tfcheck_scan

FIXTURES = Path(__file__).parent / "fixtures"


def test_severity_from_tags():
    assert severity_of(["root", "mfa"]) == "critical"
    assert severity_of(["public-access"]) == "critical"
    assert severity_of(["password-policy"]) == "high"
    assert severity_of(["tls", "encryption"]) == "high"
    assert severity_of(["logging", "retention"]) == "medium"
    assert severity_of(["review", "governance"]) == "low"
    assert severity_of([]) == "low"


def test_suppression_matches_cloud_control_and_resource():
    s = Suppressions([
        {"cloud": "aws", "control": "6.*", "resource": "sg-123", "reason": "legacy"},
    ])
    f = {"id": "6.3", "status": "FAIL", "evidence": "sg-123 rule x"}
    applied = s.apply([f], "aws")[0]
    assert applied["status"] == "SUPPRESSED"
    assert applied["suppressed"]
    assert "legacy" in applied["evidence"]

    # different cloud -> untouched
    assert s.apply([f], "azure")[0]["status"] == "FAIL"
    # evidence does not match -> untouched
    other = {"id": "6.3", "status": "FAIL", "evidence": "other"}
    assert s.apply([other], "aws")[0]["status"] == "FAIL"


def test_suppression_control_glob():
    s = Suppressions([{"cloud": "*", "control": "4.*"}])
    f = {"id": "4.2", "status": "FAIL", "evidence": "x"}
    assert s.apply([f], "gcp")[0]["status"] == "SUPPRESSED"
    other = {"id": "6.3", "status": "FAIL", "evidence": "x"}
    assert s.apply([other], "gcp")[0]["status"] == "FAIL"


def test_compliance_loads_scan_jsons_and_aggregates():
    c = Compliance.load_dir(FIXTURES / "scans")
    assert not c.is_empty()
    assert sorted(c.clouds) == ["aws", "azure"]


def test_compliance_global_tally():
    c = Compliance.load_dir(FIXTURES / "scans")
    g = c.global_()
    st = g["status"]
    assert st["FAIL"] >= 1
    assert st["PASS"] >= 1
    assert set(g.keys()) == {"status", "fail_by_severity", "failing"}


def test_compliance_per_cloud_shape():
    c = Compliance.load_dir(FIXTURES / "scans")
    per = c.per_cloud()
    assert set(per.keys()) == {"aws", "azure"}
    for v in per.values():
        assert set(v.keys()) == {"benchmark", "version", "path", "summary", "status", "fail_by_severity", "assessed"}


def test_compliance_empty_dir():
    assert Compliance.load_dir("/nonexistent").is_empty()


# ---- tfcheck ---------------------------------------------------------------


def test_check_scans_tf_files_without_credentials():
    findings = tfcheck_scan(FIXTURES / "tf", "aws")
    # fixture has a failing control (4.2: aws_cloudtrail without validation)
    fail = [f for f in findings if f.id == "4.2"]
    assert fail and fail[0].status == "FAIL"
    assert "aws_cloudtrail" in fail[0].evidence


def test_check_passes_compliant_controls():
    findings = {f.id: f for f in tfcheck_scan(FIXTURES / "tf", "aws")}
    assert findings["2.8"].status == "PASS"      # password policy ok
    assert findings["3.2.3"].status == "PASS"    # publicly_accessible=false
    assert findings["6.7"].status == "PASS"      # metadata_options nested
    assert findings["6.1.1"].status == "PASS"    # ebs encryption


def test_check_unknown_cloud_returns_empty():
    assert tfcheck_scan(FIXTURES / "tf", "oracle") == []


def test_check_finding_has_full_shape():
    findings = tfcheck_scan(FIXTURES / "tf", "aws")
    f = findings[0]
    assert f.status in ("PASS", "FAIL")
    assert f.severity in ("critical", "high", "medium", "low")
    assert f.title
    assert f.evidence
