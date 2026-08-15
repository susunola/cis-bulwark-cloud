"""Port of test/new_features_test.rb + tfcheck — severity, suppression, compliance."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import cis_cloud as C
from cis_cloud.compliance import Compliance
from cis_cloud.remediation import for_control as remediation_for, reference_for as remediation_ref
from cis_cloud.severity import of as severity_of, score as severity_score, weighted as severity_weighted
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


# ---- remediation -----------------------------------------------------------


class _FakeControl:
    def __init__(self, cid, remediate="none", stack=None, detect="none"):
        self.id = cid
        self.remediate = remediate
        self.stack = stack
        self.detect = detect


def test_remediation_exact_id():
    ctl = _FakeControl("4.1", remediate="terraform", stack="storage")
    txt = remediation_for("tencent", ctl)
    assert "COS" in txt and "ACL" in txt
    assert remediation_ref("tencent", ctl) == "https://console.cloud.tencent.com/cos/bucket"


def test_remediation_glob_match():
    ctl = _FakeControl("5.6", remediate="terraform", stack="database")
    txt = remediation_for("tencent", ctl)
    assert "TencentDB" in txt or "MySQL" in txt


def test_remediation_generic_fallback_for_unknown_cloud():
    ctl = _FakeControl("9.9", remediate="none", stack=None)
    txt = remediation_for("oracle", ctl)
    assert "console" in txt  # generic manual fallback


def test_remediation_generic_fallback_remediable():
    ctl = _FakeControl("2.1", remediate="terraform", stack="logging")
    txt = remediation_for("oracle", ctl)
    assert "cis-cloud apply" in txt and "logging" in txt


def test_remediation_attached_to_scan_findings(catalog):
    from cis_cloud.runner import Runner
    from conftest import select

    sel = select(only=["4.1"])
    r = Runner(sel, options={"format": "json"})
    findings = r._with_severity([{"id": "4.1", "title": "bucket", "status": "FAIL", "evidence": "public"}])
    assert findings[0]["remediation"], "finding should carry remediation"
    assert "COS" in findings[0]["remediation"]


# ---- risk score ------------------------------------------------------------


def test_severity_score_mapping():
    assert severity_score("critical") == 100
    assert severity_score("high") == 70
    assert severity_score("medium") == 40
    assert severity_score("low") == 10
    assert severity_score("bogus") == 10  # unknown -> low


def test_severity_weighted_sums_fail_only():
    findings = [
        {"status": "FAIL", "severity": "critical"},
        {"status": "FAIL", "severity": "medium"},
        {"status": "PASS", "severity": "critical"},  # not counted
        {"status": "MANUAL", "severity": "high"},     # not counted
    ]
    assert severity_weighted(findings) == 140  # 100 + 40


def test_finding_carries_score():
    from cis_cloud.runner import Runner
    from conftest import select

    r = Runner(select(only=["4.1"]), options={"format": "json"})
    f = r._with_severity([{"id": "4.1", "title": "bucket", "status": "FAIL", "evidence": "public"}])[0]
    assert f["score"] == severity_score(f["severity"])


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
    assert set(g.keys()) == {"status", "fail_by_severity", "risk_score", "failing"}


def test_compliance_per_cloud_shape():
    c = Compliance.load_dir(FIXTURES / "scans")
    per = c.per_cloud()
    assert set(per.keys()) == {"aws", "azure"}
    for v in per.values():
        assert set(v.keys()) == {"benchmark", "version", "path", "summary", "status", "fail_by_severity", "risk_score", "assessed"}


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
