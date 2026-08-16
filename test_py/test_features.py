"""Port of test/new_features_test.rb + tfcheck — severity, suppression, compliance."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import ohbs_cloud as C
from ohbs_cloud.compliance import Compliance
from ohbs_cloud.remediation import for_control as remediation_for, reference_for as remediation_ref
from ohbs_cloud.severity import of as severity_of, score as severity_score, weighted as severity_weighted
from ohbs_cloud.suppress import Suppressions
from ohbs_cloud.tfcheck import Finding as TfFinding
from ohbs_cloud.tfcheck import load_checks, scan as tfcheck_scan

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


def test_remediation_reference_url():
    ctl = _FakeControl("3.5", remediate="terraform", stack="network")
    assert remediation_ref("tencent", ctl) == "https://console.cloud.tencent.com/vpc"
    # no reference for an unmapped id
    assert remediation_ref("oracle", ctl) == ""


def test_remediation_every_control_resolves(catalog):
    # R7: the rule file + fallback must give every control in the registry a
    # non-empty remediation hint across all five clouds.
    from ohbs_cloud import IMPLEMENTED_CLOUDS
    from ohbs_cloud.remediation import for_control as _for
    for cloud in IMPLEMENTED_CLOUDS:
        import ohbs_cloud as _C
        _C.reset()
        os.environ["CIS_CLOUD"] = cloud
        _C.reset()
        cat = _C.get_catalog()
        for c in cat.controls:
            txt = _for(cloud, c)
            assert txt, f"{cloud} {c.id}: no remediation resolved"
        _C.reset()
        os.environ.pop("CIS_CLOUD", None)


def test_remediation_generic_fallback_for_unknown_cloud():
    ctl = _FakeControl("9.9", remediate="none", stack=None)
    txt = remediation_for("oracle", ctl)
    assert "console" in txt  # generic manual fallback


def test_remediation_generic_fallback_remediable():
    ctl = _FakeControl("2.1", remediate="terraform", stack="logging")
    txt = remediation_for("oracle", ctl)
    assert "ohbs-cloud apply" in txt and "logging" in txt


def test_remediation_attached_to_scan_findings(catalog):
    from ohbs_cloud.runner import Runner
    from conftest import select

    sel = select(only=["4.1"])
    r = Runner(sel, options={"format": "json"})
    findings = r._with_severity([{"id": "4.1", "title": "bucket", "status": "FAIL", "evidence": "public"}])
    assert findings[0]["remediation"], "finding should carry remediation"
    assert "COS" in findings[0]["remediation"]


def test_scan_markdown_renders_remediation_column(catalog):
    from ohbs_cloud.reporter import Reporter
    from conftest import select
    r = Reporter(color=False)
    f = {"id": "4.1", "title": "bucket", "status": "FAIL", "severity": "critical",
         "evidence": "public", "remediation": "Lock down the bucket"}
    out = r.scan([f], select(only=["4.1"]), format_="markdown")
    assert "| Remediation |" in out
    assert "Lock down the bucket" in out


def test_scan_html_renders_remediation_fix(catalog):
    from ohbs_cloud.reporter import Reporter
    from conftest import select
    r = Reporter(color=False)
    f = {"id": "4.1", "title": "bucket", "status": "FAIL", "severity": "critical",
         "evidence": "public", "remediation": "Lock down the bucket"}
    out = r.scan([f], select(only=["4.1"]), format_="html")
    assert "fix:" in out
    assert "Lock down the bucket" in out


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
    from ohbs_cloud.runner import Runner
    from conftest import select

    r = Runner(select(only=["4.1"]), options={"format": "json"})
    f = r._with_severity([{"id": "4.1", "title": "bucket", "status": "FAIL", "evidence": "public"}])[0]
    assert f["score"] == severity_score(f["severity"])


def test_compliance_risk_score_value():
    # S4: risk_score must equal the weighted sum of FAIL findings only.
    c = Compliance.load_dir(FIXTURES / "scans")
    g = c.global_()
    expected = severity_weighted([f for f in c.entries for f in f["findings"]])
    assert g["risk_score"] == expected
    per = c.per_cloud()
    for cloud, v in per.items():
        cloud_findings = next(e["findings"] for e in c.entries if e["cloud"] == cloud)
        assert v["risk_score"] == severity_weighted(cloud_findings)


def test_scan_table_shows_score_column(catalog):
    from ohbs_cloud.reporter import Reporter
    from conftest import select
    r = Reporter(color=False)
    f = {"id": "4.1", "title": "bucket", "status": "FAIL", "severity": "critical",
         "evidence": "public", "score": 100}
    out = r.scan([f], select(only=["4.1"]), format_="table")
    assert "SCORE" in out
    assert "100" in out


def test_scan_table_shows_resource_column_only_when_present(catalog):
    from ohbs_cloud.reporter import Reporter
    from conftest import select
    r = Reporter(color=False)
    with_res = {"id": "4.1", "title": "bucket", "status": "FAIL", "severity": "high",
                "evidence": "public", "score": 70, "resource": "cos_bucket.demo"}
    out = r.scan([with_res], select(only=["4.1"]), format_="table")
    assert "RESOURCE" in out
    assert "cos_bucket.demo" in out

    no_res = {"id": "4.1", "title": "bucket", "status": "FAIL", "severity": "high",
              "evidence": "public", "score": 70}
    out2 = r.scan([no_res], select(only=["4.1"]), format_="table")
    assert "RESOURCE" not in out2


def test_scan_csv_has_resource_column(catalog):
    from ohbs_cloud.reporter import Reporter
    from conftest import select
    r = Reporter(color=False)
    f = {"id": "4.1", "title": "bucket", "status": "FAIL", "severity": "high",
         "evidence": "public", "resource": "cos_bucket.demo"}
    out = r.scan([f], select(only=["4.1"]), format_="csv")
    assert out.splitlines()[0] == "status,severity,id,title,resource,evidence"
    assert "cos_bucket.demo" in out


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


def test_suppression_matches_structured_resource_field():
    s = Suppressions([{"cloud": "aws", "control": "6.3", "resource": "sg-123", "reason": "legacy"}])
    f = {"id": "6.3", "status": "FAIL", "evidence": "no sg text", "resource": "aws_security_group.sg-123"}
    assert s.apply([f], "aws")[0]["status"] == "SUPPRESSED"


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


# ---- richer custom ruleset -------------------------------------------------


def test_load_checks_accepts_metadata(tmp_path):
    p = tmp_path / "checks.yml"
    p.write_text("""
aws:
  "3.2.4":
    resource: aws_db_instance
    title: "Custom RDS check"
    severity: high
    remediation: "Enable multi-az."
    framework: pci
    args:
      multi_az: true
""", encoding="utf-8")
    rules = load_checks(p)
    rule = rules["aws"]["3.2.4"]
    assert rule["title"] == "Custom RDS check"
    assert rule["severity"] == "high"
    assert rule["remediation"] == "Enable multi-az."
    assert rule["framework"] == "pci"


def test_load_checks_rejects_bad_severity(tmp_path):
    p = tmp_path / "checks.yml"
    p.write_text("aws:\n  \"3.2.4\":\n    resource: aws_db_instance\n    severity: urgent\n    args: {}\n", encoding="utf-8")
    import pytest as _pytest
    with _pytest.raises(ValueError):
        load_checks(p)


def test_scan_uses_custom_rule_metadata(tmp_path):
    tf = tmp_path / "tf"
    tf.mkdir()
    (tf / "main.tf").write_text(
        'resource "aws_db_instance" "x" {\n  multi_az = false\n}\n', encoding="utf-8")
    extra = {
        "aws": {
            "9.9.9": {
                "resource": "aws_db_instance",
                "title": "Custom DB check",
                "severity": "critical",
                "remediation": "Set multi_az = true",
                "args": {"multi_az": True},
            }
        }
    }
    findings = tfcheck_scan(tf, "aws", extra_rules=extra["aws"])
    f = [x for x in findings if x.id == "9.9.9"][0]
    assert f.status == "FAIL"
    assert f.title == "Custom DB check"
    assert f.severity == "critical"
    assert f.remediation == "Set multi_az = true"
    d = f.to_dict()
    assert d["remediation"] == "Set multi_az = true"


def test_load_checks_rejects_non_string_metadata(tmp_path):
    import pytest as _pytest
    for bad in [{"title": 3}, {"remediation": ["x"]}, {"framework": {"a": 1}}]:
        p = tmp_path / "checks.yml"
        p.write_text(f"aws:\n  \"1.1\":\n    resource: aws_x\n    {list(bad)[0]}: {bad[list(bad)[0]]!r}\n    args: {{}}\n", encoding="utf-8")
        with _pytest.raises(ValueError):
            load_checks(p)


def test_scan_passes_framework_through(tmp_path):
    tf = tmp_path / "tf"
    tf.mkdir()
    (tf / "main.tf").write_text('resource "aws_db_instance" "x" {\n}\n', encoding="utf-8")
    extra = {"aws": {"7.7.7": {"resource": "aws_db_instance", "framework": "pci", "args": {}}}}
    f = [x for x in tfcheck_scan(tf, "aws", extra_rules=extra["aws"]) if x.id == "7.7.7"][0]
    assert f.framework == "pci"
    assert f.to_dict()["framework"] == "pci"
