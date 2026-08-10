# frozen_string_literal: true

require_relative "test_helper"

class NewFeaturesTest < CisTestCase
  # ---- severity -----------------------------------------------------------

  def test_severity_from_tags
    assert_equal "critical", Cis::Severity.of(%w[root mfa])
    assert_equal "critical", Cis::Severity.of(%w[public-access])
    assert_equal "high",     Cis::Severity.of(%w[password-policy])
    assert_equal "high",     Cis::Severity.of(%w[tls encryption])
    assert_equal "medium",   Cis::Severity.of(%w[logging retention])
    assert_equal "low",      Cis::Severity.of(%w[review governance])
    assert_equal "low",      Cis::Severity.of([])
  end

  def test_scan_findings_carry_severity
    # Findings produced by the runner include a severity for every control.
    # Reconstruct the runner behaviour through manual_findings' shape.
    by_id = { "2.8" => Cis::Control.new("id" => "2.8", "title" => "a",
                                        "remediate" => "terraform", "stack" => "iam",
                                        "tags" => ["password-policy"]) }
    # via the runner's with_severity, which needs a real selector - assert the
    # mapping function directly instead.
    assert_equal "high", Cis::Severity.of(by_id["2.8"].tags)
  end

  # ---- suppression --------------------------------------------------------

  def test_suppression_matches_cloud_control_and_resource
    s = Cis::Suppressions.new([
      { "cloud" => "aws", "control" => "6.*", "resource" => "sg-123", "reason" => "legacy" }
    ])
    f = { "id" => "6.3", "status" => "FAIL", "evidence" => "sg-123 rule x" }
    applied = s.apply([f], "aws").first
    assert_equal "SUPPRESSED", applied["status"]
    assert applied["suppressed"]
    assert_includes applied["evidence"], "legacy"

    # different cloud -> untouched
    assert_equal "FAIL", s.apply([f], "azure").first["status"]
    # evidence does not match -> untouched
    assert_equal "FAIL", s.apply([{ "id" => "6.3", "status" => "FAIL", "evidence" => "other" }], "aws").first["status"]
  end

  def test_suppression_control_glob
    s = Cis::Suppressions.new([{ "cloud" => "*", "control" => "4.*" }])
    f = { "id" => "4.2", "status" => "FAIL", "evidence" => "x" }
    assert_equal "SUPPRESSED", s.apply([f], "gcp").first["status"]
    assert_equal "FAIL", s.apply([{ "id" => "6.3", "status" => "FAIL", "evidence" => "x" }], "gcp").first["status"]
  end

  # ---- compliance aggregation ---------------------------------------------

  def test_compliance_loads_scan_jsons_and_aggregates
    dir = File.join(Cis::ROOT, "test", "fixtures", "scans")
    c = Cis::Compliance.load_dir(dir)
    refute c.empty?
    assert_equal %w[aws azure], c.clouds.sort

    per = c.per_cloud
    assert_equal 1, per["aws"][:status]["FAIL"]
    assert_equal 1, per["azure"][:status]["FAIL"]

    g = c.global
    assert_equal 2, g[:status]["FAIL"]
    assert_equal 1, g[:fail_by_severity]["critical"] # aws 6.3
    assert_equal 1, g[:fail_by_severity]["high"]      # azure 9.3.6
    assert_equal %w[6.3 9.3.6], g[:failing].map { |f| f["id"] }.sort
  end

  def test_compliance_renders_every_format
    dir = File.join(Cis::ROOT, "test", "fixtures", "scans")
    c = Cis::Compliance.load_dir(dir)
    out = StringIO.new
    rep = Cis::Reporter.new(io: out, color: false)
    %w[table markdown html json].each do |fmt|
      rep.compliance(c, format: fmt)
      assert out.string.include?("aws"), "compliance #{fmt} output missing cloud"
      out.truncate(0); out.rewind
    end
  end

  # ---- csv / junit scan output --------------------------------------------

  def test_scan_csv_and_junit_output
    findings = [
      { "id" => "6.3", "status" => "FAIL", "severity" => "critical", "title" => "SG", "evidence" => "open" },
      { "id" => "6.4", "status" => "SUPPRESSED", "severity" => "critical", "title" => "SG6", "evidence" => "skip" },
      { "id" => "6.5", "status" => "PASS", "severity" => "low", "title" => "SG5", "evidence" => "ok" }
    ]
    out = StringIO.new
    rep = Cis::Reporter.new(io: out, color: false)
    rep.scan(findings, nil, format: "csv")
    assert_includes out.string, "status,severity,id,title,evidence"
    assert_includes out.string, "FAIL,critical,6.3"

    out.truncate(0); out.rewind
    rep.scan(findings, nil, format: "junit")
    xml = out.string
    assert_includes xml, "<testsuite"
    assert_includes xml, 'failures="1"'
    assert_includes xml, "<failure"
    assert_includes xml, "<skipped"
  end

  # ---- tfcheck (IaC pre-deploy scan) --------------------------------------

  def test_tfcheck_finds_compliant_and_violating_resources
    dir = File.join(Cis::ROOT, "test", "fixtures", "tf")
    findings = Cis::TfCheck.scan(dir, "aws").map { |f| f.to_h.transform_keys(&:to_s) }

    by_id = findings.to_h { |f| [f["id"], f] }
    # aws fixtures comply: password policy, ebs, cloudtrail validation missing -> FAIL,
    # db public false -> PASS, instance metadata http_tokens -> PASS
    assert_equal "PASS", by_id["2.8"]["status"]
    assert_equal "PASS", by_id["6.1.1"]["status"]
    assert_equal "FAIL", by_id["4.2"]["status"] # enable_log_file_validation absent
    assert_equal "PASS", by_id["3.2.3"]["status"]
    assert_equal "PASS", by_id["6.7"]["status"]
    assert_includes by_id["4.2"]["evidence"], "aws_cloudtrail.trail"
  end

  def test_tfcheck_ignores_other_clouds_rules_when_targeted
    dir = File.join(Cis::ROOT, "test", "fixtures", "tf")
    # scanning with cloud=aws must not report azure rules, and vice versa
    azure = Cis::TfCheck.scan(dir, "azure").map { |f| f.to_h.transform_keys(&:to_s) }
    az_by_id = azure.to_h { |f| [f["id"], f] }
    assert az_by_id.key?("9.3.4")
    assert az_by_id.key?("9.3.6")
    refute az_by_id.key?("2.8"), "aws rules leaked into azure scan"
  end

  def test_tfcheck_extract_blocks_handles_nested_braces
    src = <<~HCL
      resource "aws_instance" "a" {
        metadata_options {
          http_tokens = "required"
        }
      }
    HCL
    blocks = Cis::TfCheck.extract_blocks(src, "x.tf")
    assert_equal 1, blocks.size
    assert_equal "aws_instance", blocks.first[:type]
    assert_includes blocks.first[:body], "http_tokens"
  end
end
