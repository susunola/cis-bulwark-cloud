# frozen_string_literal: true

require "json"

module Cis
  # Cross-cloud compliance posture, Prowler-style.
  #
  # `cis scan --cloud X --format json -o scans/X.json` saves per-cloud findings;
  # `cis compliance --dir scans` reads every such file and rolls them into one
  # view: per-cloud status cards, a global tally and the full failing-control
  # list ordered by severity. One cloud failing a requirement is visible the
  # moment you look at the report - no assembling spreadsheets.
  class Compliance
    CLOUD_HINTS = {
      "tencent" => ["tencent"],
      "aws"     => ["amazon"],
      "azure"   => ["azure"],
      "gcp"     => ["google"],
      "alibaba" => ["alibaba"],
    }.freeze

    STATUS_ORDER = %w[FAIL PASS MANUAL SKIPPED SUPPRESSED].freeze
    SEVERITY_ORDER = %w[critical high medium low].freeze

    attr_reader :entries

    def self.load_dir(dir)
      files = Dir.glob(File.join(dir.to_s, "*.json")).sort
      entries = files.filter_map { |f| parse_file(f) }
      new(entries)
    end

    def self.parse_file(path)
      data = JSON.parse(File.read(path))
      findings = data["findings"]
      return nil unless findings.is_a?(Array)

      {
        cloud:     infer_cloud(data, path),
        path:      path,
        benchmark: data["benchmark"],
        version:   data["version"],
        summary:   data["summary"] || {},
        findings:  findings
      }
    rescue JSON::ParserError
      nil
    end

    def self.infer_cloud(data, path)
      haystack = [data["benchmark"], data.dig("account", "cloud"), File.basename(path)].join(" ").downcase
      CLOUD_HINTS.find { |_, hints| hints.any? { |h| haystack.include?(h) } }&.first || File.basename(path, ".json")
    end

    def initialize(entries)
      @entries = entries
    end

    def empty?
      @entries.empty?
    end

    def clouds
      @entries.map { |e| e[:cloud] }
    end

    # Per-cloud tally: status counts + failing severity distribution.
    def per_cloud
      @entries.to_h do |e|
        findings = e[:findings]
        fails = findings.select { |f| f["status"] == "FAIL" }
        [
          e[:cloud],
          {
            benchmark: e[:benchmark],
            version:   e[:version],
            path:      e[:path],
            summary:   e[:summary],
            status:    tally(findings),
            fail_by_severity: SEVERITY_ORDER.to_h { |lv| [lv, fails.count { |f| f["severity"] == lv }] },
            assessed:  findings.size
          }
        ]
      end
    end

    def global
      all = @entries.flat_map { |e| e[:findings] }
      fails = all.select { |f| f["status"] == "FAIL" }
      {
        status:  tally(all),
        fail_by_severity: SEVERITY_ORDER.to_h { |lv| [lv, fails.count { |f| f["severity"] == lv }] },
        failing: fails.sort_by { |f| [SEVERITY_ORDER.index(f["severity"]) || 99, f["id"].to_s] }
      }
    end

    def tally(findings)
      STATUS_ORDER.each_with_object({}) { |s, h| h[s] = findings.count { |f| f["status"] == s } }
    end
  end
end
