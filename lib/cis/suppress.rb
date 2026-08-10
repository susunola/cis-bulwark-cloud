# frozen_string_literal: true

require "yaml"

module Cis
  # Operator-declared exclusions, read from config/suppress.yml.
  #
  #   suppress:
  #     - cloud:    "aws"            # cloud name, or "*" for every cloud
  #       control:  "6.3"            # control id, or a glob like "6.*"
  #       resource: "sg-0a1b2c3d4e5f60708"   # optional; matched against the
  #                                         # finding's evidence text
  #       reason:   "known exception - legacy jump host"
  #
  # Suppressed findings are reported with status SUPPRESSED and do not trip
  # the scan exit-code gate.
  class Suppressions
    def self.load(path = File.join(Cis::ROOT, "config", "suppress.yml"))
      rules = []
      if File.exist?(path)
        data = YAML.safe_load(File.read(path), aliases: true) || {}
        rules = Array(data["suppress"])
      end
      new(rules)
    end

    attr_reader :rules

    def initialize(rules)
      @rules = rules
    end

    def apply(findings, cloud)
      findings.map do |f|
        next f unless match?(f, cloud)

        reason = reason_for(f, cloud)
        f.merge(
          "status"     => "SUPPRESSED",
          "suppressed" => true,
          "evidence"   => "#{f['evidence']} [suppressed: #{reason}]"
        )
      end
    end

    def match?(finding, cloud)
      @rules.any? { |r| rule_hits?(r, finding, cloud) }
    end

    def rule_hits?(rule, finding, cloud)
      return false unless rule["cloud"] == "*" || rule["cloud"] == cloud
      return false unless glob_match(rule["control"], finding["id"].to_s)

      res = rule["resource"]
      res.nil? || res.empty? ||
        finding["evidence"].to_s.include?(res) || finding["id"].to_s.include?(res)
    end

    def reason_for(finding, cloud)
      rule = @rules.find { |r| rule_hits?(r, finding, cloud) }
      rule && rule["reason"] ? rule["reason"] : "suppressed in config/suppress.yml"
    end

    def glob_match(pattern, value)
      return true if pattern.nil? || pattern == "*"
      return false unless pattern.is_a?(String)

      re = Regexp.new("\\A" + pattern.gsub(".", "\\.").gsub("*", ".*") + "\\z")
      re.match?(value)
    end
  end
end
