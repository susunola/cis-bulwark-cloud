# frozen_string_literal: true

module Cis
  # Pre-deployment CIS checks against Terraform definitions, Steampipe-style.
  #
  # `cis check --tf DIR --cloud aws` parses the .tf files in DIR (no cloud
  # credentials, no terraform run), finds each resource block of interest and
  # verifies the arguments CIS requires are present. A control is PASS when
  # every matching resource satisfies its rule, FAIL when one does not.
  #
  # This is deliberately heuristic: a brace-paired scan of the source, not a
  # full HCL semantic model. It flags the missing/weak arguments that matter;
  # a resource defined in a module or created outside the scanned tree is not
  # visible here and will be caught by `cis scan` against the live cloud.
  module TfCheck
    # control -> { resource:, args: { arg => expectation } }
    # expectation: Integer (minimum), String (exact), true/false, or
    #              Array (any of).
    RULES = {
      "tencent" => {
        "4.1" => { resource: "tencentcloud_cos_bucket", args: { "acl" => "private" } },
        "2.1" => { resource: "tencentcloud_cloud_audit", args: { "audit_switch" => true } },
        "5.2" => { resource: "tencentcloud_mysql_instance", args: { "vip" => nil, "publicly_accessible" => [false] } },
      },
      "aws" => {
        "2.8"   => { resource: "aws_iam_account_password_policy", args: { "minimum_password_length" => 14 } },
        "2.9"   => { resource: "aws_iam_account_password_policy", args: { "password_reuse_prevention" => 24 } },
        "4.2"   => { resource: "aws_cloudtrail", args: { "enable_log_file_validation" => true } },
        "3.2.2" => { resource: "aws_db_instance", args: { "auto_minor_version_upgrade" => [true, nil] } },
        "3.2.3" => { resource: "aws_db_instance", args: { "publicly_accessible" => [false, nil] } },
        "6.1.1" => { resource: "aws_ebs_encryption_by_default", args: { "enabled" => true } },
        "6.7"   => { resource: "aws_instance", args: { "metadata_options" => { "http_tokens" => "required" } } },
      },
      "azure" => {
        "9.3.4" => { resource: "azurerm_storage_account", args: { "https_traffic_only_enabled" => true } },
        "9.3.6" => { resource: "azurerm_storage_account", args: { "min_tls_version" => "TLS1_2" } },
        "9.3.8" => { resource: "azurerm_storage_account", args: { "allow_nested_items_to_be_public" => false } },
        "8.3.6" => { resource: "azurerm_key_vault", args: { "enable_rbac_authorization" => true } },
        "7.6"   => { resource: "azurerm_network_watcher", args: {} },
      },
      "gcp" => {
        "2.3" => { resource: "google_logging_project_sink", args: { "filter" => /cloudaudit/ } },
        "2.13" => { resource: "google_dns_policy", args: { "enable_logging" => true } },
        "6.4" => { resource: "google_sql_database_instance", args: { "require_ssl" => true, "inside_settings" => true } },
        "4.4" => { resource: "google_compute_project_metadata", args: { "enable-oslogin" => "TRUE" } },
      },
      "alibaba" => {
        "1.11" => { resource: "alicloud_ram_account_password_policy", args: { "minimum_password_length" => 14 } },
        "2.1"  => { resource: "alicloud_actiontrail", args: { "status" => "Enable" } },
        "6.1"  => { resource: "alicloud_db_instance", args: { "ssl_action" => "Open" } },
      },
    }.freeze

    Finding = Struct.new(:id, :status, :severity, :title, :evidence, keyword_init: true)

    def self.scan(dir, cloud, catalog: nil)
      rules = RULES.fetch(cloud, {})
      return [] if rules.empty?

      files = Dir.glob(File.join(dir, "**", "*.tf"))
                 .reject { |f| f.include?("/.terraform/") || f.include?("/.git/") }
      blocks = files.flat_map { |f| extract_blocks(File.read(f), f) }
      catalog ||= Cis.catalog if Cis.cloud == cloud

      rules.map do |id, rule|
        matching = blocks.select { |b| b[:type] == rule[:resource] }
        violations = matching.reject { |b| args_ok?(rule[:args], b[:body]) }
        ctl = catalog&.controls&.find { |c| c.id == id }
        Finding.new(
          id: id,
          severity: Cis::Severity.of(ctl ? ctl.tags : []),
          title: ctl ? ctl.title : id,
          status: violations.empty? ? "PASS" : "FAIL",
          evidence: if violations.empty?
                      "#{rule[:resource]}: #{matching.size} block(s) comply"
                    else
                      "#{rule[:resource]}: #{violations.map { |b| missing(b, rule[:args]) }.join('; ')}"
                    end
        )
      end
    end

    # ---- parsing ----------------------------------------------------------

    # Find every `resource "type" "name" { ... }` block with brace pairing.
    def self.extract_blocks(src, path)
      blocks = []
      offset = 0
      while (m = src.match(/resource\s+"([^"]+)"\s+"([^"]+)"\s*\{/, offset))
        open_idx = m.end(0) - 1
        depth = 1
        i = open_idx + 1
        while i < src.length && depth.positive?
          case src[i]
          when "{" then depth += 1
          when "}" then depth -= 1
          end
          i += 1
        end
        body = src[open_idx + 1, i - open_idx - 2].to_s
        blocks << { type: m[1], name: m[2], body: body, file: path }
        offset = i
      end
      blocks
    end

    # ---- argument checks ----------------------------------------------------

    def self.args_ok?(args, body)
      args.all? { |arg, expected| arg_ok?(arg, expected, body) }
    end

    def self.arg_ok?(arg, expected, body)
      case expected
      when Hash  # nested block, e.g. metadata_options { http_tokens = "required" }
        block = nested_block(body, arg)
        block && args_ok?(expected, block)
      when Regexp
        value = extract_arg(body, arg)
        value && expected.match?(value.to_s)
      when nil # presence only
        body.match?(/^\s*#{Regexp.escape(arg)}\s*=/)
      when Array
        value = extract_arg(body, arg)
        expected.include?(value) || (value.nil? && expected.include?(nil))
      when Integer
        value = extract_arg(body, arg)
        value && value.to_i >= expected
      when Numeric
        value = extract_arg(body, arg)
        value && value.to_f >= expected.to_f
      else
        extract_arg(body, arg) == expected
      end
    end

    def self.extract_arg(body, arg)
      m = body.match(/^\s*#{Regexp.escape(arg)}\s*=\s*("([^"]*)"|(\d+(?:\.\d+)?)|(true|false))/)
      return nil unless m

      if m[2] then m[2]
      elsif m[3] then m[3].include?(".") ? m[3].to_f : m[3].to_i
      elsif m[4] then m[4] == "true"
      end
    end

    def self.nested_block(body, arg)
      m = body.match(/^\s*#{Regexp.escape(arg)}\s*\{/, 0)
      return nil unless m

      open_idx = m.end(0) - 1
      depth = 1
      i = open_idx + 1
      while i < body.length && depth.positive?
        case body[i]
        when "{" then depth += 1
        when "}" then depth -= 1
        end
        i += 1
      end
      body[open_idx + 1, i - open_idx - 2]
    end

    def self.missing(block, args)
      bad = args.reject { |arg, expected| arg_ok?(arg, expected, block[:body]) }
      "#{block[:type]}.#{block[:name]} (#{File.basename(block[:file])}) missing/weak: #{bad.keys.join(', ')}"
    end
  end
end
