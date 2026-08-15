# frozen_string_literal: true

require "open3"
require "shellwords"
require "json"

module Cis
  # Drives `terraform` on behalf of bin/cis-cloud.
  #
  # Stacks live under stacks/<name>/ as self-contained Terraform root modules.
  # Each is invoked individually so output streams in order and failures are
  # attributable.
  class Runner
    EXIT_OK      = 0
    EXIT_FINDING = 1
    EXIT_ERROR   = 2

    attr_reader :selector, :options

    def initialize(selector:, options: {}, io: $stdout, err: $stderr)
      @selector = selector
      @options  = options
      @io       = io
      @err      = err
      @reporter = Reporter.new(io: io, color: options[:color])
    end

    # ---- actions ----------------------------------------------------------

    def list
      body = @reporter.list(Cis.catalog, selector, format: options.fetch(:format, "table"))
      write_output(body)
      EXIT_OK
    end

    def scan
      if selector.detectable.empty?
        warn_no_detectable
        return report(with_severity(manual_findings), EXIT_OK, account: build_account)
      end

      say "Scanning #{selector.detectable.size} control(s) via the `audit` stack (read-only)."

      if options[:dry_run]
        say "Will scan:"
        say format("  terraform -chdir=%s apply -auto-approve # %s",
                   rel_stack_dir(Cis::AUDIT_STACK), Cis.controls_for_audit.join(", "))
        return EXIT_OK
      end

      init_code = terraform_init(Cis::AUDIT_STACK)
      return EXIT_ERROR unless init_code.zero?

      code = terraform_apply(Cis::AUDIT_STACK, Cis.controls_for_audit, action: "scan")
      return EXIT_ERROR unless code.zero?

      account = build_account(terraform: true)
      findings = with_severity(read_findings + manual_findings)
      findings = Cis::Suppressions.load.apply(findings, Cis.cloud)
      report(findings, findings.any? { |f| f["status"] == "FAIL" } ? EXIT_FINDING : EXIT_OK,
             account: account)
    rescue Error => e
      abort_with(e.message)
    end

    def check(findings)
      body = @reporter.scan(findings, selector, format: options.fetch(:format, "table"))
      write_output(body)
      findings.any? { |f| f["status"] == "FAIL" } ? EXIT_FINDING : EXIT_OK
    end

    def compliance(compliance)
      body = @reporter.compliance(compliance, format: options.fetch(:format, "table"))
      write_output(body)
      EXIT_OK
    end

    def plan
      run_hardening("plan") { |stack, ids| %W[plan -var enabled_controls=#{Shellwords.escape(ids.to_json)}] }
    end

    def apply
      run_hardening("apply") { |stack, ids| %W[apply -auto-approve -var enabled_controls=#{Shellwords.escape(ids.to_json)}] }
    end

    def destroy(stack)
      unless Cis.hardening_stacks.include?(stack)
        return abort_with("#{stack.inspect} is not a hardening stack " \
                          "(#{Cis.hardening_stacks.join(', ')})")
      end
      terraform(["destroy", "-auto-approve"], stack, action: "apply")
    end

    private

    def run_hardening(label, &build)
      stacks = selector.stacks_for_apply
      if stacks.empty?
        warn_no_remediable
        return EXIT_OK
      end

      print_plan_preamble(label, stacks)
      results = stacks.map do |stack|
        { name: stack, ids: Cis.controls_for_stack(stack), status: "planned" }
      end

      code = if options[:dry_run]
               EXIT_OK
             else
               run_stacks(label, results, &build)
             end

      report_gaps
      emit_hardening_report(label, results) if options[:report]
      code
    end

    def run_stacks(label, results, &build)
      results.each do |r|
        next if r[:ids].empty?

        say ""
        say "#{'=' * 70}"
        say "#{label} #{r[:name]}  (#{r[:ids].size} control(s): #{r[:ids].join(', ')})"
        say "#{'=' * 70}"

        init_code = terraform_init(r[:name])
        unless init_code.zero?
          r[:status] = "fail"
          say "  stack #{r[:name]} init failed (exit #{init_code}); stopping."
          return EXIT_ERROR
        end

        code = terraform(build.call(r[:name], r[:ids]), r[:name], action: "apply")
        if code.zero?
          r[:status] = "ok"
        else
          r[:status] = "fail"
          say "  stack #{r[:name]} failed (exit #{code}); stopping."
          return EXIT_ERROR
        end
      end
      EXIT_OK
    end

    def print_plan_preamble(label, stacks)
      s = selector.summary
      say "Selection: #{s['selected']}/#{s['of']} controls  " \
          "(remediable #{s['remediable']}, detectable #{s['detectable']}, manual #{s['manual']})"
      say "Will #{label}:"
      stacks.each do |stack|
        ids = Cis.controls_for_stack(stack)
        say format("  terraform -chdir=%-15s %-5s # %s",
                   rel_stack_dir(stack), label, ids.join(", "))
      end
    end

    def report_gaps
      gaps = selector.not_remediable
      return if gaps.empty?
      say ""
      say "Not enforced by Terraform (#{gaps.size}) - handle these out of band:"
      gaps.each { |c| say format("  %-6s %s", c.id, c.title) }
    end

    def warn_no_detectable
      say "No selected control is machine-assessable by the provider."
      say "Selected: #{selector.selected.size}. Use `cis list` to see why."
    end

    def warn_no_remediable
      say "No selected control is enforceable by Terraform - nothing to apply."
      report_gaps
    end

    def report(findings, code, account: nil)
      body = @reporter.scan(findings, selector, format: options.fetch(:format, "table"), account: account)
      write_output(body)
      code
    end

    def write_output(body)
      return unless options[:output]
      File.write(options[:output], body)
      say "Report written to #{options[:output]}" unless json?
    rescue SystemCallError => e
      abort_with("could not write report to #{options[:output]}: #{e.message}")
    end

    def emit_hardening_report(label, results)
      path = options[:report] == true ? default_report_path : options[:report].to_s
      payload = {
        label:        label,
        generated_at: Time.now.utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
        account:      build_account,
        summary:      selector.summary,
        stacks:       results,
        gaps:         selector.not_remediable.map { |c| { "id" => c.id, "title" => c.title } }
      }
      body = @reporter.hardening(payload, selector, format: "html")
      File.write(path, body)
      say "Hardening report written to #{path}"
    rescue SystemCallError => e
      abort_with("could not write report to #{path}: #{e.message}")
    end

    def default_report_path
      "cis-hardening-#{Time.now.utc.strftime('%Y%m%d-%H%M%S')}.html"
    end

    def build_account(terraform: false)
      acct = {
        "uin"    => ENV["CIS_UIN"],
        "name"   => ENV["CIS_ACCOUNT_NAME"],
        "app_id" => ENV["CIS_APP_ID"],
        "region" => ENV["TENCENTCLOUD_REGION"]
      }.compact
      if terraform && !options[:dry_run]
        (read_account || {}).each { |k, v| acct[k] = v unless v.nil? || v.to_s.empty? }
      end
      acct
    end

    def read_account
      dir = Cis.stack_dir(Cis::AUDIT_STACK)
      out, _err, status = Open3.capture3("terraform", "output", "-json", "cis_account", chdir: dir)
      return nil unless status.success?
      parsed = JSON.parse(out)
      val = parsed["value"]
      val.is_a?(Hash) ? val.each_with_object({}) { |(k, v), h| h[k.to_s] = v } : nil
    rescue StandardError
      nil
    end

    def manual_findings
      selector.not_detectable.map do |c|
        {
          "id"       => c.id,
          "title"    => c.title,
          "status"   => c.remediable? ? "SKIPPED" : "MANUAL",
          "evidence" => c.remediable? ? "enforced by `cis apply`, not readable" : "verify in console"
        }
      end
    end

    # Attach a risk severity to every finding, derived from the registry
    # control's tags.
    def with_severity(findings)
      by_id = selector.catalog.controls.to_h { |c| [c.id, c] }
      findings.map do |f|
        ctl = by_id[f["id"]]
        f.key?("severity") ? f : f.merge("severity" => Cis::Severity.of(ctl ? ctl.tags : []))
      end
    end

    # ---- terraform plumbing -----------------------------------------------

    # stacks/<name> for tencent, stacks/<cloud>/<name> for later clouds -
    # the display form of Cis.stack_dir, relative to the repo root.
    def rel_stack_dir(stack)
      Cis.stack_dir(stack).sub("#{Cis::ROOT}/", "")
    end

    def terraform_init(stack)
      dir = Cis.stack_dir(stack)
      say "  terraform -chdir=#{rel_stack_dir(stack)} init"
      return EXIT_OK if options[:dry_run]

      _out, err, status = Open3.capture3("terraform", "init",
                                         "-input=false",
                                         chdir: dir)
      unless status.success?
        say "  init warning: #{err.strip.lines.first}"
      end
      status.exitstatus
    end

    def terraform_apply(stack, control_ids, action:)
      ids_json = Shellwords.escape(control_ids.to_json)
      terraform(["apply", "-auto-approve", "-var", "enabled_controls=#{ids_json}"],
                stack, action: action)
    end

    def terraform(args, stack, action:)
      dir = Cis.stack_dir(stack)
      cmd = ["terraform", "-chdir=#{dir}", *args]
      say "=> #{cmd.join(' ')}" if options[:verbose]
      return EXIT_OK if options[:dry_run]

      system(*cmd)
      status = Process.last_status
      return status.exitstatus if status
      EXIT_ERROR
    end

    # ---- reading findings back -------------------------------------------

    def read_findings
      dir = Cis.stack_dir(Cis::AUDIT_STACK)
      out, err, status = Open3.capture3("terraform", "output", "-json", chdir: dir)
      raise Error, "terraform output failed: #{err.strip}" unless status.success?

      parsed = JSON.parse(out)
      node = parsed["cis_findings"]
      raise Error, "the audit stack did not emit a cis_findings output" if node.nil?

      normalize(node["value"])
    rescue JSON::ParserError => e
      raise Error, "could not parse terraform output: #{e.message}"
    end

    def normalize(value)
      rows =
        case value
        when Hash  then value.map { |id, v| (v.is_a?(Hash) ? v : { "status" => v.to_s }).merge("id" => id) }
        when Array then value.map { |v| v.is_a?(Hash) ? v : { "status" => v.to_s } }
        else            []
        end

      rows.map do |row|
        control = Cis.catalog[row["id"].to_s]
        {
          "id"       => row["id"].to_s,
          "title"    => row["title"] || control&.title || "(unknown control)",
          "status"   => row["status"].to_s.upcase,
          "evidence" => row["evidence"].to_s
        }
      end
    end

    def say(msg)
      (json? ? @err : @io).puts msg
    end

    def json?
      options[:format] == "json"
    end

    def abort_with(msg)
      @err.puts "error: #{msg}"
      EXIT_ERROR
    end
  end
end
