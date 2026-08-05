# frozen_string_literal: true

require "open3"
require "shellwords"

module Cis
  # Drives terraspace on behalf of bin/cis.
  #
  # Two actions matter:
  #
  #   scan   read-only. Deploys the `audit` stack, which declares zero managed
  #          resources - only data sources, check blocks and outputs - then
  #          reads back the `cis_findings` output and renders it.
  #
  #   apply  writes. Runs the hardening stacks that own at least one selected,
  #          remediable control, in a fixed order so runs are reproducible.
  #
  # Stacks are invoked one at a time rather than through `terraspace all` so
  # that output streams in a readable order and each failure is attributable.
  # config/app.rb still sets config.all.include_stacks, so a hand-run
  # `terraspace all up` honours the same filter.
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
        # Not "nothing to report": the operator selected controls, and every
        # one of them still needs to appear as MANUAL. Returning an empty table
        # here would read as a clean bill of health.
        warn_no_detectable
        return report(manual_findings, EXIT_OK)
      end

      say "Scanning #{selector.detectable.size} control(s) via the `audit` stack (read-only)."

      if options[:dry_run]
        say "Will scan:"
        say format("  terraspace %-5s %-11s # %s", "up", Cis::AUDIT_STACK,
                   Cis.controls_for_audit.join(", "))
        return EXIT_OK
      end

      code = terraspace(%W[up #{Cis::AUDIT_STACK} -y], action: "scan")
      return EXIT_ERROR unless code.zero?

      findings = read_findings + manual_findings
      report(findings, findings.any? { |f| f["status"] == "FAIL" } ? EXIT_FINDING : EXIT_OK)
    rescue Error => e
      abort_with(e.message)
    end

    # The argument order matters: terraspace documents `terraspace up STACK`,
    # so the stack name goes first and flags follow. Building the command as
    # `up -y STACK` happens to work under Thor but is not the documented form,
    # and `scan` already uses the documented one - keep the two in step.
    def plan
      run_hardening("plan") { |stack| %W[plan #{stack}] }
    end

    def apply
      run_hardening("apply") { |stack| %W[up #{stack} -y] }
    end

    # `cis destroy` is deliberately not exposed as a first-class verb - rolling
    # back a hardening baseline should be a conscious, per-stack decision.
    def destroy(stack)
      unless Cis::HARDENING_STACKS.include?(stack)
        return abort_with("#{stack.inspect} is not a hardening stack " \
                          "(#{Cis::HARDENING_STACKS.join(', ')})")
      end
      terraspace(%W[down #{stack} -y], action: "apply")
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
        say ""
        say "#{'=' * 70}"
        say "#{label} #{r[:name]}  (#{r[:ids].size} control(s): #{r[:ids].join(', ')})"
        say "#{'=' * 70}"
        code = terraspace(build.call(r[:name]), action: "apply")
        if code.zero?
          r[:status] = "ok"
        else
          r[:status] = "fail"
          @io.puts "\n  stack #{r[:name]} failed (exit #{code}); stopping."
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
        say format("  terraspace %-5s %-11s # %s", label == "apply" ? "up" : "plan", stack, ids.join(", "))
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

    def report(findings, code)
      body = @reporter.scan(findings, selector, format: options.fetch(:format, "table"))
      write_output(body)
      code
    end

    # `--output PATH` diverts the rendered list/scan report to a file instead
    # of stdout; the operator still sees the narration on the console.
    def write_output(body)
      return unless options[:output]
      File.write(options[:output], body)
      say "Report written to #{options[:output]}" unless json?
    rescue SystemCallError => e
      abort_with("could not write report to #{options[:output]}: #{e.message}")
    end

    # `cis apply --report [PATH]` writes an HTML hardening report after the run.
    # It is the artifact this toolkit was missing: a durable record of what was
    # actually enforced, per stack, plus the controls Terraform could not touch.
    def emit_hardening_report(label, results)
      path = options[:report] == true ? default_report_path : options[:report].to_s
      payload = {
        label:       label,
        generated_at: Time.now.utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
        summary:     selector.summary,
        stacks:      results,
        gaps:        selector.not_remediable.map { |c| { "id" => c.id, "title" => c.title } }
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

    # Controls the operator asked for that Terraform cannot assess. Emitting
    # them keeps the report honest: a short green table that quietly dropped
    # 40 controls is worse than no report at all.
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

    # ---- terraspace plumbing ---------------------------------------------

    def terraspace(args, action:)
      cmd = ["terraspace", *args]
      env = child_env(action)
      say "=> #{cmd.join(' ')}" if options[:verbose]
      return EXIT_OK if options[:dry_run]

      ok = system(env, *cmd, chdir: Cis::ROOT)
      status = Process.last_status
      return status.exitstatus if status
      ok ? EXIT_OK : EXIT_ERROR
    end

    def capture(args, action:)
      env = child_env(action)
      out, err, status = Open3.capture3(env, "terraspace", *args, chdir: Cis::ROOT)
      raise Error, "terraspace #{args.join(' ')} failed: #{err.strip}" unless status.success?
      out
    end

    def child_env(action)
      selector.to_env.merge(
        "TS_CIS_ACTION" => action,
        # Terraspace prompts on `up` unless it believes it is non-interactive.
        "TS_QUIET"      => ENV.fetch("TS_QUIET", "0")
      )
    end

    # ---- reading findings back -------------------------------------------

    def read_findings
      dir = build_dir(Cis::AUDIT_STACK)
      raise Error, "could not locate the built audit stack" unless dir && Dir.exist?(dir)

      out, err, status = Open3.capture3("terraform", "output", "-json", chdir: dir)
      raise Error, "terraform output failed: #{err.strip}" unless status.success?

      parsed = JSON.parse(out)
      node = parsed["cis_findings"]
      raise Error, "the audit stack did not emit a cis_findings output" if node.nil?

      normalize(node["value"])
    rescue JSON::ParserError => e
      raise Error, "could not parse terraform output: #{e.message}"
    end

    # `cis_findings` is a map keyed by control id; flatten it into rows and
    # attach the human title from the registry.
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

    def build_dir(stack)
      out = capture(%W[info #{stack} --path], action: "scan").strip
      path = out.lines.map(&:strip).reject(&:empty?).last
      return File.expand_path(path, Cis::ROOT) if path && !path.empty?
      nil
    rescue Error
      # Fall back to the conventional layout if `info` is unavailable.
      Dir.glob(File.join(Cis::ROOT, ".terraspace-cache", "**", "stacks", stack)).first
    end

    # Narration goes to stderr whenever the caller asked for a machine-readable
    # report, so `cis scan --format json | jq` never chokes on prose.
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
