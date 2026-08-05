# frozen_string_literal: true

module Cis
  # Renders control listings and scan findings.
  class Reporter
    STATUS_ORDER = %w[FAIL PASS MANUAL SKIPPED].freeze

    COLORS = {
      "PASS"    => "\e[32m",
      "FAIL"    => "\e[31m",
      "MANUAL"  => "\e[33m",
      "SKIPPED" => "\e[90m"
    }.freeze
    RESET = "\e[0m"

    def initialize(io: $stdout, color: nil)
      @io = io
      @color = color.nil? ? io.respond_to?(:tty?) && io.tty? : color
    end

    # ---- `cis list` -------------------------------------------------------

    def list(catalog, selector, format: "table")
      case format
      when "json"     then @io.puts(JSON.pretty_generate(list_payload(catalog, selector)))
      when "markdown" then list_markdown(catalog, selector)
      else                 list_table(catalog, selector)
      end
    end

    # ---- `cis scan` -------------------------------------------------------

    def scan(findings, selector, format: "table")
      case format
      when "json"     then @io.puts(JSON.pretty_generate(scan_payload(findings, selector)))
      when "markdown" then scan_markdown(findings)
      else                 scan_table(findings)
      end
    end

    private

    def paint(text, status)
      return text unless @color && COLORS[status]
      "#{COLORS[status]}#{text}#{RESET}"
    end

    def list_payload(catalog, selector)
      {
        "benchmark" => catalog.benchmark,
        "version"   => catalog.version,
        "summary"   => selector.summary,
        "controls"  => selector.selected.map do |c|
          c.to_h.merge("capability" => capability(c))
        end
      }
    end

    def capability(control)
      return "manual" if control.manual?
      caps = []
      caps << "remediate" if control.remediable?
      caps << "detect"    if control.detectable?
      caps.join("+")
    end

    def list_table(catalog, selector)
      @io.puts "#{catalog.benchmark} #{catalog.version}"
      @io.puts ""
      width = selector.selected.map { |c| c.title.length }.max || 40
      width = [[width, 46].max, 74].min
      header = format("  %-6s %-8s %-9s %-#{width}s %-15s %s",
                      "ID", "PROFILE", "ASSESS", "TITLE", "CAPABILITY", "STACK")
      @io.puts header
      @io.puts "  " + "-" * (header.length - 2)

      current = nil
      selector.selected.each do |c|
        if c.section != current
          current = c.section
          @io.puts ""
          @io.puts "  #{current} #{catalog.section_title(current)}"
        end
        @io.puts format("  %-6s %-8s %-9s %-#{width}s %-15s %s",
                        c.id,
                        "L#{c.level}",
                        c.assessment,
                        truncate(c.title, width),
                        capability(c),
                        c.stack || "-")
      end
      @io.puts ""
      print_summary(selector)
    end

    def list_markdown(catalog, selector)
      @io.puts "# #{catalog.benchmark} #{catalog.version}"
      @io.puts ""
      @io.puts "| ID | Profile | Assessment | Title | Capability | Stack |"
      @io.puts "|---|---|---|---|---|---|"
      selector.selected.each do |c|
        @io.puts "| #{c.id} | L#{c.level} | #{c.assessment} | #{c.title} " \
                 "| #{capability(c)} | #{c.stack || '-'} |"
      end
      @io.puts ""
      s = selector.summary
      @io.puts "Selected #{s['selected']}/#{s['of']} - " \
               "#{s['remediable']} remediable, #{s['detectable']} detectable, #{s['manual']} manual."
    end

    def print_summary(selector)
      s = selector.summary
      @io.puts "  selected #{s['selected']}/#{s['of']} controls  |  " \
               "remediable #{s['remediable']}  detectable #{s['detectable']}  manual #{s['manual']}"
      @io.puts "  stacks: #{s['stacks'].empty? ? '(none)' : s['stacks'].join(', ')}"
    end

    def scan_payload(findings, selector)
      {
        "summary"  => tally(findings).merge("selected" => selector.selected.size),
        "findings" => findings
      }
    end

    def scan_table(findings)
      @io.puts ""
      @io.puts format("  %-8s %-6s %-58s %s", "STATUS", "ID", "TITLE", "EVIDENCE")
      @io.puts "  " + "-" * 108
      sorted(findings).each do |f|
        @io.puts format("  %-8s %-6s %-58s %s",
                        paint(f["status"], f["status"]),
                        f["id"],
                        truncate(f["title"].to_s, 58),
                        truncate(f["evidence"].to_s, 34))
      end
      @io.puts ""
      t = tally(findings)
      @io.puts "  " + STATUS_ORDER.map { |s| "#{paint(s, s)} #{t[s]}" }.join("   ")
      @io.puts ""
    end

    def scan_markdown(findings)
      @io.puts "| Status | ID | Title | Evidence |"
      @io.puts "|---|---|---|---|"
      sorted(findings).each do |f|
        @io.puts "| #{f['status']} | #{f['id']} | #{f['title']} | #{f['evidence']} |"
      end
      @io.puts ""
      t = tally(findings)
      @io.puts STATUS_ORDER.map { |s| "**#{s}** #{t[s]}" }.join(" / ")
    end

    def sorted(findings)
      findings.sort_by do |f|
        [STATUS_ORDER.index(f["status"]) || 99, f["id"].to_s.split(".").map(&:to_i)]
      end
    end

    def tally(findings)
      STATUS_ORDER.each_with_object({}) do |s, h|
        h[s] = findings.count { |f| f["status"] == s }
      end
    end

    def truncate(text, width)
      text.length > width ? "#{text[0, width - 1]}~" : text
    end
  end
end
