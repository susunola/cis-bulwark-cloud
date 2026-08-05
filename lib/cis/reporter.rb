# frozen_string_literal: true

module Cis
  # Renders control listings, scan findings and hardening runs.
  class Reporter
    STATUS_ORDER = %w[FAIL PASS MANUAL SKIPPED].freeze

    COLORS = {
      "PASS"    => "\e[32m",
      "FAIL"    => "\e[31m",
      "MANUAL"  => "\e[33m",
      "SKIPPED" => "\e[90m"
    }.freeze
    RESET = "\e[0m"

    # A single self-contained stylesheet shared by every HTML report. No
    # external assets, so the file opens offline and prints cleanly to PDF.
    STYLE = <<~CSS.freeze
      :root {
        --primary:#1f4fd1; --primary-2:#4263eb;
        --pass:#2f9e44; --fail:#e03131; --manual:#f08c00; --skip:#868e96; --plan:#1971c2;
        --ink:#1d2939; --muted:#667085; --line:#eef0f3; --card:#fff; --page:#f7f8fa;
      }
      * { box-sizing: border-box; }
      body {
        font:15px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",
             Arial,"PingFang SC","Microsoft YaHei",sans-serif;
        color:var(--ink); background:var(--page);
        margin:0 auto; max-width:960px; padding:0 1.25rem 3rem;
        -webkit-font-smoothing:antialiased;
      }
      /* ---- hero header ---- */
      header.hero {
        background:linear-gradient(135deg,var(--primary),var(--primary-2));
        color:#fff; border-radius:0 0 18px 18px; padding:1.9rem 2rem;
        margin:0 0 1.75rem; box-shadow:0 6px 20px rgba(31,79,209,.18);
      }
      header.hero h1 { color:#fff; margin:0 0 .35rem; font-size:1.6rem; letter-spacing:.01em; }
      header.hero .meta { color:rgba(255,255,255,.82); font-size:.85rem; margin:.15rem 0; }
      /* ---- statistic cards ---- */
      .stats { display:grid; grid-template-columns:repeat(4,1fr); gap:1rem; margin:1.25rem 0 1.5rem; }
      .stat { background:var(--card); border:1px solid var(--line); border-radius:12px;
              padding:1rem 1.1rem; text-align:center; box-shadow:0 1px 2px rgba(16,24,40,.04); }
      .stat .num { display:block; font-size:1.9rem; font-weight:700; line-height:1; }
      .stat .lbl { display:block; margin-top:.45rem; font-size:.7rem; letter-spacing:.06em;
                   text-transform:uppercase; color:var(--muted); }
      .stat-fail   .num { color:var(--fail); }
      .stat-pass   .num { color:var(--pass); }
      .stat-manual .num { color:var(--manual); }
      .stat-skip   .num { color:var(--skip); }
      /* ---- cards ---- */
      .card { background:var(--card); border:1px solid var(--line); border-radius:16px;
              padding:1.25rem 1.4rem; margin:1.1rem 0;
              box-shadow:0 1px 2px rgba(16,24,40,.04),0 6px 16px rgba(16,24,40,.03); }
      .card h2 { font-size:1.05rem; margin:.1rem 0 .85rem; display:flex; align-items:center; gap:.55rem; }
      .card h2::before { content:""; width:4px; height:1.05rem; background:var(--primary);
                         border-radius:2px; display:inline-block; }
      /* ---- tables ---- */
      table { border-collapse:separate; border-spacing:0; width:100%; background:var(--card);
              border:1px solid var(--line); border-radius:12px; overflow:hidden;
              box-shadow:0 1px 2px rgba(16,24,40,.04); margin:.6rem 0 1rem; }
      thead th { background:#f2f4f7; color:var(--muted); font-size:.72rem; text-transform:uppercase;
                 letter-spacing:.05em; padding:.7rem .9rem; text-align:left; font-weight:600; }
      tbody td { padding:.65rem .9rem; border-bottom:1px solid #f0f2f5; vertical-align:top;
                 color:var(--ink); font-size:.9rem; }
      tbody tr:last-child td { border-bottom:none; }
      tbody tr:hover { background:#fafbfc; }
      tr.grp td { background:#f2f4f7; font-weight:600; color:var(--ink); }
      .mono { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
              font-weight:600; color:var(--primary); }
      /* ---- badges ---- */
      .badge { display:inline-flex; align-items:center; padding:.18rem .6rem; border-radius:999px;
               font-size:.72rem; font-weight:600; color:#fff; letter-spacing:.02em; }
      .badge.pass    { background:var(--pass); }
      .badge.fail    { background:var(--fail); }
      .badge.manual  { background:var(--manual); }
      .badge.skipped { background:var(--skip); }
      .badge.planned { background:var(--plan); }
      /* ---- footer ---- */
      footer { margin-top:2.5rem; padding-top:1rem; border-top:1px solid var(--line);
               color:#98a2b3; font-size:.78rem; text-align:center; }
      @media print {
        body { padding:0; }
        header.hero { box-shadow:none; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
        .card, .stat, table { box-shadow:none; }
        * { -webkit-print-color-adjust:exact; print-color-adjust:exact; }
      }
    CSS

    def initialize(io: $stdout, color: nil)
      @io = io
      @color = color.nil? ? io.respond_to?(:tty?) && io.tty? : color
    end

    # ---- `cis list` -------------------------------------------------------

    def list(catalog, selector, format: "table")
      body = case format
             when "json"     then JSON.pretty_generate(list_payload(catalog, selector))
             when "markdown" then list_markdown(catalog, selector)
             when "html"     then list_html(catalog, selector)
             else                 list_table(catalog, selector)
             end
      @io.puts body
      body
    end

    # ---- `cis scan` -------------------------------------------------------

    def scan(findings, selector, format: "table")
      body = case format
             when "json"     then JSON.pretty_generate(scan_payload(findings, selector))
             when "markdown" then scan_markdown(findings)
             when "html"     then scan_html(findings, selector)
             else                 scan_table(findings)
             end
      @io.puts body
      body
    end

    # ---- `cis apply --report` ---------------------------------------------
    #
    # Returns the rendered document as a string (the caller decides whether to
    # print it or write it to a file), so the same builder serves stdout,
    # `--report <path>` and a future `--format html` on apply.

    def hardening(payload, _selector, format: "html")
      case format
      when "markdown" then hardening_markdown(payload)
      when "html"     then hardening_html(payload)
      else                hardening_text(payload)
      end
    end

    private

    # ---- helpers ----------------------------------------------------------

    def h(s)
      s.to_s.gsub("&", "&amp;").gsub("<", "&lt;").gsub(">", "&gt;").gsub('"', "&quot;")
    end

    def doctype
      "<!DOCTYPE html>\n"
    end

    def head(title)
      +"" << "<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n" \
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n" \
        "<title>#{h(title)}</title>\n<style>\n" << STYLE << "\n</style></head>\n<body>\n"
    end

    def summary_bar(t)
      cells = STATUS_ORDER.map do |s|
        "<div class=\"stat stat-#{s.downcase}\"><span class=\"num\">#{t[s]}</span>" \
        "<span class=\"lbl\">#{s}</span></div>"
      end
      "<div class=\"stats\">#{cells.join}</div>\n"
    end

    def badge(status)
      cls = status.to_s.downcase
      "<span class=\"badge #{cls}\">#{h(status)}</span>"
    end

    def capability(control)
      return "manual" if control.manual?
      caps = []
      caps << "remediate" if control.remediable?
      caps << "detect"    if control.detectable?
      caps.join("+")
    end

    # ---- list payloads ----------------------------------------------------

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
                        c.id, "L#{c.level}", c.assessment, truncate(c.title, width),
                        capability(c), c.stack || "-")
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

    def list_html(catalog, selector)
      html = +"" << doctype << head("CIS Tencent Cloud — Control List")
      html << "<header class=\"hero\"><h1>Control List</h1>\n"
      html << "<p class=\"meta\">#{h(catalog.benchmark)} #{h(catalog.version)} · " \
              "generated #{h(Time.now.utc.strftime('%Y-%m-%d %H:%M UTC'))}</p></header>\n"
      html << "<main>\n<div class=\"card\"><table>\n<thead><tr><th>ID</th><th>Profile</th>" \
              "<th>Assessment</th><th>Title</th><th>Capability</th><th>Stack</th></tr></thead>\n"
      current = nil
      selector.selected.each do |c|
        if c.section != current
          current = c.section
          html << "<tr class=\"grp\"><td colspan=\"6\">#{h(c.section)} " \
                  "#{h(catalog.section_title(c.section))}</td></tr>\n"
        end
        html << "<tr><td><span class=\"mono\">#{h(c.id)}</span></td><td>L#{c.level}</td><td>#{h(c.assessment)}</td>" \
                "<td>#{h(c.title)}</td><td>#{h(capability(c))}</td><td><span class=\"mono\">#{h(c.stack || '-')}</span></td></tr>\n"
      end
      html << "</table>\n</div>\n</main>\n"
      html << "<footer>Generated by cis — CIS Tencent Cloud Foundation Benchmark toolkit.</footer>\n"
      html << "</body>\n</html>\n"
      html
    end

    def print_summary(selector)
      s = selector.summary
      @io.puts "  selected #{s['selected']}/#{s['of']} controls  |  " \
               "remediable #{s['remediable']}  detectable #{s['detectable']}  manual #{s['manual']}"
      @io.puts "  stacks: #{s['stacks'].empty? ? '(none)' : s['stacks'].join(', ')}"
    end

    # ---- scan payloads ----------------------------------------------------

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

    def scan_html(findings, selector)
      t = tally(findings)
      sections = findings.group_by { |f| f["id"].to_s.split(".").first }
      catalog = Cis.catalog
      html = +"" << doctype << head("CIS Tencent Cloud — Scan Report")
      html << "<header class=\"hero\"><h1>Scan Report</h1>\n"
      html << "<p class=\"meta\">#{h(catalog.benchmark)} #{h(catalog.version)} · " \
              "generated #{h(Time.now.utc.strftime('%Y-%m-%d %H:%M UTC'))}</p></header>\n"
      html << summary_bar(t)
      html << "<main>\n"
      sections.sort_by { |s, _| s.to_i }.each do |sec, rows|
        html << "<section class=\"card\"><h2>#{h(sec)} #{h(catalog.section_title(sec))}</h2>\n"
        html << "<table><thead><tr><th>Status</th><th>ID</th><th>Title</th>" \
                "<th>Evidence</th></tr></thead><tbody>\n"
        sorted(rows).each do |f|
          html << "<tr><td>#{badge(f['status'])}</td><td><span class=\"mono\">#{h(f['id'])}</span></td>" \
                  "<td>#{h(f['title'])}</td><td>#{h(f['evidence'])}</td></tr>\n"
        end
        html << "</tbody></table></section>\n"
      end
      html << "</main>\n"
      html << "<footer>Generated by cis — CIS Tencent Cloud Foundation Benchmark toolkit.</footer>\n"
      html << "</body>\n</html>\n"
      html
    end

    # ---- hardening report (apply --report) --------------------------------

    def hardening_html(payload)
      s = payload[:summary] || {}
      html = +"" << doctype << head("CIS Tencent Cloud — Hardening Report")
      html << "<header class=\"hero\"><h1>Hardening Report</h1>\n"
      html << "<p class=\"meta\">action: #{h(payload[:label])} · " \
              "generated #{h(payload[:generated_at])}</p>\n"
      if s.any?
        html << "<p class=\"meta\">Selection: #{s['selected']}/#{s['of']} controls " \
                "(remediable #{s['remediable']}, detectable #{s['detectable']}, " \
                "manual #{s['manual']})</p>\n"
      end
      html << "</header>\n<main>\n"
      html << "<section class=\"card\"><h2>Stacks</h2>\n<table><thead><tr><th>Stack</th>" \
              "<th>Controls</th><th>Result</th></tr></thead><tbody>\n"
      payload[:stacks].each do |st|
        html << "<tr><td><span class=\"mono\">#{h(st[:name])}</span></td><td><span class=\"mono\">#{h(st[:ids].join(', '))}</span></td>" \
                "<td>#{badge(st[:status])}</td></tr>\n"
      end
      html << "</tbody></table></section>\n"
      gaps = payload[:gaps] || []
      if gaps.any?
        html << "<section class=\"card\"><h2>Not enforced by Terraform (#{gaps.size})</h2>\n" \
                "<table><thead><tr><th>ID</th><th>Title</th></tr></thead><tbody>\n"
        gaps.each { |g| html << "<tr><td><span class=\"mono\">#{h(g['id'])}</span></td><td>#{h(g['title'])}</td></tr>\n" }
        html << "</tbody></table></section>\n"
      end
      html << "</main>\n"
      html << "<footer>Generated by cis — CIS Tencent Cloud Foundation Benchmark toolkit.</footer>\n"
      html << "</body>\n</html>\n"
      html
    end

    def hardening_markdown(payload)
      out = +"# Hardening Report (#{payload[:label]})\n\n"
      out << "_generated #{payload[:generated_at]}_\n\n"
      out << "## Stacks\n\n| Stack | Controls | Result |\n|---|---|---|\n"
      payload[:stacks].each do |st|
        out << "| #{st[:name]} | #{st[:ids].join(', ')} | #{st[:status]} |\n"
      end
      gaps = payload[:gaps] || []
      if gaps.any?
        out << "\n## Not enforced by Terraform (#{gaps.size})\n\n"
        gaps.each { |g| out << "- #{g['id']} #{g['title']}\n" }
      end
      out
    end

    def hardening_text(payload)
      out = +"Hardening Report (#{payload[:label]}) — #{payload[:generated_at]}\n\n"
      out << "Stacks:\n"
      payload[:stacks].each do |st|
        out << "  #{st[:name]} [#{st[:status]}]  #{st[:ids].join(', ')}\n"
      end
      gaps = payload[:gaps] || []
      if gaps.any?
        out << "\nNot enforced by Terraform (#{gaps.size}):\n"
        gaps.each { |g| out << "  #{g['id']} #{g['title']}\n" }
      end
      out
    end

    # ---- shared -----------------------------------------------------------

    def paint(text, status)
      return text unless @color && COLORS[status]
      "#{COLORS[status]}#{text}#{RESET}"
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
