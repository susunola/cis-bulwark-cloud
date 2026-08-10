# frozen_string_literal: true

module Cis
  # Renders control listings, scan findings and hardening runs.
  class Reporter
    STATUS_ORDER = %w[FAIL PASS MANUAL SKIPPED SUPPRESSED].freeze

    COLORS = {
      "PASS"    => "\e[32m",
      "FAIL"    => "\e[31m",
      "MANUAL"  => "\e[33m",
      "SKIPPED" => "\e[90m",
      "SUPPRESSED" => "\e[90m"
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
      /* ---- account bar (UIN / name / region) ---- */
      .acct { display:flex; flex-wrap:wrap; gap:.5rem 1.4rem; margin-top:.9rem; }
      .acct .kv { display:flex; flex-direction:column; line-height:1.3; }
      .acct .k { font-size:.66rem; letter-spacing:.08em; text-transform:uppercase;
                 color:rgba(255,255,255,.7); }
      .acct .v { font-size:.95rem; font-weight:600; color:#fff;
                 font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }
      /* ---- filter bar ---- */
      .filters { display:flex; flex-wrap:wrap; align-items:center; gap:.55rem;
                 margin:1.25rem 0 .5rem; }
      .filters #q { flex:1 1 240px; min-width:200px; padding:.55rem .8rem; font-size:.9rem;
                    border:1px solid var(--line); border-radius:9px; background:var(--card);
                    color:var(--ink); }
      .filter-btn { cursor:pointer; border:1px solid var(--line); background:var(--card);
                    color:var(--muted); padding:.45rem .85rem; border-radius:999px;
                    font-size:.8rem; font-weight:600; transition:all .15s; }
      .filter-btn:hover { border-color:var(--primary); color:var(--primary); }
      .filter-btn.active { background:var(--primary); border-color:var(--primary); color:#fff; }
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
      .badge.skipped    { background:var(--skip); }
      .badge.suppressed { background:var(--skip); }
      .badge.sev-critical { background:#c92a2a; }
      .badge.sev-high     { background:#e8590c; }
      .badge.sev-medium   { background:#f08c00; }
      .badge.sev-low      { background:#868e96; }
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

    def scan(findings, selector, format: "table", account: nil)
      body = case format
             when "json"     then JSON.pretty_generate(scan_payload(findings, selector))
             when "markdown" then scan_markdown(findings)
             when "html"     then scan_html(findings, selector, account: account)
             when "csv"      then scan_csv(findings)
             when "junit"    then scan_junit(findings)
             else                 scan_table(findings)
             end
      @io.puts body
      body
    end

    # ---- `cis compliance` --------------------------------------------------

    def compliance(compliance, format: "table")
      body = case format
             when "json"     then JSON.pretty_generate(compliance_payload(compliance))
             when "markdown" then compliance_markdown(compliance)
             when "html"     then compliance_html(compliance)
             else                 compliance_table(compliance)
             end
      @io.puts body
      body
    end

    def compliance_payload(c)
      { "clouds" => c.per_cloud.transform_values { |v| v.slice("benchmark", "version", "summary", "status", "fail_by_severity") },
        "global" => c.global }
    end

    def compliance_table(c)
      g = c.global
      @io.puts "Cross-cloud compliance posture"
      @io.puts ""
      @io.puts format("  %-9s %8s %8s %8s %8s", "CLOUD", "FAIL", "PASS", "MANUAL", "OTHER")
      @io.puts "  " + "-" * 46
      c.per_cloud.each do |cloud, v|
        st = v[:status]
        other = st["SKIPPED"] + st["SUPPRESSED"]
        @io.puts format("  %-9s %8d %8d %8d %8d", cloud, st["FAIL"], st["PASS"], st["MANUAL"], other)
      end
      @io.puts "  " + "-" * 46
      gst = g[:status]
      @io.puts format("  %-9s %8d %8d %8d %8d", "TOTAL", gst["FAIL"], gst["PASS"], gst["MANUAL"], gst["SKIPPED"] + gst["SUPPRESSED"])
      @io.puts ""
      @io.puts "  Failing by severity: " + Compliance::SEVERITY_ORDER.map { |lv| "#{lv} #{g[:fail_by_severity][lv]}" }.join("  ")
      if g[:failing].any?
        @io.puts ""
        @io.puts "  Failing controls:"
        g[:failing].each do |f|
          cloud = c.entries.find { |e| e[:findings].include?(f) }[:cloud]
          @io.puts format("    %-10s %-8s %-8s %-52s %s", cloud, f["severity"], f["id"],
                          truncate(f["title"].to_s, 52), truncate(f["evidence"].to_s, 40))
        end
      end
      @io.puts ""
    end

    def compliance_markdown(c)
      g = c.global
      out = +"# Cross-cloud Compliance\n\n"
      out << "| Cloud | FAIL | PASS | MANUAL | SKIPPED | SUPPRESSED |\n|---|---|---|---|---|---|\n"
      c.per_cloud.each do |cloud, v|
        st = v[:status]
        out << "| #{cloud} | #{st['FAIL']} | #{st['PASS']} | #{st['MANUAL']} | #{st['SKIPPED']} | #{st['SUPPRESSED']} |\n"
      end
      gst = g[:status]
      out << "| **Total** | **#{gst['FAIL']}** | **#{gst['PASS']}** | **#{gst['MANUAL']}** | **#{gst['SKIPPED']}** | **#{gst['SUPPRESSED']}** |\n\n"
      out << "Failing by severity: " << Compliance::SEVERITY_ORDER.map { |lv| "#{lv} #{g[:fail_by_severity][lv]}" }.join(" / ") << "\n\n"
      if g[:failing].any?
        out << "## Failing controls\n\n| Cloud | Severity | ID | Title | Evidence |\n|---|---|---|---|---|\n"
        g[:failing].each do |f|
          cloud = c.entries.find { |e| e[:findings].include?(f) }[:cloud]
          out << "| #{cloud} | #{f['severity']} | #{f['id']} | #{f['title']} | #{f['evidence']} |\n"
        end
      end
      out
    end

    def compliance_html(c)
      g = c.global
      html = +"" << doctype << head("CIS Multi-Cloud — Compliance Posture")
      html << "<header class=\"hero\"><h1>Cross-Cloud Compliance Posture</h1>\n"
      html << "<p class=\"meta\">generated #{h(Time.now.utc.strftime('%Y-%m-%d %H:%M UTC'))}</p></header>\n"
      html << "<main>\n"
      html << "<section class=\"card\"><h2>Per cloud</h2>\n<table><thead><tr><th>Cloud</th><th>FAIL</th>" \
              "<th>PASS</th><th>MANUAL</th><th>SKIPPED</th><th>SUPPRESSED</th><th>Critical fails</th></tr></thead><tbody>\n"
      c.per_cloud.each do |cloud, v|
        st = v[:status]
        html << "<tr><td><span class=\"mono\">#{h(cloud)}</span></td><td>#{st['FAIL']}</td><td>#{st['PASS']}</td>" \
                "<td>#{st['MANUAL']}</td><td>#{st['SKIPPED']}</td><td>#{st['SUPPRESSED']}</td>" \
                "<td>#{v[:fail_by_severity]['critical']}</td></tr>\n"
      end
      gst = g[:status]
      html << "<tr><td><strong>Total</strong></td><td><strong>#{gst['FAIL']}</strong></td><td><strong>#{gst['PASS']}</strong></td>" \
              "<td><strong>#{gst['MANUAL']}</strong></td><td><strong>#{gst['SKIPPED']}</strong></td>" \
              "<td><strong>#{gst['SUPPRESSED']}</strong></td><td></td></tr>\n"
      html << "</tbody></table></section>\n"
      if g[:failing].any?
        html << "<section class=\"card\"><h2>Failing controls (#{g[:failing].size})</h2>\n" \
                "<table><thead><tr><th>Cloud</th><th>Severity</th><th>ID</th><th>Title</th><th>Evidence</th></tr></thead><tbody>\n"
        g[:failing].each do |f|
          cloud = c.entries.find { |e| e[:findings].include?(f) }[:cloud]
          html << "<tr><td><span class=\"mono\">#{h(cloud)}</span></td>" \
                  "<td><span class=\"badge sev-#{f['severity']}\">#{h(f['severity'])}</span></td>" \
                  "<td><span class=\"mono\">#{h(f['id'])}</span></td><td>#{h(f['title'])}</td><td>#{h(f['evidence'])}</td></tr>\n"
        end
        html << "</tbody></table></section>\n"
      end
      html << "</main>\n<footer>CIS multi-cloud compliance</footer>\n</body>\n</html>\n"
      html
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

    # Account header: UIN, account name, app id, region. Returns "" when there
    # is nothing to show, so reports that cannot resolve an account stay clean.
    def account_bar(account)
      acct = (account || {}).reject { |_, v| v.nil? || v.to_s.empty? }
      return "" if acct.empty?
      fields = []
      fields << ["UIN", acct["uin"]]          if acct["uin"]
      fields << ["Account name", acct["name"]] if acct["name"]
      fields << ["APP ID", acct["app_id"]]     if acct["app_id"]
      fields << ["Region", acct["region"]]     if acct["region"]
      items = fields.map do |k, v|
        "<div class=\"kv\"><span class=\"k\">#{h(k)}</span><span class=\"v\">#{h(v)}</span></div>"
      end.join
      "<div class=\"acct\">#{items}</div>\n"
    end

    # Filter bar above the findings tables. "Enforced" = PASS, "Not enforced" =
    # everything else. Filtering is client-side, so the file stays self-contained.
    def filter_bar
      buttons = [
        ["ALL",      "All"],
        ["ENFORCED", "Enforced"],
        ["NOT",      "Not enforced"],
        ["FAIL",     "FAIL"],
        ["MANUAL",   "MANUAL"],
        ["SKIPPED",  "SKIPPED"]
      ].map do |status, label|
        cls = status == "ALL" ? "filter-btn active" : "filter-btn"
        "<button class=\"#{cls}\" data-status=\"#{status}\" onclick=\"setFilter(this)\">#{label}</button>"
      end.join
      "<div class=\"filters\">" \
      "<input id=\"q\" type=\"search\" placeholder=\"Search by ID or title…\" oninput=\"applyFilter()\">" \
      "#{buttons}</div>\n"
    end

    def filter_script
      <<~JS
        <script>
        function setFilter(btn){
          document.querySelectorAll('.filter-btn').forEach(function(b){b.classList.remove('active');});
          btn.classList.add('active');
          applyFilter();
        }
        function applyFilter(){
          var q = (document.getElementById('q').value||'').trim().toLowerCase();
          var st = document.querySelector('.filter-btn.active').getAttribute('data-status');
          document.querySelectorAll('tbody tr[data-status]').forEach(function(tr){
            var s = tr.getAttribute('data-status');
            var okS = st==='ALL' || (st==='ENFORCED' && s==='PASS') ||
                      (st==='NOT' && s!=='PASS') || st===s;
            var txt = (tr.getAttribute('data-search')||'').toLowerCase();
            var okT = q==='' || txt.indexOf(q) !== -1;
            tr.style.display = (okS && okT) ? '' : 'none';
          });
          document.querySelectorAll('section.card').forEach(function(sec){
            var rows = sec.querySelectorAll('tbody tr[data-status]');
            if (rows.length === 0) return;
            var visible = Array.prototype.filter.call(rows, function(r){return r.style.display !== 'none';});
            sec.style.display = visible.length === 0 ? 'none' : '';
          });
        }
        </script>
      JS
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
      html << "<footer>CIS Tencent Cloud Foundation Benchmark v1.0.0</footer>\n"
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
      @io.puts format("  %-10s %-8s %-7s %-44s %s", "STATUS", "ID", "SEV", "TITLE", "EVIDENCE")
      @io.puts "  " + "-" * 110
      sorted(findings).each do |f|
        @io.puts format("  %-10s %-8s %-7s %-44s %s",
                        paint(f["status"], f["status"]),
                        f["id"],
                        f["severity"],
                        truncate(f["title"].to_s, 44),
                        truncate(f["evidence"].to_s, 38))
      end
      @io.puts ""
      t = tally(findings)
      @io.puts "  " + STATUS_ORDER.map { |s| "#{paint(s, s)} #{t[s]}" }.join("   ")
      @io.puts ""
    end

    def scan_markdown(findings)
      @io.puts "| Status | Severity | ID | Title | Evidence |"
      @io.puts "|---|---|---|---|---|"
      sorted(findings).each do |f|
        @io.puts "| #{f['status']} | #{f['severity']} | #{f['id']} | #{f['title']} | #{f['evidence']} |"
      end
      @io.puts ""
      t = tally(findings)
      @io.puts STATUS_ORDER.map { |s| "**#{s}** #{t[s]}" }.join(" / ")
    end

    def scan_csv(findings)
      require "csv"
      out = CSV.generate do |csv|
        csv << %w[status severity id title evidence]
        sorted(findings).each { |f| csv << [f["status"], f["severity"], f["id"], f["title"], f["evidence"]] }
      end
      @io.puts out
      out
    end

    def scan_junit(findings)
      failed = findings.select { |f| f["status"] == "FAIL" }
      xml = +"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
      xml << "<testsuite name=\"cis-scan\" tests=\"#{findings.size}\" failures=\"#{failed.size}\">\n"
      sorted(findings).each do |f|
        xml << "  <testcase name=\"#{h(f['id'])} #{h(f['title'])}\" classname=\"#{h(f['severity'] || 'unknown')}\">\n"
        if f["status"] == "FAIL"
          xml << "    <failure message=\"#{h(f['evidence'])}\" />\n"
        elsif f["status"] == "SUPPRESSED"
          xml << "    <skipped message=\"suppressed\" />\n"
        end
        xml << "  </testcase>\n"
      end
      xml << "</testsuite>\n"
      @io.puts xml
      xml
    end

    def scan_html(findings, selector, account: nil)
      t = tally(findings)
      sections = findings.group_by { |f| f["id"].to_s.split(".").first }
      catalog = Cis.catalog
      html = +"" << doctype << head("CIS Tencent Cloud — Scan Report")
      html << "<header class=\"hero\"><h1>Scan Report</h1>\n"
      html << "<p class=\"meta\">#{h(catalog.benchmark)} #{h(catalog.version)} · " \
              "generated #{h(Time.now.utc.strftime('%Y-%m-%d %H:%M UTC'))}</p>\n"
      html << account_bar(account)
      html << "</header>\n"
      html << summary_bar(t)
      html << filter_bar
      html << "<main>\n"
      # "enforced" = PASS, everything else is "not enforced".
      sections.sort_by { |s, _| s.to_i }.each do |sec, rows|
        html << "<section class=\"card\"><h2>#{h(sec)} #{h(catalog.section_title(sec))}</h2>\n"
        html << "<table><thead><tr><th>Status</th><th>Severity</th><th>ID</th><th>Title</th>" \
                "<th>Evidence</th></tr></thead><tbody>\n"
        sorted(rows).each do |f|
          s = h(f["status"])
          search = h("#{f['id']} #{f['title']}").downcase
          html << "<tr data-status=\"#{s}\" data-search=\"#{search}\">" \
                  "<td>#{badge(f['status'])}</td>" \
                  "<td><span class=\"badge sev-#{f['severity']}\">#{h(f['severity'])}</span></td>" \
                  "<td><span class=\"mono\">#{h(f['id'])}</span></td>" \
                  "<td>#{h(f['title'])}</td><td>#{h(f['evidence'])}</td></tr>\n"
        end
        html << "</tbody></table></section>\n"
      end
      html << "</main>\n"
      html << filter_script
      html << "<footer>CIS Tencent Cloud Foundation Benchmark v1.0.0</footer>\n"
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
      html << account_bar(payload[:account])
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
      html << "<footer>CIS Tencent Cloud Foundation Benchmark v1.0.0</footer>\n"
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
