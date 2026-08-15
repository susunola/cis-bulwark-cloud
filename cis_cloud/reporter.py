"""Renders control listings, scan findings and hardening runs."""

from __future__ import annotations

import csv
import html as _html
import io
import json
import sys
from datetime import datetime, timezone
from typing import Any, Optional, TextIO

from . import get_catalog as _catalog_mod
from .compliance import SEVERITY_ORDER as COMPLIANCE_SEVERITY_ORDER
from .compliance import Compliance
from .frameworks import FRAMEWORK_TITLES as _FRAMEWORK_TITLES

STATUS_ORDER = ["FAIL", "PASS", "MANUAL", "SKIPPED", "SUPPRESSED"]

COLORS = {
    "PASS": "\033[32m",
    "FAIL": "\033[31m",
    "MANUAL": "\033[33m",
    "SKIPPED": "\033[90m",
    "SUPPRESSED": "\033[90m",
}
RESET = "\033[0m"

STYLE = """
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
header.hero {
  background:linear-gradient(135deg,var(--primary),var(--primary-2));
  color:#fff; border-radius:0 0 18px 18px; padding:1.9rem 2rem;
  margin:0 0 1.75rem; box-shadow:0 6px 20px rgba(31,79,209,.18);
}
header.hero h1 { color:#fff; margin:0 0 .35rem; font-size:1.6rem; letter-spacing:.01em; }
header.hero .meta { color:rgba(255,255,255,.82); font-size:.85rem; margin:.15rem 0; }
.acct { display:flex; flex-wrap:wrap; gap:.5rem 1.4rem; margin-top:.9rem; }
.acct .kv { display:flex; flex-direction:column; line-height:1.3; }
.acct .k { font-size:.66rem; letter-spacing:.08em; text-transform:uppercase;
           color:rgba(255,255,255,.7); }
.acct .v { font-size:.95rem; font-weight:600; color:#fff;
           font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }
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
.card { background:var(--card); border:1px solid var(--line); border-radius:16px;
        padding:1.25rem 1.4rem; margin:1.1rem 0;
        box-shadow:0 1px 2px rgba(16,24,40,.04),0 6px 16px rgba(16,24,40,.03); }
.card h2 { font-size:1.05rem; margin:.1rem 0 .85rem; display:flex; align-items:center; gap:.55rem; }
.card h2::before { content:""; width:4px; height:1.05rem; background:var(--primary);
                   border-radius:2px; display:inline-block; }
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
footer { margin-top:2.5rem; padding-top:1rem; border-top:1px solid var(--line);
         color:#98a2b3; font-size:.78rem; text-align:center; }
@media print {
  body { padding:0; }
  header.hero { box-shadow:none; -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .card, .stat, table { box-shadow:none; }
  * { -webkit-print-color-adjust:exact; print-color-adjust:exact; }
}
"""


def _now_utc(fmt: str) -> str:
    return datetime.now(timezone.utc).strftime(fmt)


class Reporter:
    def __init__(self, io: Optional[TextIO] = None, err: Optional[TextIO] = None,
                 color: Optional[bool] = None):
        self.io = io or sys.stdout
        self.err = err or sys.stderr
        if color is None:
            color = hasattr(self.io, "isatty") and self.io.isatty()
        self.color = color

    # ---- `list` -----------------------------------------------------------

    def list(self, catalog, selector, format_: str = "table") -> str:
        if format_ == "json":
            body = json.dumps(self._list_payload(catalog, selector), indent=2, ensure_ascii=False)
        elif format_ == "markdown":
            body = self._list_markdown(catalog, selector)
        elif format_ == "html":
            body = self._list_html(catalog, selector)
        else:
            body = self._list_table(catalog, selector)
        self.io.write(body + "\n")
        return body

    # ---- `scan` -----------------------------------------------------------

    def scan(self, findings: list[dict], selector, format_: str = "table",
             account: Optional[dict] = None) -> str:
        if format_ == "json":
            body = json.dumps(self._scan_payload(findings, selector), indent=2, ensure_ascii=False)
        elif format_ == "markdown":
            body = self._scan_markdown(findings)
        elif format_ == "html":
            body = self._scan_html(findings, selector, account=account)
        elif format_ == "csv":
            body = self._scan_csv(findings)
        elif format_ == "junit":
            body = self._scan_junit(findings)
        elif format_ == "sarif":
            body = self._scan_sarif(findings, selector)
        else:
            body = self._scan_table(findings)
        self.io.write(body + "\n")
        return body

    # ---- `compliance` ------------------------------------------------------

    def compliance(self, compliance: Compliance, format_: str = "table") -> str:
        if format_ == "json":
            body = json.dumps(self._compliance_payload(compliance), indent=2, ensure_ascii=False)
        elif format_ == "markdown":
            body = self._compliance_markdown(compliance)
        elif format_ == "html":
            body = self._compliance_html(compliance)
        else:
            body = self._compliance_table(compliance)
        self.io.write(body + "\n")
        return body

    def _compliance_payload(self, c: Compliance) -> dict:
        per = {}
        for cloud, v in c.per_cloud().items():
            per[cloud] = {k: v[k] for k in ("benchmark", "version", "summary", "status", "fail_by_severity")}
        return {"clouds": per, "global": c.global_()}

    def _compliance_table(self, c: Compliance) -> str:
        g = c.global_()
        out = io.StringIO()
        out.write("Cross-cloud compliance posture\n\n")
        out.write(f"  {'CLOUD':<9} {'FAIL':>8} {'PASS':>8} {'MANUAL':>8} {'OTHER':>8} {'RISK':>6}\n")
        out.write("  " + "-" * 55 + "\n")
        for cloud, v in c.per_cloud().items():
            st = v["status"]
            other = st["SKIPPED"] + st["SUPPRESSED"]
            out.write(f"  {cloud:<9} {st['FAIL']:>8d} {st['PASS']:>8d} {st['MANUAL']:>8d} {other:>8d} {v.get('risk_score', 0):>6d}\n")
        out.write("  " + "-" * 55 + "\n")
        gst = g["status"]
        out.write(f"  {'TOTAL':<9} {gst['FAIL']:>8d} {gst['PASS']:>8d} {gst['MANUAL']:>8d} {gst['SKIPPED'] + gst['SUPPRESSED']:>8d} {g.get('risk_score', 0):>6d}\n\n")
        sev_line = "  Failing by severity: " + "  ".join(
            f"{lv} {g['fail_by_severity'][lv]}" for lv in COMPLIANCE_SEVERITY_ORDER)
        out.write(sev_line + f"   (weighted risk score {g.get('risk_score', 0)})\n")
        if g["failing"]:
            out.write("\n  Failing controls:\n")
            for f in g["failing"]:
                cloud = next(e["cloud"] for e in c.entries if f in e["findings"])
                out.write(f"    {cloud:<10} {str(f.get('severity')):<8} {str(f.get('id')):<8} "
                          f"{self._truncate(str(f.get('title', '')), 52):<52} {self._truncate(str(f.get('evidence', '')), 40)}\n")
        out.write("\n")
        return out.getvalue()

    def _compliance_markdown(self, c: Compliance) -> str:
        g = c.global_()
        out = io.StringIO()
        out.write("# Cross-cloud Compliance\n\n")
        out.write("| Cloud | FAIL | PASS | MANUAL | SKIPPED | SUPPRESSED | Risk |\n|---|---|---|---|---|---|---|\n")
        for cloud, v in c.per_cloud().items():
            st = v["status"]
            out.write(f"| {cloud} | {st['FAIL']} | {st['PASS']} | {st['MANUAL']} | {st['SKIPPED']} | {st['SUPPRESSED']} | {v.get('risk_score', 0)} |\n")
        gst = g["status"]
        out.write(f"| **Total** | **{gst['FAIL']}** | **{gst['PASS']}** | **{gst['MANUAL']}** | **{gst['SKIPPED']}** | **{gst['SUPPRESSED']}** | **{g.get('risk_score', 0)}** |\n\n")
        out.write("Failing by severity: " + " / ".join(
            f"{lv} {g['fail_by_severity'][lv]}" for lv in COMPLIANCE_SEVERITY_ORDER) + "\n\n")
        if g["failing"]:
            out.write("## Failing controls\n\n| Cloud | Severity | ID | Title | Evidence |\n|---|---|---|---|---|\n")
            for f in g["failing"]:
                cloud = next(e["cloud"] for e in c.entries if f in e["findings"])
                out.write(f"| {cloud} | {f.get('severity')} | {f.get('id')} | {f.get('title')} | {f.get('evidence')} |\n")
        return out.getvalue()

    def _compliance_html(self, c: Compliance) -> str:
        g = c.global_()
        html = self._doctype() + self._head("CIS Multi-Cloud — Compliance Posture")
        html += "<header class=\"hero\"><h1>Cross-Cloud Compliance Posture</h1>\n"
        html += f"<p class=\"meta\">generated {self._h(_now_utc('%Y-%m-%d %H:%M UTC'))}</p></header>\n"
        html += "<main>\n"
        html += "<section class=\"card\"><h2>Per cloud</h2>\n<table><thead><tr><th>Cloud</th><th>FAIL</th>" \
                "<th>PASS</th><th>MANUAL</th><th>SKIPPED</th><th>SUPPRESSED</th><th>Critical fails</th><th>Risk</th></tr></thead><tbody>\n"
        for cloud, v in c.per_cloud().items():
            st = v["status"]
            html += f"<tr><td><span class=\"mono\">{self._h(cloud)}</span></td><td>{st['FAIL']}</td><td>{st['PASS']}</td>" \
                    f"<td>{st['MANUAL']}</td><td>{st['SKIPPED']}</td><td>{st['SUPPRESSED']}</td>" \
                    f"<td>{v['fail_by_severity']['critical']}</td><td>{v.get('risk_score', 0)}</td></tr>\n"
        gst = g["status"]
        html += f"<tr><td><strong>Total</strong></td><td><strong>{gst['FAIL']}</strong></td><td><strong>{gst['PASS']}</strong></td>" \
                f"<td><strong>{gst['MANUAL']}</strong></td><td><strong>{gst['SKIPPED']}</strong></td>" \
                f"<td><strong>{gst['SUPPRESSED']}</strong></td><td></td><td><strong>{g.get('risk_score', 0)}</strong></td></tr>\n"
        html += "</tbody></table></section>\n"
        if g["failing"]:
            html += f"<section class=\"card\"><h2>Failing controls ({len(g['failing'])})</h2>\n" \
                    "<table><thead><tr><th>Cloud</th><th>Severity</th><th>ID</th><th>Title</th><th>Evidence</th></tr></thead><tbody>\n"
            for f in g["failing"]:
                cloud = next(e["cloud"] for e in c.entries if f in e["findings"])
                html += f"<tr><td><span class=\"mono\">{self._h(cloud)}</span></td>" \
                        f"<td><span class=\"badge sev-{f.get('severity')}\">{self._h(str(f.get('severity')))}</span></td>" \
                        f"<td><span class=\"mono\">{self._h(str(f.get('id')))}</span></td><td>{self._h(str(f.get('title')))}</td><td>{self._h(str(f.get('evidence')))}</td></tr>\n"
            html += "</tbody></table></section>\n"
        html += "</main>\n<footer>CIS multi-cloud compliance</footer>\n</body>\n</html>\n"
        return html

    # ---- hardening report --------------------------------------------------

    def hardening(self, payload: dict, selector, format_: str = "html") -> str:
        if format_ == "markdown":
            return self._hardening_markdown(payload)
        if format_ == "html":
            return self._hardening_html(payload)
        return self._hardening_text(payload)

    # ---- helpers ------------------------------------------------------------

    @staticmethod
    def _h(s) -> str:
        return _html.escape(str(s), quote=True)

    @staticmethod
    def _doctype() -> str:
        return "<!DOCTYPE html>\n"

    def _head(self, title: str) -> str:
        return (f"<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
                f"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
                f"<title>{self._h(title)}</title>\n<style>\n{STYLE}\n</style></head>\n<body>\n")

    def _summary_bar(self, t: dict) -> str:
        cells = "".join(
            f"<div class=\"stat stat-{s.lower()}\"><span class=\"num\">{t[s]}</span>"
            f"<span class=\"lbl\">{s}</span></div>"
            for s in STATUS_ORDER
        )
        return f"<div class=\"stats\">{cells}</div>\n"

    @staticmethod
    def _badge(status) -> str:
        cls = str(status).lower()
        return f"<span class=\"badge {cls}\">{_html.escape(str(status))}</span>"

    def _account_bar(self, account: Optional[dict]) -> str:
        acct = {k: v for k, v in (account or {}).items() if v is not None and str(v) != ""}
        if not acct:
            return ""
        fields = []
        if acct.get("uin"):
            fields.append(("UIN", acct["uin"]))
        if acct.get("name"):
            fields.append(("Account name", acct["name"]))
        if acct.get("app_id"):
            fields.append(("APP ID", acct["app_id"]))
        if acct.get("region"):
            fields.append(("Region", acct["region"]))
        items = "".join(
            f"<div class=\"kv\"><span class=\"k\">{self._h(k)}</span><span class=\"v\">{self._h(v)}</span></div>"
            for k, v in fields
        )
        return f"<div class=\"acct\">{items}</div>\n"

    @staticmethod
    def _filter_bar() -> str:
        buttons = "".join(
            f"<button class=\"{'filter-btn active' if status == 'ALL' else 'filter-btn'}\" "
            f"data-status=\"{status}\" onclick=\"setFilter(this)\">{label}</button>"
            for status, label in [("ALL", "All"), ("ENFORCED", "Enforced"), ("NOT", "Not enforced"),
                                  ("FAIL", "FAIL"), ("MANUAL", "MANUAL"), ("SKIPPED", "SKIPPED")]
        )
        return ("<div class=\"filters\">"
                "<input id=\"q\" type=\"search\" placeholder=\"Search by ID or title…\" oninput=\"applyFilter()\">"
                f"{buttons}</div>\n")

    @staticmethod
    def _filter_script() -> str:
        return """
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
"""

    def _capability(self, control) -> str:
        if control.manual():
            return "manual"
        caps = []
        if control.remediable():
            caps.append("remediate")
        if control.detectable():
            caps.append("detect")
        return "+".join(caps)

    @staticmethod
    def _framework_suffix(selector) -> str:
        """Human-readable suffix naming the active framework view, or '' when none."""
        key = getattr(selector, "framework", None)
        if not key:
            return ""
        return f"  — {_FRAMEWORK_TITLES.get(key, key)} view"

    # ---- list payloads ------------------------------------------------------

    def _list_payload(self, catalog, selector) -> dict:
        key = getattr(selector, "framework", None)
        return {
            "benchmark": catalog.benchmark,
            "version": catalog.version,
            "framework": _FRAMEWORK_TITLES.get(key, key) if key else "",
            "summary": selector.summary,
            "controls": [{**c.to_dict(), "capability": self._capability(c)} for c in selector.selected],
        }

    def _list_table(self, catalog, selector) -> str:
        out = io.StringIO()
        out.write(f"{catalog.benchmark} {catalog.version}{self._framework_suffix(selector)}\n\n")
        widths = [len(c.title) for c in selector.selected] or [40]
        width = max(min(max(widths), 74), 46)
        header = f"  {'ID':<6} {'PROFILE':<8} {'ASSESS':<9} {'TITLE':<{width}} {'CAPABILITY':<15} STACK"
        out.write(header + "\n")
        out.write("  " + "-" * (len(header) - 2) + "\n")
        current = None
        for c in selector.selected:
            if c.section != current:
                current = c.section
                out.write("\n")
                out.write(f"  {current} {catalog.section_title(current)}\n")
            title = self._truncate(c.title, width)
            out.write(f"  {c.id:<6} L{c.level:<7} {c.assessment:<9} {title:<{width}} "
                      f"{self._capability(c):<15} {c.stack or '-'}\n")
        out.write("\n")
        out.write(self._print_summary(selector))
        return out.getvalue()

    def _list_markdown(self, catalog, selector) -> str:
        out = io.StringIO()
        out.write(f"# {catalog.benchmark} {catalog.version}{self._framework_suffix(selector)}\n\n")
        out.write("| ID | Profile | Assessment | Title | Capability | Stack |\n|---|---|---|---|---|---|\n")
        for c in selector.selected:
            out.write(f"| {c.id} | L{c.level} | {c.assessment} | {c.title} "
                      f"| {self._capability(c)} | {c.stack or '-'} |\n")
        out.write("\n")
        s = selector.summary
        out.write(f"Selected {s['selected']}/{s['of']} - "
                  f"{s['remediable']} remediable, {s['detectable']} detectable, {s['manual']} manual.\n")
        return out.getvalue()

    def _list_html(self, catalog, selector) -> str:
        html = self._doctype() + self._head("CIS Tencent Cloud — Control List")
        html += "<header class=\"hero\"><h1>Control List</h1>\n"
        html += f"<p class=\"meta\">{self._h(catalog.benchmark)} {self._h(catalog.version)} · " \
                f"generated {self._h(_now_utc('%Y-%m-%d %H:%M UTC'))}{self._h(self._framework_suffix(selector))}</p></header>\n"
        html += "<main>\n<div class=\"card\"><table>\n<thead><tr><th>ID</th><th>Profile</th>" \
                "<th>Assessment</th><th>Title</th><th>Capability</th><th>Stack</th></tr></thead>\n"
        current = None
        for c in selector.selected:
            if c.section != current:
                current = c.section
                html += f"<tr class=\"grp\"><td colspan=\"6\">{self._h(c.section)} " \
                        f"{self._h(catalog.section_title(c.section))}</td></tr>\n"
            html += (f"<tr><td><span class=\"mono\">{self._h(c.id)}</span></td><td>L{c.level}</td><td>{self._h(c.assessment)}</td>"
                     f"<td>{self._h(c.title)}</td><td>{self._h(self._capability(c))}</td>"
                     f"<td><span class=\"mono\">{self._h(c.stack or '-')}</span></td></tr>\n")
        html += "</table>\n</div>\n</main>\n"
        html += "<footer>CIS Tencent Cloud Foundation Benchmark v1.0.0</footer>\n"
        html += "</body>\n</html>\n"
        return html

    def _print_summary(self, selector) -> str:
        s = selector.summary
        stacks = ", ".join(s["stacks"]) if s["stacks"] else "(none)"
        return (f"  selected {s['selected']}/{s['of']} controls  |  "
                f"remediable {s['remediable']}  detectable {s['detectable']}  manual {s['manual']}\n"
                f"  stacks: {stacks}\n")

    # ---- scan payloads -------------------------------------------------------

    @staticmethod
    def _scan_payload(findings: list[dict], selector) -> dict:
        tally = {s: sum(1 for f in findings if f.get("status") == s) for s in STATUS_ORDER}
        return {
            "summary": {**tally, "selected": len(selector.selected)},
            "findings": findings,
        }

    def _scan_sarif(self, findings: list[dict], selector) -> str:
        """Render findings as a SARIF 2.1.0 report (for GitHub Code Scanning).

        Only FAIL (and SUPPRESSED, surfaced as suppressed alerts) findings
        become results; PASS/MANUAL carry no alert. Rules are the selected
        controls that produced at least one finding, so the rule index stays
        small and references resolve.
        """
        catalog = _catalog_mod()
        benchmark = str(catalog.benchmark) if catalog else "CIS benchmark"
        version = str(catalog.version) if catalog else ""
        tool_name = "cis-cloud"
        sarif_version = "2.1.0"

        # Severity mapping per the SARIF spec (level): error/warning/note/none.
        sev_level = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}

        results = []
        rule_by_id = {}
        # Findings reference cloud resources, not repo files, so results carry a
        # placeholder artifact location (Code Scanning requires >=1 location).
        loc = [{
            "physicalLocation": {
                "artifactLocation": {"uri": "README.md"},
                "region": {"startLine": 1},
            }
        }]
        for f in findings:
            status = str(f.get("status", "")).upper()
            if status not in ("FAIL", "SUPPRESSED"):
                continue
            cid = str(f.get("id", ""))
            if cid not in rule_by_id:
                rule_by_id[cid] = {
                    "id": cid,
                    "name": str(f.get("title") or cid),
                    "shortDescription": {"text": str(f.get("title") or cid)},
                    "fullDescription": {"text": str(f.get("remediation") or "")},
                    "defaultConfiguration": {"level": sev_level.get(
                        str(f.get("severity")), "warning")},
                }
            results.append({
                "ruleId": cid,
                "level": sev_level.get(str(f.get("severity")), "warning"),
                "message": {"text": str(f.get("evidence") or "")},
                "kind": "fail" if status == "FAIL" else "pass",
                "locations": loc,
                "properties": {"suppressed": status == "SUPPRESSED"},
            })

        report = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": sarif_version,
            "runs": [{
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "informationUri": "https://github.com/susunola/cis-cloud",
                        "version": version,
                        "rules": list(rule_by_id.values()),
                    }
                },
                "results": results,
                "properties": {"benchmark": benchmark, "version": version},
            }],
        }
        return json.dumps(report, indent=2, ensure_ascii=False)

    def _scan_table(self, findings: list[dict]) -> str:
        out = io.StringIO()
        show_res = any(f.get("resource") for f in findings)
        res_col = " RESOURCE" if show_res else ""
        out.write("\n")
        out.write(f"  {'STATUS':<10} {'ID':<8} {'SEV':<7} {'SCORE':>5}  {'TITLE':<44}{res_col} EVIDENCE\n")
        out.write("  " + "-" * (118 + (18 if show_res else 0)) + "\n")
        for f in self._sorted(findings):
            res = f" {self._truncate(str(f.get('resource', '')), 17):<17}" if show_res else ""
            out.write(f"  {self._paint(str(f.get('status')), str(f.get('status'))):<10} "
                      f"{str(f.get('id')):<8} {str(f.get('severity')):<7} "
                      f"{str(f.get('score') or ''):>5}  "
                      f"{self._truncate(str(f.get('title', '')), 44):<44}{res} "
                      f"{self._truncate(str(f.get('evidence', '')), 38)}\n")
        out.write("\n")
        t = self._tally(findings)
        out.write("  " + "   ".join(f"{self._paint(s, s)} {t[s]}" for s in STATUS_ORDER) + "\n")
        out.write("\n")
        return out.getvalue()

    def _scan_markdown(self, findings: list[dict]) -> str:
        out = io.StringIO()
        out.write("| Status | Severity | ID | Title | Resource | Evidence | Remediation |\n|---|---|---|---|---|---|---|\n")
        for f in self._sorted(findings):
            out.write(f"| {f.get('status')} | {f.get('severity')} | {f.get('id')} | {self._md_escape(f.get('title'))} | "
                      f"{self._md_escape(f.get('resource'))} | {self._md_escape(f.get('evidence'))} | "
                      f"{self._md_escape(f.get('remediation') or '')} |\n")
        out.write("\n")
        t = self._tally(findings)
        out.write(" / ".join(f"**{s}** {t[s]}" for s in STATUS_ORDER) + "\n")
        return out.getvalue()

    @staticmethod
    def _md_escape(value) -> str:
        return str(value or "").replace("|", "\\|")

    @staticmethod
    def _fix_snippet(remediation) -> str:
        """Inline HTML 'fix:' hint for a finding's remediation, or ''."""
        if not remediation:
            return ""
        return "<br><span class=\"mono\">fix:</span> " + _html.escape(str(remediation))

    def _scan_csv(self, findings: list[dict]) -> str:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["status", "severity", "id", "title", "resource", "evidence"])
        for f in self._sorted(findings):
            writer.writerow([f.get("status"), f.get("severity"), f.get("id"),
                             f.get("title"), f.get("resource"), f.get("evidence")])
        return buf.getvalue()

    def _scan_junit(self, findings: list[dict]) -> str:
        failed = [f for f in findings if f.get("status") == "FAIL"]
        out = io.StringIO()
        out.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
        out.write(f"<testsuite name=\"cis-scan\" tests=\"{len(findings)}\" failures=\"{len(failed)}\">\n")
        for f in self._sorted(findings):
            out.write(f"  <testcase name=\"{self._h(f.get('id'))} {self._h(str(f.get('title')))}\" "
                      f"classname=\"{self._h(str(f.get('severity') or 'unknown'))}\">\n")
            if f.get("status") == "FAIL":
                out.write(f"    <failure message=\"{self._h(str(f.get('evidence')))}\" />\n")
            elif f.get("status") == "SUPPRESSED":
                out.write("    <skipped message=\"suppressed\" />\n")
            out.write("  </testcase>\n")
        out.write("</testsuite>\n")
        return out.getvalue()

    def _scan_html(self, findings: list[dict], selector, account: Optional[dict] = None) -> str:
        t = self._tally(findings)
        sections: dict[str, list[dict]] = {}
        for f in findings:
            sections.setdefault(str(f.get("id", "")).split(".")[0], []).append(f)
        catalog = _catalog_mod()
        html = self._doctype() + self._head("CIS Tencent Cloud — Scan Report")
        html += "<header class=\"hero\"><h1>Scan Report</h1>\n"
        html += f"<p class=\"meta\">{self._h(catalog.benchmark)} {self._h(catalog.version)} · " \
                f"generated {self._h(_now_utc('%Y-%m-%d %H:%M UTC'))}</p>\n"
        html += self._account_bar(account)
        html += "</header>\n"
        html += self._summary_bar(t)
        html += self._filter_bar()
        html += "<main>\n"
        for sec in sorted(sections, key=lambda s: (int(s) if s.isdigit() else s)):
            rows = sections[sec]
            html += f"<section class=\"card\"><h2>{self._h(sec)} {self._h(catalog.section_title(sec))}</h2>\n"
            html += "<table><thead><tr><th>Status</th><th>Severity</th><th>ID</th><th>Title</th>" \
                    "<th>Resource</th><th>Evidence</th></tr></thead><tbody>\n"
            for f in self._sorted(rows):
                s = self._h(str(f.get("status")))
                search = self._h(f"{f.get('id')} {f.get('title')}").lower()
                rem = f.get("remediation") or ""
                html += (f"<tr data-status=\"{s}\" data-search=\"{search}\">"
                         f"<td>{self._badge(f.get('status'))}</td>"
                         f"<td><span class=\"badge sev-{f.get('severity')}\">{self._h(str(f.get('severity')))}</span></td>"
                         f"<td><span class=\"mono\">{self._h(str(f.get('id')))}</span></td>"
                         f"<td>{self._h(str(f.get('title')))}</td>"
                         f"<td><span class=\"mono\">{self._h(str(f.get('resource') or ''))}</span></td>"
                         f"<td>{self._h(str(f.get('evidence')))}"
                         f"{self._fix_snippet(rem)}</td></tr>\n")
            html += "</tbody></table></section>\n"
        html += "</main>\n"
        html += self._filter_script()
        html += "<footer>CIS Tencent Cloud Foundation Benchmark v1.0.0</footer>\n"
        html += "</body>\n</html>\n"
        return html

    # ---- hardening report ----------------------------------------------------

    def _hardening_html(self, payload: dict) -> str:
        s = payload.get("summary") or {}
        html = self._doctype() + self._head("CIS Tencent Cloud — Hardening Report")
        html += "<header class=\"hero\"><h1>Hardening Report</h1>\n"
        html += f"<p class=\"meta\">action: {self._h(payload.get('label'))} · " \
                f"generated {self._h(payload.get('generated_at'))}</p>\n"
        html += self._account_bar(payload.get("account"))
        if s:
            html += (f"<p class=\"meta\">Selection: {s['selected']}/{s['of']} controls "
                     f"(remediable {s['remediable']}, detectable {s['detectable']}, "
                     f"manual {s['manual']})</p>\n")
        html += "</header>\n<main>\n"
        html += "<section class=\"card\"><h2>Stacks</h2>\n<table><thead><tr><th>Stack</th>" \
                "<th>Controls</th><th>Result</th></tr></thead><tbody>\n"
        for st in payload.get("stacks", []):
            html += f"<tr><td><span class=\"mono\">{self._h(st['name'])}</span></td>" \
                    f"<td><span class=\"mono\">{self._h(', '.join(st['ids']))}</span></td>" \
                    f"<td>{self._badge(st['status'])}</td></tr>\n"
        html += "</tbody></table></section>\n"
        gaps = payload.get("gaps") or []
        if gaps:
            html += f"<section class=\"card\"><h2>Not enforced by Terraform ({len(gaps)})</h2>\n" \
                    "<table><thead><tr><th>ID</th><th>Title</th></tr></thead><tbody>\n"
            for g in gaps:
                html += f"<tr><td><span class=\"mono\">{self._h(str(g['id']))}</span></td><td>{self._h(str(g['title']))}</td></tr>\n"
            html += "</tbody></table></section>\n"
        html += "</main>\n"
        html += "<footer>CIS Tencent Cloud Foundation Benchmark v1.0.0</footer>\n"
        html += "</body>\n</html>\n"
        return html

    def _hardening_markdown(self, payload: dict) -> str:
        out = io.StringIO()
        out.write(f"# Hardening Report ({payload.get('label')})\n\n")
        out.write(f"_generated {payload.get('generated_at')}_\n\n")
        out.write("## Stacks\n\n| Stack | Controls | Result |\n|---|---|---|\n")
        for st in payload.get("stacks", []):
            out.write(f"| {st['name']} | {', '.join(st['ids'])} | {st['status']} |\n")
        gaps = payload.get("gaps") or []
        if gaps:
            out.write(f"\n## Not enforced by Terraform ({len(gaps)})\n\n")
            for g in gaps:
                out.write(f"- {g['id']} {g['title']}\n")
        return out.getvalue()

    def _hardening_text(self, payload: dict) -> str:
        out = io.StringIO()
        out.write(f"Hardening Report ({payload.get('label')}) — {payload.get('generated_at')}\n\n")
        out.write("Stacks:\n")
        for st in payload.get("stacks", []):
            out.write(f"  {st['name']} [{st['status']}]  {', '.join(st['ids'])}\n")
        gaps = payload.get("gaps") or []
        if gaps:
            out.write(f"\nNot enforced by Terraform ({len(gaps)}):\n")
            for g in gaps:
                out.write(f"  {g['id']} {g['title']}\n")
        return out.getvalue()

    # ---- shared ---------------------------------------------------------------

    def _paint(self, text: str, status: str) -> str:
        if self.color and status in COLORS:
            return f"{COLORS[status]}{text}{RESET}"
        return text

    @staticmethod
    def _sorted(findings: list[dict]) -> list[dict]:
        def key(f):
            status_idx = STATUS_ORDER.index(f.get("status")) if f.get("status") in STATUS_ORDER else 99
            parts = [int(p) if p.isdigit() else p for p in str(f.get("id", "")).split(".")]
            return (status_idx, parts)
        return sorted(findings, key=key)

    @staticmethod
    def _tally(findings: list[dict]) -> dict:
        return {s: sum(1 for f in findings if f.get("status") == s) for s in STATUS_ORDER}

    @staticmethod
    def _truncate(text: str, width: int) -> str:
        return f"{text[:width - 1]}~" if len(text) > width else text
