"""Drives `terraform` on behalf of cis-cloud.

Stacks live under stacks/<name>/ as self-contained Terraform root modules.
Each is invoked individually so output streams in order and failures are
attributable.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import time
from typing import Any, Callable, Optional, TextIO

from . import (
    AUDIT_STACK,
    Error,
    get_catalog as _catalog_mod,
    cloud as _cloud,
    controls_for_audit,
    controls_for_stack,
    get_root,
    hardening_stacks,
    stack_dir,
)
from .reporter import Reporter
from .severity import of as severity_of
from .suppress import Suppressions

EXIT_OK = 0
EXIT_FINDING = 1
EXIT_ERROR = 2


class Runner:
    def __init__(self, selector, options: Optional[dict] = None,
                 io: Optional[TextIO] = None, err: Optional[TextIO] = None):
        self.selector = selector
        self.options = options or {}
        self.io = io or sys.stdout
        self.err = err or sys.stderr
        self.reporter = Reporter(io=io, err=err, color=self.options.get("color"))

    # ---- actions -------------------------------------------------------------

    def list(self) -> int:
        body = self.reporter.list(_catalog_mod(), self.selector,
                                  format_=self.options.get("format", "table"))
        self._write_output(body)
        return EXIT_OK

    def scan(self) -> int:
        if not self.selector.detectable:
            self._warn_no_detectable()
            return self._report(
                self._with_severity(self._manual_findings()), EXIT_OK,
                account=self._build_account())

        self._say(f"Scanning {len(self.selector.detectable)} control(s) via the `audit` stack (read-only).")

        if self.options.get("dry_run"):
            self._say("Will scan:")
            self._say(f"  terraform -chdir={self._rel_stack_dir(AUDIT_STACK)} apply -auto-approve # "
                      f"{', '.join(controls_for_audit())}")
            return EXIT_OK

        init_code = self._terraform_init(AUDIT_STACK)
        if init_code != 0:
            return EXIT_ERROR

        code = self._terraform_apply(AUDIT_STACK, controls_for_audit(), action="scan")
        if code != 0:
            return EXIT_ERROR

        account = self._build_account(terraform=True)
        findings = self._with_severity(self._read_findings() + self._manual_findings())
        findings = Suppressions.load().apply(findings, _cloud())
        code = EXIT_FINDING if any(f.get("status") == "FAIL" for f in findings) else EXIT_OK
        self._push(findings, account)
        return self._report(findings, code, account=account)

    def _push(self, findings: list[dict], account: Optional[dict]) -> None:
        """Write a timestamped JSON copy of the scan to options['push'] (a dir)."""
        push = self.options.get("push")
        if not push:
            return
        import json as _json
        from pathlib import Path as _Path
        import time as _time

        d = _Path(push)
        d.mkdir(parents=True, exist_ok=True)
        acct = (account or {}).get("name") or os.environ.get("CIS_ACCOUNT") or _cloud()
        safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in str(acct))
        ts = _time.strftime("%Y%m%d-%H%M%S", _time.gmtime())
        path = d / f"{_cloud()}-{safe}-{ts}.json"
        payload = {
            "cloud": _cloud(),
            "account": account or {},
            "summary": self.selector.summary,
            "findings": findings,
        }
        path.write_text(_json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        self._say(f"Pushed scan result to {path}")

    def check(self, findings: list[dict]) -> int:
        body = self.reporter.scan(findings, self.selector,
                                  format_=self.options.get("format", "table"))
        self._write_output(body)
        return EXIT_FINDING if any(f.get("status") == "FAIL" for f in findings) else EXIT_OK

    def compliance(self, compliance) -> int:
        body = self.reporter.compliance(compliance, format_=self.options.get("format", "table"))
        self._write_output(body)
        return EXIT_OK

    def diff(self, base_path: str, cur_path: str) -> int:
        from .diff import diff as compute_diff, load_scan, render_diff

        try:
            base = load_scan(base_path)
            cur = load_scan(cur_path)
        except (FileNotFoundError, ValueError) as e:
            return self._abort_with(str(e))
        base["_path"] = base_path
        cur["_path"] = cur_path
        d = compute_diff(base, cur)
        body = render_diff(d, format_=self.options.get("format", "table"))
        self.io.write(body + "\n")
        self._write_output(body)
        return EXIT_FINDING if d["summary"]["new"] else EXIT_OK

    def check_drift(self, base_path: str, current_path: Optional[str] = None) -> int:
        """Compare a baseline scan against a fresh scan and flag regressions.

        With `current_path` set, compare two files (offline). Otherwise run a
        live `scan` (format json), capture it, and compare against the baseline.
        Exits `EXIT_FINDING` when there are new regressions, else OK.
        """
        from .drift import drift as compute_drift, load_scan, render_drift

        try:
            base = load_scan(base_path)
        except (FileNotFoundError, ValueError) as e:
            return self._abort_with(str(e))
        base["_path"] = base_path

        if current_path:
            try:
                cur = load_scan(current_path)
            except (FileNotFoundError, ValueError) as e:
                return self._abort_with(str(e))
            cur["_path"] = current_path
        else:
            cur = self._scan_to_json()
            if cur is None:
                return EXIT_ERROR

        d = compute_drift(base, cur)
        body = render_drift(d, format_=self.options.get("format", "table"))
        self.io.write(body + "\n")
        self._write_output(body)
        return EXIT_FINDING if d["summary"]["regressions"] else EXIT_OK

    def _scan_to_json(self) -> Optional[dict]:
        """Run a live scan and return its JSON payload, or None on failure."""
        import io as _io
        saved_io = self.io
        saved_reporter_io = self.reporter.io
        saved_fmt = self.options.get("format")
        self.options["format"] = "json"
        buf = _io.StringIO()
        self.io = buf
        self.reporter.io = buf
        try:
            code = self.scan()
        finally:
            self.options["format"] = saved_fmt
            self.io = saved_io
            self.reporter.io = saved_reporter_io
        if code == EXIT_ERROR:
            return None
        try:
            payload = json.loads(buf.getvalue())
        except json.JSONDecodeError:
            return None
        if not isinstance(payload, dict):
            return None
        # Give the current payload a stable path label for display.
        payload["_path"] = "live scan"
        return payload

    def batch(self, accounts: list[str], out_dir: str) -> int:
        """Scan a list of accounts and aggregate the results.

        Each account is scanned by re-invoking the CLI in a child process with
        CIS_ACCOUNT=<name> set, so provider credentials/profile selection can
        differ per account. Per-account JSON is written to out_dir and then
        rolled up into a compliance view (reusing compliance.py).
        """
        from pathlib import Path as _Path
        from .compliance import Compliance

        d = _Path(out_dir)
        d.mkdir(parents=True, exist_ok=True)
        cmd = [sys.executable, "-m", "cis_cloud"]
        # Reproduce the current cloud + filter selection in the child.
        base_env = dict(os.environ)
        cmd += ["--cloud", _cloud()]
        child_argv = cmd + ["scan", "--format", "json"]
        # TODO: forward filter env through to_env for parity with the parent.

        any_fail = False
        for acct in accounts:
            env = dict(base_env)
            env["CIS_ACCOUNT"] = acct
            self._say(f"Scanning account {acct} ...")
            proc = subprocess.run(child_argv, capture_output=True, text=True, env=env)
            if proc.returncode != 0 and proc.returncode != EXIT_FINDING:
                self.err.write(f"  account {acct} failed (exit {proc.returncode}): {proc.stderr.strip()}\n")
                continue
            path = d / f"{acct}.json"
            path.write_text(proc.stdout, encoding="utf-8")
            self._say(f"  wrote {path}")
            if proc.returncode == EXIT_FINDING:
                any_fail = True

        compliance = Compliance.load_dir(out_dir)
        body = self.reporter.compliance(compliance, format_=self.options.get("format", "table"))
        self._write_output(body)
        return EXIT_FINDING if any_fail else EXIT_OK

    def plan(self) -> int:
        # Left-shift: when --plan-check is set (with --tf), run the static
        # tfcheck scan first and block if any control FAILs, so violations are
        # caught before the plan/apply cycle.
        tf_dir = self.options.get("tf_dir")
        if self.options.get("plan_check") and tf_dir:
            code = self._plan_check(tf_dir)
            if code != EXIT_OK:
                return code
        return self._run_hardening("plan", lambda stack, ids: ["plan", "-var", f"enabled_controls={shlex.quote(json.dumps(ids))}"])

    def apply(self) -> int:
        return self._run_hardening("apply", lambda stack, ids: ["apply", "-auto-approve", "-var", f"enabled_controls={shlex.quote(json.dumps(ids))}"])

    def destroy(self, stack: str) -> int:
        if stack not in hardening_stacks():
            return self._abort_with(f"{stack!r} is not a hardening stack ({', '.join(hardening_stacks())})")
        return self._terraform(["destroy", "-auto-approve"], stack, action="apply")

    def _plan_check(self, tf_dir: str) -> int:
        """Static pre-plan gate: run tfcheck and block on FAIL findings."""
        from pathlib import Path as _Path
        from .tfcheck import scan as tfcheck_scan

        if not _Path(tf_dir).is_dir():
            return self._abort_with(f"no such directory for --plan-check: {tf_dir}")
        self._say(f"Static check before plan: {tf_dir}")
        findings = [f.to_dict() for f in tfcheck_scan(tf_dir, _cloud())]
        fails = [f for f in findings if f.get("status") == "FAIL"]
        if fails:
            self.reporter.scan(findings, self.selector, format_="table")
            self._say(f"Blocking plan: {len(fails)} control(s) FAIL in the Terraform source.")
            return EXIT_FINDING
        self._say(f"Static check clean ({len(findings)} rule(s) assessed).")
        return EXIT_OK

    # ---- hardening -------------------------------------------------------------

    def _run_hardening(self, label: str, build: Callable) -> int:
        stacks = self.selector.stacks_for_apply
        if not stacks:
            self._warn_no_remediable()
            return EXIT_OK

        self._print_plan_preamble(label, stacks)
        results = [
            {"name": stack, "ids": controls_for_stack(stack), "status": "planned"}
            for stack in stacks
        ]

        code = EXIT_OK if self.options.get("dry_run") else self._run_stacks(label, results, build)

        self._report_gaps()
        if self.options.get("report"):
            self._emit_hardening_report(label, results)
        return code

    def _run_stacks(self, label: str, results: list[dict], build: Callable) -> int:
        for r in results:
            if not r["ids"]:
                continue
            self._say("")
            self._say("=" * 70)
            self._say(f"{label} {r['name']}  ({len(r['ids'])} control(s): {', '.join(r['ids'])})")
            self._say("=" * 70)

            init_code = self._terraform_init(r["name"])
            if init_code != 0:
                r["status"] = "fail"
                self._say(f"  stack {r['name']} init failed (exit {init_code}); stopping.")
                return EXIT_ERROR

            code = self._terraform(build(r["name"], r["ids"]), r["name"], action="apply")
            if code == 0:
                r["status"] = "ok"
            else:
                r["status"] = "fail"
                self._say(f"  stack {r['name']} failed (exit {code}); stopping.")
                return EXIT_ERROR
        return EXIT_OK

    def _print_plan_preamble(self, label: str, stacks: list[str]) -> None:
        s = self.selector.summary
        self._say(f"Selection: {s['selected']}/{s['of']} controls  "
                  f"(remediable {s['remediable']}, detectable {s['detectable']}, manual {s['manual']})")
        self._say(f"Will {label}:")
        for stack in stacks:
            ids = controls_for_stack(stack)
            self._say(f"  terraform -chdir={self._rel_stack_dir(stack):<15} {label:<5} # {', '.join(ids)}")

    def _report_gaps(self) -> None:
        gaps = self.selector.not_remediable
        if not gaps:
            return
        self._say("")
        self._say(f"Not enforced by Terraform ({len(gaps)}) - handle these out of band:")
        for c in gaps:
            self._say(f"  {c.id:<6} {c.title}")

    def _warn_no_detectable(self) -> None:
        self._say("No selected control is machine-assessable by the provider.")
        self._say(f"Selected: {len(self.selector.selected)}. Use `cis-cloud list` to see why.")

    def _warn_no_remediable(self) -> None:
        self._say("No selected control is enforceable by Terraform - nothing to apply.")
        self._report_gaps()

    def _report(self, findings: list[dict], code: int, account: Optional[dict] = None) -> int:
        body = self.reporter.scan(findings, self.selector,
                                  format_=self.options.get("format", "table"), account=account)
        self._write_output(body)
        return code

    def _write_output(self, body: str) -> None:
        if not self.options.get("output"):
            return
        try:
            with open(self.options["output"], "w", encoding="utf-8") as fh:
                fh.write(body)
            if not self._json():
                self._say(f"Report written to {self.options['output']}")
        except OSError as e:
            self._abort_with(f"could not write report to {self.options['output']}: {e}")

    def _emit_hardening_report(self, label: str, results: list[dict]) -> None:
        path = self.options["report"] if isinstance(self.options["report"], str) else self._default_report_path()
        payload = {
            "label": label,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "account": self._build_account(),
            "summary": self.selector.summary,
            "stacks": results,
            "gaps": [{"id": c.id, "title": c.title} for c in self.selector.not_remediable],
        }
        body = self.reporter.hardening(payload, self.selector, format_="html")
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(body)
            self._say(f"Hardening report written to {path}")
        except OSError as e:
            self._abort_with(f"could not write report to {path}: {e}")

    @staticmethod
    def _default_report_path() -> str:
        return f"cis-hardening-{time.strftime('%Y%m%d-%H%M%S', time.gmtime())}.html"

    def _build_account(self, terraform: bool = False) -> dict:
        acct = {k: v for k, v in {
            "uin": os.environ.get("CIS_UIN"),
            "name": os.environ.get("CIS_ACCOUNT_NAME"),
            "app_id": os.environ.get("CIS_APP_ID"),
            "region": os.environ.get("TENCENTCLOUD_REGION"),
        }.items() if v}
        if terraform and not self.options.get("dry_run"):
            for k, v in (self._read_account() or {}).items():
                if v is not None and str(v) != "":
                    acct[k] = v
        return acct

    def _read_account(self) -> Optional[dict]:
        dir_ = stack_dir(AUDIT_STACK)
        try:
            proc = subprocess.run(["terraform", "output", "-json", "cis_account"],
                                  capture_output=True, text=True, cwd=str(dir_))
            if proc.returncode != 0:
                return None
            parsed = json.loads(proc.stdout)
            val = parsed.get("value")
            return {str(k): v for k, v in val.items()} if isinstance(val, dict) else None
        except (OSError, json.JSONDecodeError):
            return None

    def _manual_findings(self) -> list[dict]:
        out = []
        for c in self.selector.not_detectable:
            if c.remediable():
                out.append({
                    "id": c.id, "title": c.title, "status": "SKIPPED",
                    "evidence": "enforced by `cis-cloud apply`, not readable",
                })
            else:
                out.append({
                    "id": c.id, "title": c.title, "status": "MANUAL",
                    "evidence": "verify in console",
                })
        return out

    def _with_severity(self, findings: list[dict]) -> list[dict]:
        from . import remediation as _remediation
        from .severity import score as _score
        by_id = {c.id: c for c in self.selector.catalog.controls}
        cloud = _cloud()
        out = []
        for f in findings:
            ctl = by_id.get(str(f.get("id")))
            sev = severity_of(ctl.tags if ctl else [])
            out.append({
                **f,
                "severity": sev,
                "score": _score(sev),
                "remediation": _remediation.for_control(cloud, ctl) if ctl else (f.get("remediation") or ""),
            })
        return out

    # ---- terraform plumbing -----------------------------------------------------

    def _rel_stack_dir(self, stack: str) -> str:
        return str(stack_dir(stack)).replace(str(get_root()) + "/", "")

    def _terraform_init(self, stack: str) -> int:
        dir_ = stack_dir(stack)
        self._say(f"  terraform -chdir={self._rel_stack_dir(stack)} init")
        if self.options.get("dry_run"):
            return EXIT_OK
        proc = subprocess.run(["terraform", "init", "-input=false"],
                              capture_output=True, text=True, cwd=str(dir_))
        if proc.returncode != 0:
            first = (proc.stderr.strip().splitlines() or [""])[0]
            self._say(f"  init warning: {first}")
        return proc.returncode

    def _terraform_apply(self, stack: str, control_ids: list[str], action: str) -> int:
        ids_json = shlex.quote(json.dumps(control_ids))
        return self._terraform(["apply", "-auto-approve", "-var", f"enabled_controls={ids_json}"],
                               stack, action=action)

    def _terraform(self, args: list[str], stack: str, action: str) -> int:
        dir_ = stack_dir(stack)
        cmd = ["terraform", f"-chdir={dir_}"] + list(args)
        if self.options.get("verbose"):
            self._say("=> " + " ".join(cmd))
        if self.options.get("dry_run"):
            return EXIT_OK
        proc = subprocess.run(cmd)
        return proc.returncode

    # ---- reading findings back ----------------------------------------------------

    def _read_findings(self) -> list[dict]:
        dir_ = stack_dir(AUDIT_STACK)
        try:
            proc = subprocess.run(["terraform", "output", "-json"],
                                  capture_output=True, text=True, cwd=str(dir_))
        except OSError as e:
            raise Error(f"terraform output failed: {e}")
        if proc.returncode != 0:
            raise Error(f"terraform output failed: {proc.stderr.strip()}")
        try:
            parsed = json.loads(proc.stdout)
        except json.JSONDecodeError as e:
            raise Error(f"could not parse terraform output: {e}")
        node = parsed.get("cis_findings")
        if node is None:
            raise Error("the audit stack did not emit a cis_findings output")
        return self._normalize(node.get("value"))

    def _normalize(self, value) -> list[dict]:
        from .schema import normalize_finding as _normalize_finding
        if isinstance(value, dict):
            rows = [{**(v if isinstance(v, dict) else {"status": str(v)}), "id": cid}
                    for cid, v in value.items()]
        elif isinstance(value, list):
            rows = [v if isinstance(v, dict) else {"status": str(v)} for v in value]
        else:
            rows = []
        out = []
        for row in rows:
            control = _catalog_mod()[str(row.get("id", ""))]
            detail = row.get("evidence_detail")
            resource = row.get("resource") or (
                detail[0].get("resource") if isinstance(detail, list) and detail else "") or ""
            out.append(_normalize_finding({
                "id": str(row.get("id", "")),
                "title": row.get("title") or (control.title if control else "(unknown control)"),
                "status": str(row.get("status", "")).upper(),
                "evidence": str(row.get("evidence", "")),
                "evidence_detail": detail,
                "resource": resource,
            }, control=control))
        return out

    # ---- output helpers -----------------------------------------------------------

    def _say(self, msg: str) -> None:
        (self.err if self._json() else self.io).write(msg + "\n")

    def _json(self) -> bool:
        return self.options.get("format") == "json"

    def _abort_with(self, msg: str) -> int:
        self.err.write(f"error: {msg}\n")
        return EXIT_ERROR
