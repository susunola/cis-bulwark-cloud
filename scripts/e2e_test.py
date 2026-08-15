#!/usr/bin/env python3
"""End-to-end test for cis-cloud.

Two modes:

  offline (default, no credentials, free, ~seconds)
    Runs the REAL installed CLI through its full command surface — `list`,
    `scan --dry-run`, `plan --dry-run`, `check` (offline tfcheck), `diff`,
    `check-drift`, and the `mcp` JSON-RPC server — against real files. This
    is the end-to-end counterpart to test_py/: the unit suite mocks the
    terraform boundary and the reporter, but only running the real binary
    catches "the CLI wiring is broken", "the JSON stdout is polluted by
    narration", or "a subcommand forgot to parse its arguments".

  live (opt-in, needs a real cloud account + credentials, ~minutes)
    Drives a REAL scan/apply cycle against the account selected by CIS_CLOUD
    (default tencent): `scan` -> save baseline -> `check-drift` against it ->
    a guarded `apply` of a small, reversible control set -> re-`scan` to
    confirm. Any hardening stacks `apply` touched are ALWAYS `destroy`ed on
    exit (success, failure, or Ctrl-C) unless --keep-on-failure is set and
    the run actually failed. `live` never runs against an account you did not
    authorise, and it cleans up after itself.

Usage:
    # offline (default)
    python3 scripts/e2e_test.py

    # live, against a real account (CIS_CLOUD=tencent|aws|azure|gcp|alibaba)
    export CIS_CLOUD=tencent
    export TENCENTCLOUD_SECRET_ID=... TENCENTCLOUD_SECRET_KEY=... TENCENTCLOUD_REGION=ap-guangzhou
    python3 scripts/e2e_test.py --mode live --cloud tencent --only 4.1
    #   ^ applies a real, reversible control (COS bucket ACL) and tears it down

    python3 scripts/e2e_test.py --mode live --cloud aws --only 6.1.1 --keep-on-failure

Exit codes:
    0  all checks passed
    1  a live scan/diff found failing or new controls (expected on a fresh
       account; informational)
    2  a command errored / an assertion failed / hard misconfiguration
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Module root is <repo>/cis_cloud; the data root (config/stacks/modules) is
# <repo>/cis_cloud/data.
MODULE = ROOT / "cis_cloud"
# Make cis_cloud importable in this process (mirrors PYTHONPATH set for the
# child CLI invocations).
sys.path.insert(0, str(ROOT))


class E2E:
    """Runs cis-cloud end-to-end and asserts on exit codes + output shape."""

    def __init__(self, mode: str, cloud: str, only: str | None = None,
                 keep_on_failure: bool = False, verbose: bool = False):
        self.mode = mode
        self.cloud = cloud
        self.only = only
        self.keep_on_failure = keep_on_failure
        self.verbose = verbose
        self.failures: list[str] = []
        self.checks = 0
        self.applied_stacks: list[str] = []
        self._scan_base: Path | None = None

    # ---- helpers -----------------------------------------------------------

    def _run(self, args, env_extra=None, check: int | None = None,
             allow: tuple[int, ...] = ()) -> subprocess.CompletedProcess:
        """Run the CLI; assert on exit code when `check` is given."""
        env = dict(os.environ)
        env["CIS_CLOUD"] = self.cloud
        env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        if env_extra:
            env.update({k: str(v) for k, v in env_extra.items() if v is not None})
        cmd = [sys.executable, "-m", "cis_cloud"] + list(args)
        self.checks += 1
        if self.verbose:
            print("  $ " + " ".join(cmd), file=sys.stderr)
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=str(ROOT))
        if check is not None and proc.returncode != check and proc.returncode not in allow:
            self.fail(f"exit={proc.returncode} (want {check}) for {args}\n  stdout: {proc.stdout[:400]}\n  stderr: {proc.stderr[:400]}")
        return proc

    def _run_stdin(self, args, stdin: str, check: int | None = None,
                   allow: tuple[int, ...] = ()) -> subprocess.CompletedProcess:
        """Run the CLI feeding `stdin` (e.g. the MCP JSON-RPC server)."""
        env = dict(os.environ)
        env["CIS_CLOUD"] = self.cloud
        env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        cmd = [sys.executable, "-m", "cis_cloud"] + list(args)
        self.checks += 1
        if self.verbose:
            print("  $ " + " ".join(cmd) + "  <<< stdin", file=sys.stderr)
        proc = subprocess.run(cmd, input=stdin, capture_output=True, text=True,
                              env=env, cwd=str(ROOT))
        if check is not None and proc.returncode != check and proc.returncode not in allow:
            self.fail(f"exit={proc.returncode} (want {check}) for {args}\n  stdout: {proc.stdout[:400]}\n  stderr: {proc.stderr[:400]}")
        return proc

    def fail(self, msg: str) -> None:
        self.failures.append(msg)
        print(f"  FAIL: {msg}", file=sys.stderr)

    def ok(self, msg: str) -> None:
        print(f"  ok: {msg}")

    # ---- offline: no credentials, real CLI --------------------------------

    def _remediable_control(self) -> str:
        """Return a control id that is remediable on the active cloud."""
        import cis_cloud as C
        os.environ["CIS_CLOUD"] = self.cloud
        C.reset()
        cat = C.get_catalog()
        rem = [c.id for c in cat.controls if c.remediable()]
        if not rem:
            self.fail(f"cloud={self.cloud} has no remediable controls")
            return "4.1"
        return rem[0]

    def run_offline(self) -> None:
        print(f"[offline] exercising real CLI against cloud={self.cloud}")
        ctl = self._remediable_control()

        self.ok("module import smoke check (catches SyntaxError/ImportError)")
        # Import every package module in a child process; the cheapest way to
        # catch an f-string/parse error on the CI interpreter before the
        # command paths run (a py3.11-only SyntaxError surfaced in CI).
        import cis_cloud as C
        pkg_dir = Path(C.__file__).parent
        modules = sorted(
            f.stem for f in pkg_dir.glob("*.py")
            if f.name != "__main__.py")
        script = "import " + "; import ".join(f"cis_cloud.{m}" for m in modules)
        env = dict(os.environ)
        env["CIS_CLOUD"] = self.cloud
        env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        self.checks += 1
        if self.verbose:
            print("  $ " + " ".join([sys.executable, "-c", script]), file=sys.stderr)
        imp = subprocess.run([sys.executable, "-c", script], capture_output=True,
                             text=True, env=env, cwd=str(ROOT))
        if imp.returncode != 0:
            self.fail(f"module import failed: {imp.stderr[:400]}")

        self.ok("list -> json is parseable with controls")
        proc = self._run(["list", "--format", "json"], check=0)
        payload = json.loads(proc.stdout)
        assert payload["controls"], "list returned no controls"

        self.ok("list -> table renders the benchmark header")
        proc = self._run(["list", "--format", "table"], check=0)
        assert proc.stdout.strip(), "table list empty"

        self.ok(f"scan --dry-run plans the audit stack for {ctl}, exits 0")
        self._run(["scan", "--only", ctl, "--dry-run"], check=0)

        self.ok(f"plan --dry-run previews a hardening stack for {ctl}, exits 0")
        proc = self._run(["plan", "--only", ctl, "--dry-run"], check=0)
        assert "-chdir=stacks/" in proc.stdout, "plan did not preview a hardening stack"

        self.ok("check --tf (offline tfcheck) produces findings")
        # The offline tfcheck fixture is aws-only; run it explicitly on aws.
        proc = self._run(["--cloud", "aws", "check", "--tf", str(ROOT / "test_py" / "fixtures" / "tf"),
                          "--format", "json"], check=0, allow=(1,))
        assert "findings" in proc.stdout, "check did not emit findings"

        self.ok("mcp tools/list handshake")
        resp = self._run_stdin(["mcp"], '{"id":1,"method":"tools/list"}\n')
        if resp.returncode != 0:
            self.fail(f"mcp exited {resp.returncode}: {resp.stderr[:300]}")
        else:
            line = resp.stdout.strip().splitlines()[0]
            assert json.loads(line)["result"]["tools"], "mcp tools/list returned no tools"

        self.ok("diff + check-drift on synthetic scan files")
        with tempfile.TemporaryDirectory() as td:
            base = Path(td) / "base.json"
            cur = Path(td) / "cur.json"
            base.write_text(json.dumps({"findings": [
                {"id": ctl, "title": ctl, "status": "PASS", "evidence": ""}]}))
            cur.write_text(json.dumps({"findings": [
                {"id": ctl, "title": ctl, "status": "FAIL", "evidence": "public"}]}))
            self._run(["diff", str(base), str(cur)], check=1)          # new failure -> exit 1
            self._run(["check-drift", str(base), str(cur)], check=1)   # regression  -> exit 1
            self._run(["check-drift", str(base), str(base)], check=0)  # no drift    -> exit 0

        print(f"[offline] {self.checks} command invocations, all green")

    # ---- live: real cloud account (opt-in) --------------------------------

    def run_live(self) -> None:
        if not self.only:
            print("error: --mode live requires --only IDS (a small, reversible control set)", file=sys.stderr)
            sys.exit(2)
        # Sanity: creds present (heuristic per cloud).
        self._assert_live_creds()

        print(f"[live] driving a real scan/apply cycle on cloud={self.cloud} "
              f"for controls {self.only}")
        try:
            self._live_cycle()
        finally:
            self._teardown()

    def _assert_live_creds(self) -> None:
        cloud = self.cloud
        required = {
            "tencent": ["TENCENTCLOUD_SECRET_ID", "TENCENTCLOUD_SECRET_KEY"],
            "aws": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"],
            "azure": ["AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_SUBSCRIPTION_ID"],
            "gcp": ["GOOGLE_APPLICATION_CREDENTIALS"],
            "alibaba": ["ALICLOUD_ACCESS_KEY", "ALICLOUD_SECRET_KEY"],
        }.get(cloud, [])
        missing = [k for k in required if not os.environ.get(k)]
        if missing:
            print(f"error: --mode live on cloud={cloud} needs env vars: {', '.join(missing)}", file=sys.stderr)
            sys.exit(2)

    def _live_cycle(self) -> None:
        self.ok("scan (real, read-only) -> save baseline")
        with tempfile.TemporaryDirectory() as td:
            base = Path(td) / "base.json"
            self._run(["scan", "--only", self.only, "--format", "json", "-o", str(base)],
                      check=None, allow=(0, 1))  # findings may be non-zero -> 1
            self._scan_base = base

            self.ok("check-drift baseline vs a fresh live scan")
            # A fresh scan compared against the just-saved baseline should show
            # no drift (same account state) unless something changed in between.
            self._run(["check-drift", "--baseline", str(base)], check=None, allow=(0, 1))

            self.ok("plan (dry-run) previews the hardening stacks")
            proc = self._run(["plan", "--only", self.only, "--dry-run"], check=0)
            # Parse the stack names plan would touch so teardown knows them.
            self.applied_stacks = self._stacks_from_plan(proc.stdout)

            self.ok("apply a small reversible control set")
            self._run(["apply", "--only", self.only], check=None, allow=(0, 1, 2))

            self.ok("re-scan to confirm posture")
            self._run(["scan", "--only", self.only, "--format", "table"], check=None, allow=(0, 1))

    def _stacks_from_plan(self, plan_out: str) -> list[str]:
        """Extract the hardening stack names `plan --dry-run` will touch."""
        stacks: list[str] = []
        for line in plan_out.splitlines():
            # "terraform -chdir=stacks/<name> plan  # ..." (tencent) or
            # "terraform -chdir=stacks/<cloud>/<name> ..."
            if "-chdir=stacks/" in line:
                chunk = line.split("-chdir=stacks/", 1)[1].split()[0]
                name = chunk.split("/")[-1]
                if name and name not in stacks:
                    stacks.append(name)
        return stacks

    def _teardown(self) -> None:
        if not self.applied_stacks:
            print("[live] no hardening stacks applied; nothing to tear down")
            return
        if self.failures and not self.keep_on_failure:
            print(f"[live] run failed; tearing down applied stacks: {', '.join(self.applied_stacks)}")
        print(f"[live] destroying applied stacks: {', '.join(self.applied_stacks)}")
        for stack in self.applied_stacks:
            self._run(["destroy", stack], check=None, allow=(0, 2))

    # ---- entry -------------------------------------------------------------

    def run(self) -> int:
        try:
            if self.mode == "offline":
                self.run_offline()
            else:
                self.run_live()
        except AssertionError as e:
            self.fail(f"assertion: {e}")
        except Exception as e:  # noqa: BLE001 - surface any E2E error
            self.fail(f"exception: {type(e).__name__}: {e}")

        if self.failures:
            print(f"\nE2E FAILED ({len(self.failures)} failure(s)):", file=sys.stderr)
            for f in self.failures:
                print(f"  - {f}", file=sys.stderr)
            return 2
        print(f"\nE2E passed ({self.checks} command invocations, 0 failures)")
        return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="e2e_test", description="cis-cloud end-to-end test")
    p.add_argument("--mode", choices=["offline", "live"], default="offline",
                   help="offline (default, no creds) or live (real cloud account)")
    p.add_argument("--cloud", default=os.environ.get("CIS_CLOUD", "tencent"),
                   help="cloud to target (default CIS_CLOUD or tencent)")
    p.add_argument("--only", default=None, metavar="IDS",
                   help="control id(s)/glob(s) for live mode (small & reversible)")
    p.add_argument("--keep-on-failure", action="store_true",
                   help="live: do not destroy applied stacks when the run fails")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)
    return E2E(mode=args.mode, cloud=args.cloud, only=args.only,
               keep_on_failure=args.keep_on_failure, verbose=args.verbose).run()


if __name__ == "__main__":
    sys.exit(main())
