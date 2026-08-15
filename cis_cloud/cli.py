"""cis-cloud — CIS cloud foundation benchmark (plain Terraform).

    cis-cloud --cloud aws list                show the control registry for a cloud
    cis-cloud scan                            read-only assessment of the selected controls
    cis-cloud plan                            show what `cis-cloud apply` would change
    cis-cloud apply                           enforce the selected controls
    cis-cloud destroy STACK                   roll back one hardening stack

Cloud: defaults to tencent; override per run with --cloud, or persistently
with CIS_CLOUD=aws.

Filtering (composable; all of them also work as CIS_* environment variables):

    --only 3.5,4.*                  exactly these ids/globs, ignoring `enabled:`
    --exclude 4.6                   drop these ids/globs, applied last
    --section 3,4                   restrict to these benchmark sections
    --tag cos,encryption            keep controls carrying ANY of these tags
    --profile level1                keep Level 1 controls only

Output / behaviour:

    --format table|json|markdown|html   default: table
    -o, --output PATH                   write the list/scan report to a file
    --report [PATH]                     after `apply`, write an HTML hardening
                                         report (default: cis-hardening-<ts>.html)
    --dry-run                           print the terraform commands, run nothing
    --verbose                           echo each terraform invocation
    --no-color                          disable ANSI colour
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import Error, cloud as _cloud, hardening_stacks, reset, get_selector as _selector
from .compliance import Compliance
from .runner import Runner
from .tfcheck import scan as tfcheck_scan

COMMANDS = ["list", "scan", "plan", "apply", "destroy", "compliance", "check", "diff", "check-drift", "batch"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cis-cloud",
        description="CIS cloud foundation benchmarks via plain Terraform.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  cis-cloud list --profile level1\n"
            "  cis-cloud scan --section 3,4 --format json\n"
            "  cis-cloud scan --section 4 --format html --output report.html\n"
            "  cis-cloud plan --only 4.*\n"
            "  cis-cloud apply --tag cos --exclude 4.6 --report\n"
            "  cis-cloud check --tf DIR --checks checks.yml\n"
            "  cis-cloud diff scans/baseline.json scans/current.json\n"
            "  cis-cloud check-drift --baseline scans/base.json          # fresh scan vs baseline\n"
            "  cis-cloud check-drift scans/base.json scans/current.json  # offline compare\n"
            "  cis-cloud batch --accounts a1,a2 --cloud aws --out scans\n"
        ),
    )
    p.add_argument("command", nargs="?", choices=COMMANDS,
                   help="command to run: " + ", ".join(COMMANDS))
    p.add_argument("stack", nargs="?", help="stack name for `destroy`")
    # `diff` takes two scan JSON files: cis-cloud diff baseline.json current.json
    p.add_argument("args", nargs="*", metavar="PATH",
                   help="scan JSON paths for `diff` (baseline then current)")

    p.add_argument("--cloud", metavar="NAME",
                   help="cloud to operate on (tencent, aws, azure, gcp, alibaba; default tencent)")

    g = p.add_argument_group("Filtering")
    g.add_argument("--only", metavar="IDS", help="comma separated control ids or globs (e.g. 3.5,4.*)")
    g.add_argument("--exclude", metavar="IDS", help="comma separated ids or globs to drop")
    g.add_argument("--section", metavar="NUMS", help="comma separated benchmark sections (e.g. 3,4)")
    g.add_argument("--tag", metavar="TAGS", help="comma separated tags; matches ANY")
    g.add_argument("--profile", metavar="LEVEL", help="level1 or level2")
    g.add_argument("--framework", metavar="NAME",
                   help="view controls mapped to another framework: nist, pci, djcp")

    o = p.add_argument_group("Output")
    o.add_argument("--format", choices=["table", "json", "markdown", "html", "csv", "junit", "sarif"],
                   default="table", help="table (default), json, markdown, html, csv, junit, sarif")
    o.add_argument("-o", "--output", metavar="PATH", help="write the list/scan report to a file (any format)")
    o.add_argument("--push", metavar="DIR",
                   help="also write a timestamped JSON scan result into DIR")
    o.add_argument("--report", nargs="?", const=True, metavar="PATH",
                   help="after `apply`, write an HTML hardening report (default: cis-hardening-<ts>.html)")
    o.add_argument("--dir", metavar="PATH", help="scan results directory for `compliance` (default: $CIS_SCAN_DIR or ./scans)")
    o.add_argument("--accounts", metavar="A,B,C",
                   help="for `batch`: comma separated account names to scan and aggregate")
    o.add_argument("--out", metavar="DIR",
                   help="for `batch`: directory to write per-account scan JSON (default: ./scans)")
    o.add_argument("--tf", dest="tf_dir", metavar="DIR", help="directory of Terraform files for `check`")
    o.add_argument("--checks", metavar="FILE",
                   help="YAML file of extra user-defined checks, merged into `check` rules")
    o.add_argument("--baseline", metavar="PATH",
                   help="for `check-drift`: baseline scan JSON to compare a fresh scan against")
    o.add_argument("--plan-check", action="store_true",
                   help="with `plan`, run a static tfcheck on --tf and block if any control FAILs")
    o.add_argument("--dry-run", action="store_true", help="print what would run, execute nothing")
    o.add_argument("--verbose", action="store_true", help="echo each terraform invocation")
    o.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    return p


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help(sys.stderr)
        return 2

    if args.cloud:
        os.environ["CIS_CLOUD"] = args.cloud
    for flag, key in [("only", "CIS_ONLY"), ("exclude", "CIS_EXCLUDE"),
                      ("section", "CIS_SECTIONS"), ("tag", "CIS_TAGS"),
                      ("profile", "CIS_PROFILE"), ("framework", "CIS_FRAMEWORK")]:
        val = getattr(args, flag)
        if val:
            os.environ[key] = val

    reset()

    options = {
        "format": args.format,
        "output": args.output,
        "push": args.push,
        "report": args.report,
        "dir": args.dir,
        "tf_dir": args.tf_dir,
        "plan_check": args.plan_check,
        "dry_run": args.dry_run,
        "verbose": args.verbose,
        "color": not args.no_color,
    }

    if args.command == "diff":
        paths = ([args.stack] if args.stack else []) + args.args
        if len(paths) != 2:
            print("error: `cis-cloud diff` needs two scan JSON paths: baseline then current", file=sys.stderr)
            return 2
        return Runner(None, options=options).diff(paths[0], paths[1])

    if args.command == "check-drift":
        paths = ([args.stack] if args.stack else []) + args.args
        if args.baseline:
            return Runner(None, options=options).check_drift(args.baseline)
        if len(paths) != 2:
            print("error: `cis-cloud check-drift` needs --baseline PATH (live scan) "
                  "or two scan JSON paths (offline): baseline then current", file=sys.stderr)
            return 2
        return Runner(None, options=options).check_drift(paths[0], paths[1])

    if args.command == "batch":
        accounts = [a.strip() for a in (args.accounts or "").split(",") if a.strip()]
        if not accounts:
            print("error: `cis-cloud batch` needs --accounts a,b,c", file=sys.stderr)
            return 2
        out_dir = args.out or os.environ.get("CIS_SCAN_DIR") or str(Path.cwd() / "scans")
        return Runner(_selector(), options=options).batch(accounts, out_dir)

    try:
        sel = _selector()
    except Error as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if sel.is_empty() and args.command != "list":
        print("error: the current filters select 0 controls; nothing to do.", file=sys.stderr)
        return 2

    runner = Runner(sel, options=options)

    if args.command == "list":
        return runner.list()
    if args.command == "scan":
        return runner.scan()
    if args.command == "plan":
        return runner.plan()
    if args.command == "apply":
        return runner.apply()

    if args.command == "check":
        dir_ = args.tf_dir
        if dir_ is None:
            print("error: `cis-cloud check` needs --tf DIR (a directory of .tf files)", file=sys.stderr)
            return 2
        if not Path(dir_).is_dir():
            print(f"error: no such directory: {dir_}", file=sys.stderr)
            return 2
        extra = None
        if args.checks:
            from .tfcheck import load_checks
            try:
                extra = load_checks(args.checks).get(_cloud())
            except (FileNotFoundError, ValueError) as e:
                print(f"error: {e}", file=sys.stderr)
                return 2
        findings = [f.to_dict() for f in tfcheck_scan(dir_, _cloud(), extra_rules=extra)]
        return runner.check(findings)

    if args.command == "compliance":
        dir_ = args.dir or os.environ.get("CIS_SCAN_DIR") or str(Path.cwd() / "scans")
        compliance = Compliance.load_dir(dir_)
        if compliance.is_empty():
            print(f"error: no scan results found in {dir_}; save per-cloud scans with: "
                  f"cis-cloud --cloud X scan --format json -o scans/X.json", file=sys.stderr)
            return 2
        return runner.compliance(compliance)

    if args.command == "destroy":
        stack = args.stack
        if stack is None:
            print(f"error: `cis-cloud destroy` needs a stack name ({', '.join(hardening_stacks())})",
                  file=sys.stderr)
            return 2
        return runner.destroy(stack)

    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
