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

COMMANDS = ["list", "scan", "plan", "apply", "destroy", "compliance", "check"]


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
        ),
    )
    p.add_argument("command", nargs="?", choices=COMMANDS,
                   help="command to run: " + ", ".join(COMMANDS))
    p.add_argument("stack", nargs="?", help="stack name for `destroy`")

    p.add_argument("--cloud", metavar="NAME",
                   help="cloud to operate on (tencent, aws, azure, gcp, alibaba; default tencent)")

    g = p.add_argument_group("Filtering")
    g.add_argument("--only", metavar="IDS", help="comma separated control ids or globs (e.g. 3.5,4.*)")
    g.add_argument("--exclude", metavar="IDS", help="comma separated ids or globs to drop")
    g.add_argument("--section", metavar="NUMS", help="comma separated benchmark sections (e.g. 3,4)")
    g.add_argument("--tag", metavar="TAGS", help="comma separated tags; matches ANY")
    g.add_argument("--profile", metavar="LEVEL", help="level1 or level2")

    o = p.add_argument_group("Output")
    o.add_argument("--format", choices=["table", "json", "markdown", "html", "csv", "junit"],
                   default="table", help="table (default), json, markdown, html, csv, junit")
    o.add_argument("-o", "--output", metavar="PATH", help="write the list/scan report to a file (any format)")
    o.add_argument("--report", nargs="?", const=True, metavar="PATH",
                   help="after `apply`, write an HTML hardening report (default: cis-hardening-<ts>.html)")
    o.add_argument("--dir", metavar="PATH", help="scan results directory for `compliance` (default: $CIS_SCAN_DIR or ./scans)")
    o.add_argument("--tf", dest="tf_dir", metavar="DIR", help="directory of Terraform files for `check`")
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
                      ("profile", "CIS_PROFILE")]:
        val = getattr(args, flag)
        if val:
            os.environ[key] = val

    reset()

    options = {
        "format": args.format,
        "output": args.output,
        "report": args.report,
        "dir": args.dir,
        "tf_dir": args.tf_dir,
        "dry_run": args.dry_run,
        "verbose": args.verbose,
        "color": not args.no_color,
    }

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
        findings = [f.to_dict() for f in tfcheck_scan(dir_, _cloud())]
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
