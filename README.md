> ⚠️ **Not affiliated with, endorsed by, or sponsored by the Center for Internet
> Security (CIS).** See [DISCLAIMER.md](./DISCLAIMER.md). `ohbs-cloud`
> implements hardening *aligned with* the CIS Benchmarks™; it references CIS as
> a standard only.

# oh baseline cloud

> **Repository / CLI / PyPI package:** `ohbs-cloud`
> Full name: **oh baseline cloud** — part of the **oh baseline** (ohbs) family,
> **Open Source Hardened Baseline**.

A Terraform + thin Python implementation of five cloud **foundation baselines**
across Tencent Cloud, AWS, Azure, GCP, and Alibaba Cloud — **387 security
recommendations** (Identity, Logging, Networking, Storage, Database, Kubernetes).

Two modes, one codebase: `scan` (read-only compliance assessment) and `apply`
(enforcement), wrapped in a thin Python layer (`ohbs-cloud`).

> Benchmark documents (PDFs) are **not redistributed** — only derived control
> items are implemented, per CIS Terms of Use.

## Install

```bash
pip install ohbs-cloud                # CLI + all five control registries + Terraform stacks
```

Requirements: Python >= 3.10, Terraform >= 1.5.0, and the relevant cloud
provider. Cloud credentials are read from environment variables
(e.g. `TENCENTCLOUD_SECRET_ID`, `TENCENTCLOUD_SECRET_KEY`, `TENCENTCLOUD_REGION`).

## Commands

| Command | Purpose |
|---------|---------|
| `ohbs-cloud list` | print the control registry |
| `ohbs-cloud scan` | read-only assessment |
| `ohbs-cloud plan` | show what `apply` would change |
| `ohbs-cloud apply` | enforce selected controls |
| `ohbs-cloud destroy STACK` | roll back one hardening stack |
| `ohbs-cloud compliance --dir scans` | aggregate per-cloud scan JSONs |
| `ohbs-cloud check --tf DIR` | pre-deploy baseline checks on Terraform |
| `ohbs-cloud diff BASE CUR` | compare two scan JSONs |
| `ohbs-cloud check-drift [BASE CUR \| --baseline FILE]` | flag regressions |
| `ohbs-cloud batch --accounts a,b` | scan several accounts |
| `ohbs-cloud mcp` | MCP JSON-RPC server over stdio |

Global flags: `--format`, `-o`, `--push`, `--report`, `--dry-run`, `--verbose`,
`--no-color`, `--cloud`, `--profile`, `--section`, `--tag`, `--only`,
`--exclude`, `--framework`.

## Usage

```bash
# sanity check (no credentials)
ohbs-cloud list
pytest test_py -q                 # 310 offline tests

# first scan
ohbs-cloud scan --profile level1
ohbs-cloud scan --section 4 --format html -o rpt.html

# first enforcement
ohbs-cloud apply --tag cos --dry-run
ohbs-cloud apply --tag cos --report

# other clouds
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_DEFAULT_REGION=us-east-1
ohbs-cloud --cloud aws list
ohbs-cloud --cloud aws scan --section 6 --format html -o aws-scan.html
ohbs-cloud --cloud aws apply --only 2.8,2.9,6.1.1 --dry-run
```

## Supported baselines (as standard references)

- CIS Tencent Cloud Enterprise Foundation Benchmark v1.0.0
- CIS Amazon Web Services Foundations Benchmark v7.0.0
- CIS Microsoft Azure Foundations Benchmark v6.0.0
- CIS Google Cloud Platform Foundation Benchmark v5.0.0
- CIS Alibaba Cloud Foundation Benchmark v2.0.0

These names identify the public standards `ohbs-cloud` aligns with; the project
is not certified by or affiliated with CIS.

## License

MIT — see [LICENSE](./LICENSE).
