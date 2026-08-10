<p align="center">
  <img src="https://cdn.jsdelivr.net/gh/susunola/cis-bulwark-cloud@2c345c2/docs/logo-full.png" alt="cis-bulwark-cloud — SecX Series" width="640">
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/benchmark-v1.0.0-006EFF" alt="Benchmark v1.0.0">
  <img src="https://img.shields.io/badge/ruby-3.1%2B-CC342D?logo=ruby&logoColor=white" alt="Ruby 3.1+">
  <img src="https://img.shields.io/badge/terraform-1.5%2B-7B42BC?logo=terraform&logoColor=white" alt="Terraform 1.5+">
  <img src="https://img.shields.io/badge/provider-tencentcloud-0052D9" alt="Tencent Cloud Provider">
  <a href="https://github.com/susunola/cis-bulwark-cloud/actions/workflows/ci.yml"><img src="https://github.com/susunola/cis-bulwark-cloud/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
</p>

# cis-bulwark-cloud

A plain **Terraform** implementation of the **CIS Tencent Cloud Foundation
Benchmark v1.0.0** — 91 security recommendations across Identity, Logging,
Networking, Storage, Database and Kubernetes. Two modes, one codebase: `scan`
for read-only compliance assessment, `apply` for enforcement. No Terraspace, no
extra orchestrator — just the Terraform CLI and a thin Ruby wrapper.

The repository also ships the official CIS benchmark PDFs and extracted control
catalogs for **AWS, Alibaba Cloud, GCP and Azure** under
[`benchmarks/`](benchmarks/). Tencent and AWS are fully implemented with
`scan` + `apply`; Alibaba, GCP and Azure are published as reference catalogs
for upcoming provider mappings.

## Table of Contents

- [Capabilities](#capabilities)
- [Quick Start](#quick-start)
- [Project Layout](#project-layout)
- [Commands](#commands)
- [Filtering](#filtering)
- [Sections and Stacks](#sections-and-stacks)
- [Scan](#scan)
- [Apply](#apply)
- [HTML Reports](#html-reports)
- [Control Registry](#control-registry)
- [Tests](#tests)
- [CI / Validation](#ci--validation)
- [Limitations](#limitations)
- [Requirements](#requirements)

---

## Capabilities

| Capability | Count | Detail |
|---|---|---|
| Controls in benchmark | **91** | CIS Foundation v1.0.0 (2025-11-12) |
| Remediably by Terraform | **39** | `cis apply` can enforce these |
| Detectable by Terraform | **20** | `cis scan` can assess these |
| Manual / outside Terraform scope | **43** | Reported as `MANUAL`, never silently dropped |

A control can be **both** enforceable and detectable (e.g. 4.1 — COS bucket public
access), **remediable but not detectable** (e.g. 4.3 — COS logging: Terraform sets
it, the provider has no read-back data source), or **detectable but not
remediable** (e.g. 1.15 — CAM `*:*` policies: found by audit, but Terraform has
no business deleting a policy it didn't create).

Every selected control appears in the scan report — including the 43 unassessable
ones as `MANUAL`. A green table that silently drops half the benchmark is worse
than no report.

---

## Supported Benchmarks

The benchmark PDFs and their machine-readable control catalogs (`catalog.json`)
live under [`benchmarks/<cloud>/`](benchmarks/). Catalogs are extracted from the
Summary Table + profile applicability of each PDF by
`tools/extract_benchmark.py`.

| Cloud | Benchmark | Version | Controls | Status |
|---|---|---|---|---|
| Tencent Cloud | CIS Tencent Cloud Enterprise Foundation Benchmark | v1.0.0 | 91 | `scan` + `apply` |
| Amazon Web Services | CIS Amazon Web Services Foundations Benchmark | v7.0.0 | 64 | `scan` + `apply` |
| Alibaba Cloud | CIS Alibaba Cloud Foundation Benchmark | v2.0.0 | 78 | catalog only |
| Google Cloud Platform | CIS Google Cloud Platform Foundation Benchmark | v5.0.0 | 84 | catalog only |
| Microsoft Azure | CIS Microsoft Azure Foundations Benchmark | v6.0.0 | 70 | catalog only |

Tencent's registry feeds `config/controls.yml`, AWS's feeds
`config/aws/controls.yml` (both via `tools/generate_controls.py --cloud NAME`);
the other three are reference catalogs until a provider mapping is written. The
`aws`, `alibaba`, `gcp` and `azure` catalogs carry an extra `group` field on
three-level controls (e.g. `2.1.1` → `"Organizations"`). Benchmark PDFs are ©
The Center for Internet Security, Inc.

---

## Quick Start

```bash
git clone https://github.com/susunola/cis-bulwark-cloud.git
cd cis-bulwark-cloud

gem install minitest -v 5.26.1        # only dependency of the offline suite

export TENCENTCLOUD_SECRET_ID=<your-secret-id>
export TENCENTCLOUD_SECRET_KEY=<your-secret-key>
export TENCENTCLOUD_REGION=ap-guangzhou
```

**Sanity check** (no cloud, no credentials):

```bash
ruby bin/cis list          # prints the control registry
ruby test/run.rb           # 167 tests, 6179 assertions, offline
```

**First scan:**

```bash
ruby bin/cis scan --profile level1                   # table to stdout
ruby bin/cis scan --section 4 --format html -o rpt.html  # self-contained HTML
```

**First enforcement (dry-run first):**

```bash
ruby bin/cis apply --tag cos --dry-run               # preview
ruby bin/cis apply --tag cos --report                # enforce + HTML record
```

**AWS (pick the cloud with `--cloud` or `CIS_CLOUD`):**

```bash
export AWS_ACCESS_KEY_ID=<your-access-key>
export AWS_SECRET_ACCESS_KEY=<your-secret-key>
export AWS_DEFAULT_REGION=us-east-1

ruby bin/cis --cloud aws list                        # 64 AWS controls
ruby bin/cis --cloud aws scan --section 6 --format html -o aws-scan.html
ruby bin/cis --cloud aws apply --only 2.8,2.9,6.1.1 --dry-run   # preview
```

AWS covers 8 remediable / 9 detectable controls; the rest are reported as
`MANUAL` because the provider has no enumerable data source or no non-destructive
resource for them. See `stacks/aws/` for per-stack import instructions.

---

## Project Layout

```
bin/cis                     CLI entry point (--cloud tencent|aws)
config/controls.yml         Tencent registry — 91 entries, source of truth
config/aws/controls.yml     AWS registry — 64 entries
benchmarks/                 CIS benchmark PDFs + extracted catalogs, per cloud
  tencent/catalog.json      Tencent Cloud (91 controls) - feeds controls.yml
  aws/catalog.json          AWS v7.0.0 (64 controls) - feeds config/aws/controls.yml
  alibaba/catalog.json      Alibaba Cloud v2.0.0 (78 controls) - reference
  gcp/catalog.json          GCP v5.0.0 (84 controls) - reference
  azure/catalog.json        Azure v6.0.0 (70 controls) - reference
lib/cis.rb                  Shared Ruby layer: catalog, selector, reporter
lib/cis/runner.rb           Runner: shells out to `terraform`
lib/cis/catalog.rb, selector.rb, reporter.rb, control.rb
modules/                    Reusable Terraform modules
  security_group_baseline/
  cos_secure_bucket/
  cls_audit_alarm/
stacks/
  audit/                    Read-only: data sources + check blocks, zero resources
  iam/                      \
  logging/                   |
  network/                   | Six hardening stacks (self-contained root modules)
  storage/                   |
  database/                  |
  kubernetes/               /
test/                       139 tests — no cloud, no credentials
tools/
  extract_benchmark.py      Extract <cloud>/catalog.json from a CIS benchmark PDF text
  generate_controls.py      Generate config/controls.yml from the Tencent catalog
  validate.sh               terraform init+validate every stack/module offline
docs/
  sample-scan.html          Example scan report (static)
  sample-hardening.html     Example hardening report (static)
```

Each stack under `stacks/` is a **self-contained root module**: it carries its
own `provider.tf` and `backend.tf`, so `terraform -chdir=stacks/<name> ...`
works standalone. State defaults to a per-stack `terraform.tfstate`; see
`stacks/<name>/backend.tf` for the COS (tencent) / S3 (aws) remote-backend
guidance. Later clouds nest under `stacks/<cloud>/<name>`.

---

## Commands

```
cis --cloud aws list       Show the registry for a cloud (default: tencent)
cis scan                   Read-only assessment of selected controls
cis plan                   Show what cis apply would change
cis apply                  Enforce selected controls
cis destroy STACK          Roll back one hardening stack
```

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Clean, or nothing to do |
| `1` | Scan found at least one failing control |
| `2` | Run broke — bad flags, empty selection, terraform failed |

`1` is reserved for findings so CI can gate on it. `MANUAL` rows never produce a
`1`: "could not check" is not "broken."

### Output Flags

| Flag | Meaning |
|---|---|
| `--format table\|json\|markdown\|html` | Default `table` |
| `-o, --output PATH` | Write `list`/`scan` report to file |
| `--report [PATH]` | After `apply`, write HTML hardening report |
| `--dry-run` | Print terraform commands, execute nothing |
| `--verbose` | Echo each terraform invocation |
| `--no-color` | Disable ANSI colour |

With `--format json`, all narration goes to **stderr** — `cis scan --format json | jq` is always safe.

---

## Filtering

Every filter is available both as a flag and as an environment variable. They compose.

| Flag | Variable | Meaning |
|---|---|---|
| `--only 3.5,4.*` | `CIS_ONLY` | Exactly these ids/globs. Replaces the `enabled:` baseline |
| `--exclude 4.6` | `CIS_EXCLUDE` | Drop these ids/globs. Applied last, always wins |
| `--section 3,4` | `CIS_SECTIONS` | Restrict to these benchmark sections |
| `--tag cos,mfa` | `CIS_TAGS` | Keep controls carrying any of these tags |
| `--profile level1` | `CIS_PROFILE` | `level1` (67 controls) or `level2` (all 91) |

**Precedence:** `--only` replaces the baseline; `--section`, `--tag` and
`--profile` narrow whatever baseline is in play; `--exclude` is applied last and
beats everything.

A filter that matches nothing is a hard error:

```bash
$ ruby bin/cis scan --only 12.7
error: filter "12.7" matches no control in the benchmark
$ echo $?
2
```

CLI flags overwrite pre-existing `CIS_*` variables. The resolved selection is
exported to the terraform invocations — `bin/cis`, the stack filtering and the
`enabled_controls` variable all resolve to the same answer.

---

## Sections and Stacks

| § | Area | Controls | Remediable | Stack |
|---|---|---|---|---|
| 1 | Identity and Access Management | 16 | 1 | `iam` |
| 2 | Logging and Monitoring | 20 | 17 | `logging` (16), `network` (2.4) |
| 3 | Networking | 7 | 6 | `network` |
| 4 | Storage | 9 | 6 | `storage` |
| 5 | TencentDB for MySQL | 6 | 6 | `database` |
| 6 | Kubernetes Engine | 9 | 3 | `kubernetes` |
| 7 | Cloud Security Center | 6 | 0 | — (manual) |
| 8 | Cloud Workload Protection | 6 | 0 | — (manual) |
| 9 | Container Security Service | 12 | 0 | — (manual) |

2.4 (VPC flow logs) lives in the `network` stack — stacks are grouped by the
resource they touch, not by section number.

Stacks always run in fixed order for reproducibility: `iam`, `logging`, `network`,
`storage`, `database`, `kubernetes`.

---

## Scan

Deploys the `audit` stack (zero managed resources — data sources, `check` blocks
and outputs only), reads back `cis_findings`, renders the result.

Covers the 20 detectable controls:

```
1.15 1.16  2.1 2.2 2.3 2.20  3.1 3.3 3.4 3.5 3.6
4.1 4.2 4.8 4.9  5.2  6.8 6.9  8.1 8.2
```

```bash
$ ruby bin/cis scan --profile level1 --dry-run
Scanning 15 control(s) via the audit stack (read-only).
Will scan:
  terraform -chdir=stacks/audit apply -auto-approve # 1.15, 1.16, 2.1, 2.2, 2.3, 3.3, 3.4, 4.1, 4.2, 4.8, 4.9, 5.2, 6.8, 6.9, 8.1
```

| Status | Meaning |
|---|---|
| `PASS` | Assessed, compliant |
| `FAIL` | Assessed, non-compliant — exit 1 |
| `SKIPPED` | Enforced by `apply` but not readable back |
| `MANUAL` | Outside Terraform scope; verify in console |

Selecting only manual controls is valid:

```bash
$ ruby bin/cis scan --section 9 --no-color
No selected control is machine-assessable by the provider.
Selected: 12. Use cis list to see why.

  STATUS   ID     TITLE                                                EVIDENCE
  ------------------------------------------------------------------------------------
  MANUAL   9.1    Ensure Container Security protection is enabled ...  verify in console
  ...
  FAIL 0   PASS 0   MANUAL 12   SKIPPED 0
```

---

## Apply

Runs one hardening stack at a time — each is a separate `terraform apply` — so
output is readable and every failure is attributable to a stack. A failing stack
**stops the run**.

```bash
$ ruby bin/cis apply --tag cos --exclude 4.6 --dry-run
Selection: 9/91 controls  (remediable 8, detectable 3, manual 0)
Will apply:
  terraform -chdir=stacks/logging   apply # 2.2, 2.13, 2.18
  terraform -chdir=stacks/storage   apply # 4.1, 4.3, 4.4, 4.5, 4.7
```

### Hardening Report (`cis apply --report`)

Records what was enforced per stack, plus the controls Terraform could not touch.
Same account header as the scan report.

```bash
cis apply --tag cos --exclude 4.6 --report             # -> cis-hardening-<ts>.html
cis apply --only 4.*            --report harden.html   # -> harden.html
```

`--report` works under `--dry-run`: stacks are marked `planned` instead of
`ok`/`fail`, giving a preview artifact before touching the account.

---

## HTML Reports

`cis scan` and `cis apply` produce self-contained HTML reports with an account
header, summary statistics, per-section tables, and a client-side filter bar. No
external assets are loaded. See [sample-scan.html](docs/sample-scan.html) and
[sample-hardening.html](docs/sample-hardening.html) for what they look like.

---

## Control Registry

`config/controls.yml` is the source of truth. Each entry:

```yaml
- id: "4.6"
  title: "Ensure server-side encryption is set to SSE-COS"
  assessment: Manual
  profile: "Level 2"
  enabled: true
  remediate: terraform
  detect: none
  stack: storage
  tags: [cos, encryption, sse-cos]
```

| Field | Meaning |
|---|---|
| `assessment` | `Automated` / `Manual`, as classified by CIS |
| `profile` | `Level 1` / `Level 2`, as classified by CIS |
| `enabled` | Participates in `scan`/`apply` by default — **edit this for permanent scope** |
| `remediate` | `terraform` / `none` — can `apply` enforce it |
| `detect` | `terraform` / `none` — can `scan` evaluate it |
| `stack` | Owning Terraform stack (`null` when unsupported) |
| `tags` | Free-form selectors for `--tag` |

Use `--only` for one-off runs; edit `enabled:` for permanent exclusions.
The rest of the file is generated by `tools/generate_controls.py` from the
official CIS benchmark PDF.

---

## Tests

```bash
ruby test/run.rb                 # 167 runs, 6179 assertions
ruby test/selector_test.rb       # single file
```

No cloud API calls, no credentials, no `terraform` execution — every CLI test
runs with `--dry-run`.

| File | Covers |
|---|---|
| `catalog_test.rb` | Registry well-formedness: 91 ids, section sizes, profile split, capability counts |
| `selector_test.rb` | Filter semantics and precedence, `to_env`/`from_env` round-trip |
| `wiring_test.rb` | **Registry ↔ HCL alignment (tencent)** |
| `aws_wiring_test.rb` | **Registry ↔ HCL alignment (AWS)** |
| `cli_test.rb` | Flags, exit codes, output formats, env-vs-flag precedence, `--cloud` |
| `runner_test.rb` | Exit-code contract, terraform command issuance |
| `benchmarks_test.rb` | **Every `benchmarks/<cloud>/catalog.json`**: shape, id uniqueness/contiguity, enum values, pdftotext residue, group↔sections agreement, catalog ↔ controls.yml drift |

### Wiring Test

The most important test in the suite. It reads the Terraform as text and
validates against `config/controls.yml`:

- Every stack's `local.implemented` **exactly equals** the set of remediable
  controls the registry routes to that stack — no drift, no duplication
- The audit stack contains **no `resource` or `module` blocks**
- The audit stack's probe keys **exactly equal** the 20 detectable controls
- Every resource is gated on the selection — filtered runs are really filtered
- Every `.tfvars` wires `enabled_controls` from a method that actually exists
- HCL is canonically formatted (`terraform fmt`, self-skips when the binary is absent)

This catches the failure mode that matters most: *"the registry says storage owns
4.7, but `storage/main.tf` never implements it"* — which otherwise surfaces as a
clean-looking report.

---

## CI / Validation

### GitHub Actions

`.github/workflows/ci.yml` runs `ruby test/run.rb` on every push and pull
request, then `terraform init -backend=false && terraform validate` on every
module and stack. Ruby + minitest + Terraform CLI only — no cloud account.

### Offline Terraform Validation

```bash
tools/validate.sh                    # every stack and module
tools/validate.sh storage audit      # named targets
```

Copies `stacks/` and `modules/` into a scratch tree that mirrors the project
root (so `../../modules/` source paths keep resolving), then runs
`terraform init -backend=false && terraform validate`. No account required.

---

## Limitations

- **Coverage ceiling.** 39/91 remediable, 20/91 detectable. Several `MANUAL`
  controls are manual only because the provider data source hasn't been wired —
  the `audit/data.tf` gating pattern is the template. Moving controls from manual
  to detectable is the highest-value contribution.
- **No drift tracking.** `cis scan` is point-in-time. Baseline save/compare is
  the natural next feature for compliance cadence.
- **No post-apply verification.** `apply` does not re-run `scan` to assert the
  control flipped to PASS.
- **Failing stack stops the run.** No `--continue-on-error`. Current behaviour is
  intentional (attribution over throughput).
- **Local state by default.** Switch `stacks/<name>/backend.tf` to a COS remote
  backend for multi-operator use.
- **`region` defaults to `ap-guangzhou`.** Consider failing loudly when
  `TENCENTCLOUD_REGION` is unset for a compliance tool.

---

## Requirements

- Ruby >= 3.1
- Terraform >= 1.5.0
- [`tencentcloudstack/tencentcloud`](https://registry.terraform.io/providers/tencentcloudstack/tencentcloud) provider `~> 1.81`
- Tencent Cloud API credentials (`TENCENTCLOUD_SECRET_ID`, `TENCENTCLOUD_SECRET_KEY`, `TENCENTCLOUD_REGION`)

Credentials are read from the environment only — nothing about an account
belongs in this repository.

## License

MIT — see [LICENSE](LICENSE).
