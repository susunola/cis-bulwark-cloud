<p align="center">
  <a href="https://github.com/susunola/cis-tencentcloud/actions/workflows/ci.yml"><img src="https://github.com/susunola/cis-tencentcloud/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="../LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <a href="#"><img src="https://img.shields.io/badge/benchmark-CIS%20Foundation%20v1.0.0-0052d9" alt="CIS Foundation v1.0.0"></a>
  <a href="#"><img src="https://img.shields.io/badge/ruby-%3E%3D%203.1-cc342d" alt="Ruby >= 3.1"></a>
  <a href="#"><img src="https://img.shields.io/badge/terraform-%3E%3D%201.5.0-7b42bc" alt="Terraform >= 1.5.0"></a>
</p>

---

A [Terraspace](https://terraspace.cloud) project that assesses and enforces the
**CIS Tencent Cloud Foundation Benchmark v1.0.0** — 91 security recommendations
across Identity, Logging, Networking, Storage, Database and Kubernetes. Two
modes, one codebase: `scan` for read-only compliance assessment, `apply` for
enforcement.

This is the Terraspace version. See the [plain Terraform version](../terraform) if you prefer.

---

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

## Quick Start

```bash
git clone https://github.com/susunola/cis-tencentcloud.git
cd cis-tencentcloud/terraspace
bundle install

export TENCENTCLOUD_SECRET_ID=<your-secret-id>
export TENCENTCLOUD_SECRET_KEY=<your-secret-key>
export TENCENTCLOUD_REGION=ap-guangzhou
```

**Sanity check** (no cloud, no credentials):

```bash
ruby bin/cis list          # prints the control registry
ruby test/run.rb           # 141 tests, 1569 assertions, offline
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

---

## Project Layout

```
bin/cis                     CLI entry point
config/
  controls.yml              Control registry — 91 entries, source of truth (symlink to ../config/controls.yml)
  app.rb                    Terraspace config; computes include_stacks from filters
  terraform/provider.tf     Provider pin, injected into every stack
  terraform/backend.tf      State backend
app/
  stacks/audit/             Read-only: data sources + check blocks, zero resources
  stacks/iam/               \
  stacks/logging/            |
  stacks/network/            | Six hardening stacks
  stacks/storage/            |
  stacks/database/           |
  stacks/kubernetes/        /
lib/cis/
  runner.rb                 Terraspace-specific runner
  catalog.rb, selector.rb, reporter.rb, control.rb   shared via symlink
modules/                    security_group_baseline, cos_secure_bucket, cls_audit_alarm (symlink to ../modules)
test/                       141 tests — no cloud, no credentials
tools/
  generate_controls.py      Generate controls.yml from the CIS benchmark PDF (symlink to ../tools/generate_controls.py)
  validate.sh               terraform init+validate every stack/module offline
```

---

## Commands

```
cis list                 Show the registry and what the current filter selects
cis scan                 Read-only assessment of selected controls
cis plan                 Show what cis apply would change
cis apply                Enforce selected controls
cis destroy STACK        Roll back one hardening stack
```

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Clean, or nothing to do |
| `1` | Scan found at least one failing control |
| `2` | Run broke — bad flags, empty selection, terraspace failed |

`1` is reserved for findings so CI can gate on it. `MANUAL` rows never produce a
`1`: "could not check" is not "broken."

### Output Flags

| Flag | Meaning |
|---|---|
| `--format table\|json\|markdown\|html` | Default `table` |
| `-o, --output PATH` | Write `list`/`scan` report to file |
| `--report [PATH]` | After `apply`, write HTML hardening report |
| `--dry-run` | Print terraspace commands, execute nothing |
| `--verbose` | Echo each terraspace invocation |
| `--no-color` | Disable ANSI colour |

With `--format json`, all narration goes to **stderr** — `cis scan --format json | jq` is always safe.

---

## Filtering

Every filter available as both a flag and an environment variable. They compose.

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
exported to the child `terraspace` process — `bin/cis`, the Terraspace
`include_stacks` filter, and the ERB inside `tfvars/` all resolve to the same
answer.

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
  terraspace up audit  # 1.15, 1.16, 2.1, 2.2, 2.3, 3.3, 3.4, 4.1, 4.2, 4.8, 4.9, 5.2, 6.8, 6.9, 8.1
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

Runs one hardening stack at a time — not `terraspace all` — so output is readable
and every failure is attributable to a stack. A failing stack **stops the run**.

```bash
$ ruby bin/cis apply --tag cos --exclude 4.6 --dry-run
Selection: 9/91 controls  (remediable 8, detectable 3, manual 0)
Will apply:
  terraspace up logging   # 2.2, 2.13, 2.18
  terraspace up storage   # 4.1, 4.3, 4.4, 4.5, 4.7
```

After apply succeeds, anything selected that Terraform could not enforce is
listed explicitly — the gap is visible, not assumed away.

Selecting only unenforceable controls is not an error:

```bash
$ ruby bin/cis apply --section 9
No selected control is enforceable by Terraform - nothing to apply.

Not enforced by Terraform (12) - handle these out of band:
  9.1    Ensure Container Security protection is enabled for clusters
  ...
```

`cis destroy` is per-stack and takes no filter — rolling back a hardening
baseline should be a conscious decision, not a side effect of a flag.

---

## HTML Reports

Self-contained HTML (inline CSS, zero external assets) — opens offline, prints
cleanly to PDF. Useful as audit artifacts.

### Compliance Report (`cis scan --format html`)

Grouped by section, colour-coded status badges. The header shows **UIN, account
name, app ID, and region** — read from the audit stack's `cis_account` output,
or from `CIS_UIN` / `CIS_ACCOUNT_NAME` / `CIS_APP_ID` / `TENCENTCLOUD_REGION`
environment variables. A filter bar below the summary provides free-text search
and status toggles (All / Enforced / Not Enforced / FAIL / MANUAL / SKIPPED).

```bash
cis scan --section 4 --format html --output report.html
CIS_UIN=100012345678 CIS_ACCOUNT_NAME=acme-prod cis scan --format html
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
| `stack` | Owning Terraspace stack (`null` when unsupported) |
| `tags` | Free-form selectors for `--tag` |

Use `--only` for one-off runs; edit `enabled:` for permanent exclusions.
The rest of the file is generated by `tools/generate_controls.py` from the
official CIS benchmark PDF.

---

## Tests

```bash
ruby test/run.rb                 # 141 runs, 1569 assertions
ruby test/selector_test.rb       # single file
```

No cloud API calls, no credentials, no `terraspace` invocation — every CLI test
runs with `--dry-run`.

| File | Covers |
|---|---|
| `catalog_test.rb` | Registry well-formedness: 91 ids, section sizes, profile split, capability counts |
| `selector_test.rb` | Filter semantics and precedence, `to_env`/`from_env` round-trip |
| `wiring_test.rb` | **Registry ↔ HCL alignment** |
| `cli_test.rb` | Flags, exit codes, output formats, env-vs-flag precedence |
| `runner_test.rb` | Exit-code contract, terraspace command issuance |

### Wiring Test

The most important test in the suite. It reads the Terraform as text and
validates against `config/controls.yml`:

- Every stack's `local.implemented` **exactly equals** the set of remediable
  controls the registry routes to that stack — no drift, no duplication
- The audit stack contains **no `resource` or `module` blocks**
- The audit stack's probe keys **exactly equal** the 20 detectable controls
- Every resource is gated on the selection — filtered runs are really filtered
- Every `tfvars` wires `enabled_controls` from a method that actually exists
- HCL is canonically formatted

This catches the failure mode that matters most: *"the registry says storage owns
4.7, but `storage/main.tf` never implements it"* — which otherwise surfaces as a
clean-looking report.

---

## CI / Validation

### GitHub Actions

`.github/workflows/ci.yml` runs `ruby test/run.rb` on every push and pull
request. Ruby + minitest only — no Terraform, no cloud account. The wiring test
self-skips `terraform fmt` when the binary is absent.

### Offline Terraform Validation

```bash
tools/validate.sh                    # every stack and module
tools/validate.sh storage audit      # named targets
```

Copies `app/` to a temp tree, injects the provider block, strips ERB `tfvars/`,
then runs `terraform init -backend=false && terraform validate`. No account
required.

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
- **Local state by default.** Switch `config/terraform/backend.tf` to COS remote
  backend for multi-operator use.
- **`region` defaults to `ap-guangzhou`.** Consider failing loudly when
  `TENCENTCLOUD_REGION` is unset for a compliance tool.

---

## Requirements

- Ruby >= 3.1
- Terraform >= 1.5.0
- [`tencentcloudstack/tencentcloud`](https://registry.terraform.io/providers/tencentcloudstack/tencentcloud) provider `~> 1.81`
- Terraspace `~> 2.2` (`bundle install`)
- Tencent Cloud API credentials (`TENCENTCLOUD_SECRET_ID`, `TENCENTCLOUD_SECRET_KEY`, `TENCENTCLOUD_REGION`)

Credentials are read from the environment only — nothing about an account
belongs in this repository.
