# cis-tencentcloud

Terraspace project that scans for, and enforces, the
**CIS Tencent Cloud Foundation Benchmark v1.0.0** (91 recommendations, released
11-12-2025).

Two things it is built to do:

1. **Pick exactly which recommendations you care about** — by id, glob, section,
   tag or profile level.
2. **Run in one of two modes** — `scan` (read-only assessment) or `apply`
   (enforcement). They are separate stacks, not a flag on the same code path.

---

## What the benchmark actually gives you

Be clear-eyed about this before you start, because it sets the ceiling on what
any tool can do here:

| | Count | Note |
|---|---|---|
| Recommendations in v1.0.0 | 91 | |
| CIS-classified **Automated** | 25 | |
| CIS-classified **Manual** | 66 | |
| **Remediable** by Terraform | **39** | `cis apply` can enforce these |
| **Detectable** by Terraform | **20** | `cis scan` can assess these |
| **Neither** | **43** | reported as `MANUAL`, never silently dropped |

Those three capability numbers overlap by design. A control can be:

- **both** — `4.1` COS bucket public access: enforceable, and readable back;
- **remediable but not detectable** — `4.3` COS bucket logging: Terraform can
  set it, but the provider exposes no data source to confirm it afterwards;
- **detectable but not remediable** — `1.15` CAM policies granting full `*:*`
  privileges: the audit stack can find them, but Terraform has no business
  deleting a policy it did not create.

Every selected control appears in the scan report — the 43 unassessable ones as
`MANUAL`. That is deliberate. A short green table that quietly dropped half the
benchmark is worse than no report at all.

---

## Layout

```
bin/cis                    the CLI
config/
  controls.yml             the control registry - 91 entries, the source of truth
  app.rb                   Terraspace config; computes include_stacks from the filter
  terraform/provider.tf    provider pin, injected into every built stack
  terraform/backend.tf     state location
app/
  stacks/audit/            read-only. data sources + check blocks + outputs, zero resources
  stacks/iam/              \
  stacks/logging/           |
  stacks/network/           | the six hardening stacks
  stacks/storage/           |
  stacks/database/          |
  stacks/kubernetes/       /
  modules/                 security_group_baseline, cos_secure_bucket, cls_audit_alarm
lib/cis/                   catalog, selector, runner, reporter
test/                      134 tests / 1507 assertions; no cloud, no credentials
tools/validate.sh          terraform init+validate every stack and module offline
```

---

## Install

```bash
bundle install                 # terraspace ~> 2.2
export TENCENTCLOUD_SECRET_ID=...
export TENCENTCLOUD_SECRET_KEY=...
export TENCENTCLOUD_REGION=ap-guangzhou
```

Requires Terraform >= 1.5.0 and the `tencentcloudstack/tencentcloud` provider
`~> 1.81`. Credentials are read from the environment only — nothing about an
account belongs in this repository.

Sanity check without touching an account:

```bash
ruby bin/cis list            # prints the registry, exits 0
ruby test/run.rb             # full suite, no network
```

---

## Commands

```
cis list                 show the registry and what the current filter selects
cis scan                 read-only assessment of the selected controls
cis plan                 show what `cis apply` would change
cis apply                enforce the selected controls
cis destroy STACK        roll back one hardening stack
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | clean, or nothing to do |
| `1` | **the scan found at least one failing control** |
| `2` | the run itself broke — bad flags, empty selection, terraspace failed |

`1` is reserved for findings so CI can gate on it. `MANUAL` rows never produce
a `1`: "we could not check this" is not "this is broken."

---

## Filtering

Every filter is available as a flag and as an environment variable. They
compose.

| Flag | Variable | Meaning |
|---|---|---|
| `--only 3.5,4.*` | `CIS_ONLY` | exactly these ids/globs. **Replaces** the `enabled:` baseline |
| `--exclude 4.6` | `CIS_EXCLUDE` | drop these ids/globs. **Applied last, always wins** |
| `--section 3,4` | `CIS_SECTIONS` | restrict to these benchmark sections |
| `--tag cos,mfa` | `CIS_TAGS` | keep controls carrying **any** of these tags |
| `--profile level1` | `CIS_PROFILE` | `level1` (67 controls) or `level2` (cumulative, all 91) |

Precedence: `--only` replaces the baseline entirely; `--section`, `--tag` and
`--profile` narrow whatever baseline is in play; `--exclude` is applied last and
beats everything.

A filter that matches nothing is a **hard error**, not an empty run:

```bash
$ ruby bin/cis scan --only 12.7
error: filter "12.7" matches no control in the benchmark
$ echo $?
2
```

CLI flags overwrite any pre-existing `CIS_*` variables, and the resolved
selection is exported to the child `terraspace` process — so `bin/cis`, the
Terraspace `include_stacks` filter and the ERB inside `tfvars/` all resolve to
the same answer. There is exactly one place the selection is decided.

### Output flags

| Flag | Meaning |
|---|---|
| `--format table\|json\|markdown` | default `table` |
| `--dry-run` | print the terraspace commands, execute nothing |
| `--verbose` | echo each terraspace invocation |
| `--no-color` | disable ANSI colour |

With `--format json`, all narration goes to **stderr**, so
`cis scan --format json \| jq` is always safe.

---

## Sections and stacks

| § | Area | Controls | Remediable | Owning stack |
|---|---|---|---|---|
| 1 | Identity and Access Management | 16 | 1 | `iam` |
| 2 | Logging and Monitoring | 20 | 17 | `logging` (16), `network` (2.4) |
| 3 | Networking | 7 | 6 | `network` |
| 4 | Storage | 9 | 6 | `storage` |
| 5 | TencentDB for MySQL | 6 | 6 | `database` |
| 6 | Kubernetes Engine | 9 | 3 | `kubernetes` |
| 7 | Cloud Security Center | 6 | 0 | — manual |
| 8 | Cloud Workload Protection | 6 | 0 | — manual |
| 9 | Container Security Service | 12 | 0 | — manual |

Note that `2.4` is a flow-log control and lives in the `network` stack, not
`logging` — stacks are grouped by the resource they touch, not by section.

Sections 7–9 are console-only products with no Terraform surface. Section 1 is
mostly CAM password policy (1.7–1.14), which the provider does not expose.

Stacks always run in this order, so a run is reproducible:
`iam, logging, network, storage, database, kubernetes`.

---

## `cis scan`

Deploys the `audit` stack, reads back its `cis_findings` output, and renders a
table. The audit stack declares **zero managed resources** — only data sources,
`check` blocks and outputs. That is enforced by the test suite, not by
convention.

It covers the 20 detectable controls:

```
1.15 1.16  2.1 2.2 2.3 2.20  3.1 3.3 3.4 3.5 3.6
4.1 4.2 4.8 4.9  5.2  6.8 6.9  8.1 8.2
```

```bash
$ ruby bin/cis scan --profile level1 --dry-run
Scanning 15 control(s) via the `audit` stack (read-only).
Will scan:
  terraspace up    audit       # 1.15, 1.16, 2.1, 2.2, 2.3, 3.3, 3.4, 4.1, 4.2, 4.8, 4.9, 5.2, 6.8, 6.9, 8.1
```

Four statuses:

| Status | Meaning |
|---|---|
| `PASS` | assessed, compliant |
| `FAIL` | assessed, non-compliant → **exit 1** |
| `SKIPPED` | Terraform enforces it, but cannot read it back to confirm |
| `MANUAL` | outside Terraform entirely; verify in the console |

Selecting only manual controls is legal and produces a full `MANUAL` table
rather than an error:

```bash
$ ruby bin/cis scan --section 9 --no-color
No selected control is machine-assessable by the provider.
Selected: 12. Use `cis list` to see why.

  STATUS   ID     TITLE                                                      EVIDENCE
  ------------------------------------------------------------------------------------------
  MANUAL   9.1    Ensure Container Security protection is enabled for clust~ verify in console
  ...
  FAIL 0   PASS 0   MANUAL 12   SKIPPED 0
```

---

## `cis plan` / `cis apply`

Runs one hardening stack at a time — not `terraspace all` — so output streams in
a readable order and every failure is attributable to a stack. A failing stack
**stops the run**; it does not carry on to the next one.

```bash
$ ruby bin/cis apply --tag cos --exclude 4.6 --dry-run
Selection: 9/91 controls  (remediable 8, detectable 3, manual 0)
Will apply:
  terraspace up    logging     # 2.2, 2.13, 2.18
  terraspace up    storage     # 4.1, 4.3, 4.4, 4.5, 4.7
```

After a successful apply, anything selected that Terraform could not enforce is
listed explicitly, so the gap is visible rather than assumed away.

Selecting only unenforceable controls is not an error — it reports and exits 0:

```bash
$ ruby bin/cis apply --section 9
No selected control is enforceable by Terraform - nothing to apply.

Not enforced by Terraform (12) - handle these out of band:
  9.1    Ensure Container Security protection is enabled for clusters
  ...
```

`cis destroy` is deliberately per-stack and takes no filter. Rolling back a
hardening baseline should be a conscious decision, not a side effect of a flag.

---

## Choosing controls permanently

`config/controls.yml` is the registry. The `enabled:` flag on each entry is the
baseline — that is the field intended for hand-editing:

```yaml
- id: "4.6"
  title: "Ensure server-side encryption is set to SSE-COS"
  assessment: Manual
  profile: "Level 2"
  enabled: true          # <- edit this
  remediate: terraform
  detect: none
  stack: storage
  tags: [cos, encryption, sse-cos]
```

| Field | Meaning |
|---|---|
| `assessment` | `Automated` / `Manual`, as classified by CIS |
| `profile` | `Level 1` / `Level 2`, as classified by CIS |
| `enabled` | whether it participates in `scan` / `apply` by default |
| `remediate` | `terraform` / `none` — can `cis apply` enforce it |
| `detect` | `terraform` / `none` — can `cis scan` evaluate it |
| `stack` | which Terraspace stack owns it (`null` when unsupported) |
| `tags` | free-form selectors for `--tag` |

Use `--only` for a one-off run; use `enabled:` when a control is permanently out
of scope for your organisation. Everything else in the file is generated by
`tools/generate_controls.py` from the benchmark PDF.

---

## Tests

```bash
ruby test/run.rb                # everything: 134 runs, 1507 assertions
ruby test/selector_test.rb      # one file
```

No cloud API calls, no credentials, no `terraspace` invocation — every CLI test
runs with `--dry-run`.

| File | Covers |
|---|---|
| `catalog_test.rb` | the registry is well-formed: 91 ids, section sizes, profile split, capability counts, loader error cases |
| `selector_test.rb` | filter semantics and precedence, `to_env`/`from_env` round-trip |
| `wiring_test.rb` | **the registry and the HCL agree** |
| `cli_test.rb` | flags, exit codes, output formats, env-vs-flag precedence |
| `runner_test.rb` | the exit-code contract and which terraspace commands get issued |

`wiring_test.rb` is the one that earns its keep. It reads the Terraform as text
and holds it against `config/controls.yml`, asserting among other things that:

- every stack's `local.implemented` list **exactly equals** the set of
  remediable controls the registry routes to that stack — no drift in either
  direction, no control implemented twice
- the audit stack contains **no `resource` or `module` blocks at all**
- the audit stack's probe keys **exactly equal** the 20 detectable controls
- every resource is gated on the selection, so a filtered run really is filtered
- every `tfvars` wires `enabled_controls` from a method that actually exists
- the HCL is canonically formatted

This catches the failure mode that matters most in a compliance tool: *"the
registry says storage owns 4.7, but `storage/main.tf` never implements it"* —
which otherwise surfaces as a clean-looking report.

### Offline Terraform validation

```bash
tools/validate.sh                       # every stack and module
tools/validate.sh storage audit         # named targets
```

Copies `app/` to a temp tree, injects the provider block Terraspace would have
injected, strips the ERB `tfvars/`, then runs `terraform init -backend=false &&
terraform validate`. No account required.

### Continuous integration

`.github/workflows/ci.yml` runs `ruby test/run.rb` on every push and pull
request. It needs only Ruby and `minitest` — Terraform is not installed because
the `wiring_test` `fmt` check self-skips when the binary is absent, and every CLI
path the suite exercises runs with `--dry-run`. This keeps the registry↔HCL
alignment gate in force on every change without requiring a cloud account in CI.

---

## Notes

- **State** lives in `<project>/state/`, deliberately *not* inside
  `.terraspace-cache`, so `terraspace clean cache` cannot destroy the record of
  what has been applied. Switch `config/terraform/backend.tf` to a COS backend
  for anything beyond a single operator.
- **`terraspace` run by hand** honours the same filter: `config/app.rb` sets
  `config.all.include_stacks = Cis.active_stacks`, which reads the same `CIS_*`
  variables. Without `TS_CIS_ACTION` set, all stacks are visible so the project
  stays introspectable.
- **`SKIPPED` is not `PASS`.** Controls that `cis apply` enforces but the
  provider cannot read back are reported as `SKIPPED` with the reason attached,
  never as a pass.

---

## Known limitations & roadmap

What is deliberately out of scope today, and where the leverage is if you pick
this up again:

- **Coverage is the ceiling.** 39/91 remediable and 20/91 detectable. Several
  `MANUAL` controls are manual only because we have not wired up the
  corresponding provider data source, not because the provider lacks one — the
  `audit/data.tf` gating pattern is the template. Moving a control from manual to
  detectable is the single highest-value contribution.
- **No drift / baseline tracking.** `cis scan` is point-in-time. A `cis scan
  --baseline save` + `compare` for change-over-time is the natural next feature
  for real compliance cadence.
- **No post-apply verification.** `apply` does not re-run `scan` to assert the
  control flipped to PASS. A `cis verify` subcommand would close that loop.
- **A failing stack stops the run.** There is no `--continue-on-error`; the
  current behaviour is intentional (attribution over throughput) but a flag would
  help in large runs.
- **Local state by default.** `config/terraform/backend.tf` notes the COS remote
  backend switch for anything beyond a single operator.
- **`region` defaults to `ap-guangzhou`.** It is only ever a default, never
  hardcoded into logic, but for a compliance tool a wrong-region run is dangerous
  — consider failing loudly when `TENCENTCLOUD_REGION` is unset.

