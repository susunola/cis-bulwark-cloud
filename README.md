<p align="center">
  <img src="https://img.shields.io/github/actions/workflow/status/susunola/cis-tencentcloud/ci.yml?branch=main&label=ci" alt="CI">
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT License">
  <img src="https://img.shields.io/badge/benchmark-CIS%20Foundation%20v1.0.0-7B68EE" alt="CIS v1.0.0">
  <img src="https://img.shields.io/badge/ruby-%E2%89%A53.1-CC342D" alt="Ruby ≥3.1">
  <img src="https://img.shields.io/badge/terraform-%E2%89%A51.5.0-7B42BC" alt="Terraform ≥1.5.0">
</p>

# cis-tencentcloud

Scan and enforce the **CIS Tencent Cloud Foundation Benchmark v1.0.0** (91 controls
across 9 sections). Read-only assessment, automated hardening, and HTML compliance
reports — no external services, no agent install.

Two delivery formats so you can pick the shape that fits your workflow:

| | `terraspace/` | `terraform/` |
|---|---|---|
| **Orchestrator** | Terraspace | Terraform CLI |
| **How stacks work** | One Terraspace project, stacks share a provider | Each stack is a self-contained root module |
| **State** | Injected via `config/terraform/backend.tf` | Per-stack `stacks/<name>/backend.tf` |
| **Best for** | Teams already on Terraspace; stacked environments | Generic Terraform pipelines; scriptable CI |
| **Entry point** | `terraspace/bin/cis` | `terraform/bin/cis` |
| **Tests** | 141 runs / 1569 assertions | 139 runs / 1526 assertions |

Both versions share the same registry (`config/controls.yml`), the same Terraform
modules, the same CLI flag vocabulary, and the same HTML report format.

---

## Quick Start

Pick your version:

```bash
# Terraform (plain)
cd terraform
ruby test/run.rb                    # verify with zero credentials

# Terraspace
cd terraspace
ruby test/run.rb
```

Real account (Terraform version):

```bash
cd terraform
export TENCENTCLOUD_SECRET_ID=...
export TENCENTCLOUD_SECRET_KEY=...
export TENCENTCLOUD_REGION=ap-guangzhou

# See what's selected
bin/cis list

# Scan (read-only)
bin/cis scan --format html --output scan-report.html

# Enforce
bin/cis apply --report hardening.html
```

---

## What's Inside

```
cis-tencentcloud/
├── terraspace/          ← Terraspace version (original)
│   ├── app/stacks/      ← 6 hardening stacks + 1 audit
│   ├── app/modules/     ← Reusable Terraform modules
│   ├── lib/cis/         ← Ruby CLI + reporter
│   ├── bin/cis          ← Entry point
│   └── test/            ← 141 runs, offline
│
├── terraform/           ← Plain Terraform version
│   ├── stacks/          ← Self-contained root modules
│   ├── modules/         ← Same reusable modules
│   ├── lib/cis/         ← Ruby CLI + reporter
│   ├── bin/cis          ← Entry point
│   └── test/            ← 139 runs, offline
│
└── LICENSE              ← MIT
```

---

## Commands (both versions)

| Command | Purpose |
|---|---|
| `cis list` | List controls — table / JSON / markdown / HTML |
| `cis scan` | Read-only assessment via the `audit` stack |
| `cis plan` | Preview what `apply` would change |
| `cis apply` | Enforce controls (apply hardening stacks) |
| `cis destroy STACK` | Tear down a single stack |

### Filters

| Flag | Example |
|---|---|
| `--only ID,GLOB` | `--only "4.1,4.3"` or `--only "4.*"` |
| `--exclude ID,GLOB` | `--exclude 4.6` |
| `--section N` | `--section "1,3,4"` |
| `--tag TAG` | `--tag cos` |
| `--profile LEVEL` | `--profile level1` |
| `--dry-run` | Print what would run, execute nothing |
| `--format FMT` | `table` / `json` / `markdown` / `html` |
| `--output PATH` | Write report to file |
| `--report [PATH]` | HTML hardening report (apply only) |

---

## Reports

Both `cis scan` and `cis apply` produce self-contained HTML reports:

- Account header (UIN, account name, APP ID, region)
- Summary statistics
- Per-section tables with status badges
- Client-side filter bar: Enforced / Not enforced / FAIL / MANUAL / SKIPPED
- Zero external assets — print-friendly, PDF-compatible

---

## Roadmap

- [ ] CIS Enterprise Foundation Benchmark v1.0.0 (68 additional controls)
- [ ] `cis verify` — post-apply scan diff
- [ ] COS remote state backend templates
- [ ] `--continue-on-error` for apply

---

## License

MIT — see [LICENSE](LICENSE).
