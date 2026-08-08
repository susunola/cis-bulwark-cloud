<p align="center">
  <img src="https://cdn.jsdelivr.net/gh/susunola/cis-bulwark-cloud@2c345c2/docs/logo-full.png" alt="cis-bulwark-cloud — SecX Series" width="640">
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/benchmark-v1.0.0-006EFF" alt="Benchmark v1.0.0">
  <img src="https://img.shields.io/badge/ruby-3.1%2B-CC342D?logo=ruby&logoColor=white" alt="Ruby 3.1+">
  <img src="https://img.shields.io/badge/terraform-1.6%2B-7B42BC?logo=terraform&logoColor=white" alt="Terraform 1.6+">
  <img src="https://img.shields.io/badge/provider-tencentcloud-0052D9" alt="Tencent Cloud Provider">
  <a href="https://github.com/susunola/cis-bulwark-cloud/actions/workflows/ci.yml"><img src="https://github.com/susunola/cis-bulwark-cloud/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
</p>

# cis-bulwark-cloud

Terraform and Terraspace implementations of the **CIS Tencent Cloud Foundation Benchmark v1.0.0**.

Two variants are provided in the same repository:

| | `terraspace/` | `terraform/` |
|---|---|---|
| Orchestrator | Terraspace | Terraform CLI |
| Stack layout | One project, shared provider | Self-contained root modules |
| State backend | `config/terraform/backend.tf` | `stacks/<name>/backend.tf` |
| Entry point | `terraspace/bin/cis` | `terraform/bin/cis` |

Both share `config/controls.yml`, the modules under `modules/`, the CLI code under `lib/cis/`, and the HTML report format.

## Quick start

Run the offline test suite:

```bash
# Terraform (plain)
cd terraform
ruby test/run.rb

# Terraspace
cd terraspace
ruby test/run.rb
```

Real account (Terraform variant):

```bash
cd terraform
export TENCENTCLOUD_SECRET_ID=...
export TENCENTCLOUD_SECRET_KEY=...
export TENCENTCLOUD_REGION=ap-guangzhou

bin/cis list
bin/cis scan --format html --output scan-report.html
bin/cis apply --report hardening.html
```

## Repository layout

```
cis-bulwark-cloud/
├── modules/             # Reusable Terraform modules
├── lib/cis/             # Shared Ruby CLI code (runner varies by variant)
├── config/              # Shared control registry
├── tools/               # Shared catalog + generator
├── terraspace/          # Terraspace variant
│   ├── app/stacks/      # 6 hardening stacks + audit
│   ├── lib/cis/runner.rb
│   ├── bin/cis          # Entry point
│   └── test/            # Offline tests
│
├── terraform/           # Plain Terraform variant
│   ├── stacks/          # Self-contained root modules
│   ├── lib/cis/runner.rb
│   ├── bin/cis          # Entry point
│   └── test/            # Offline tests
│
└── LICENSE              # MIT
```

## Commands

| Command | Purpose |
|---|---|
| `cis list` | List controls |
| `cis scan` | Read-only assessment via the `audit` stack |
| `cis plan` | Preview what `apply` would change |
| `cis apply` | Enforce controls |
| `cis destroy STACK` | Tear down a single hardening stack |

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

## Reports

`cis scan` and `cis apply` produce self-contained HTML reports with an account header, summary statistics, per-section tables, and a client-side filter bar. No external assets are loaded.

## License

MIT — see [LICENSE](LICENSE).
