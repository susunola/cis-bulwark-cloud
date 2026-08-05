# cis-tencentcloud

Terraform and Terraspace implementations of the **CIS Tencent Cloud Foundation Benchmark v1.0.0**.

Two variants are provided in the same repository:

| | `terraspace/` | `terraform/` |
|---|---|---|
| Orchestrator | Terraspace | Terraform CLI |
| Stack layout | One project, shared provider | Self-contained root modules |
| State backend | `config/terraform/backend.tf` | `stacks/<name>/backend.tf` |
| Entry point | `terraspace/bin/cis` | `terraform/bin/cis` |

Both share `config/controls.yml`, the modules under `modules/` / `app/modules/`, the CLI flags, and the HTML report format.

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
cis-tencentcloud/
├── terraspace/          # Terraspace variant
│   ├── app/stacks/      # 6 hardening stacks + audit
│   ├── app/modules/     # Reusable Terraform modules
│   ├── lib/cis/         # Ruby CLI + reporter
│   ├── bin/cis          # Entry point
│   └── test/            # Offline tests
│
├── terraform/           # Plain Terraform variant
│   ├── stacks/          # Self-contained root modules
│   ├── modules/         # Reusable Terraform modules
│   ├── lib/cis/         # Ruby CLI + reporter
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
