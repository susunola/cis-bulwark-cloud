# cis-tencentcloud — Terraform Version

Scan and enforce the CIS Tencent Cloud Foundation Benchmark v1.0.0 using plain
Terraform CLI. Each stack is a self-contained root module — no Terraspace required.

## Quick Start

```bash
# Zero-credentials smoke test (offline)
ruby test/run.rb

# Real scan (read-only)
export TENCENTCLOUD_SECRET_ID=...
export TENCENTCLOUD_SECRET_KEY=...
export TENCENTCLOUD_REGION=ap-guangzhou

cd stacks/audit
terraform init
terraform apply -auto-approve -var 'enabled_controls=["4.1","4.2"]'
terraform output -json cis_findings
```

### Using the CLI wrapper

```bash
bin/cis list                              # what's in scope
bin/cis scan --section 4 --format html    # read-only assessment
bin/cis apply --tag cos --report          # enforce + HTML report
bin/cis destroy storage                   # tear down
```

## Directory Layout

```
terraform/
├── stacks/               ← Self-contained Terraform root modules
│   ├── audit/            ← Read-only assessment stack
│   ├── iam/              ← CIS Section 1
│   ├── logging/          ← CIS Section 2 (CloudAudit, CLS)
│   ├── network/          ← CIS Sections 2.4, 3
│   ├── storage/          ← CIS Section 4 (COS)
│   ├── database/         ← CIS Section 5 (TencentDB)
│   └── kubernetes/       ← CIS Section 6 (TKE)
├── modules/              ← Reusable modules
├── lib/cis/              ← Ruby CLI + report engine
├── bin/cis               ← Entry point
├── config/controls.yml   ← Control registry
├── test/                 ← Offline test suite (no credentials)
└── tools/                ← Catalog extraction scripts
```

## Differences from the Terraspace version

| Feature | Terraspace | Terraform |
|---|---|---|
| Stack isolation | Shared provider config | Self-contained root modules |
| State backend | `config/terraform/backend.tf` | Per-stack `stacks/<name>/backend.tf` |
| Variable wiring | ERB `tfvars/` → automatic | `-var` passed by `bin/cis` |
| `terraform init` | `terraspace` wraps it | Run manually per stack |
| Multi-environment | Terraspace environments | Separate .tfvars files |

Both versions share the same modules, control registry, and HTML report format.
