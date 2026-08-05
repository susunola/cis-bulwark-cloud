<p align="center">
  <a href="https://github.com/susunola/cis-tencentcloud/actions/workflows/ci.yml"><img src="https://github.com/susunola/cis-tencentcloud/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="../LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License"></a>
  <a href="#"><img src="https://img.shields.io/badge/benchmark-CIS%20Foundation%20v1.0.0-0052d9" alt="CIS Foundation v1.0.0"></a>
  <a href="#"><img src="https://img.shields.io/badge/ruby-%3E%3D%203.1-cc342d" alt="Ruby >= 3.1"></a>
  <a href="#"><img src="https://img.shields.io/badge/terraform-%3E%3D%201.5.0-7b42bc" alt="Terraform >= 1.5.0"></a>
</p>

# cis-tencentcloud — Terraform Version

Scan and enforce the CIS Tencent Cloud Foundation Benchmark v1.0.0 using plain
Terraform CLI. Each stack is a self-contained root module — no Terraspace required.

This is the plain Terraform version. See the [Terraspace version](../terraspace) if you prefer.

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
