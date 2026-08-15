# cis-cloud QA / Test Plan

Covers the suite added by the "industry borrowings" work (P0→P2): remediation
guidance, drift detection, risk score, structured resource, richer custom
ruleset, canonical schema, and the MCP surface — on top of the pre-existing
registry/wiring/CLI suite.

Run everything offline (no cloud, no credentials):

```bash
pytest test_py -q          # full suite
pytest test_py/test_drift.py -q   # one new feature file
```

CI runs `pytest test_py -q` on every push/PR (`.github/workflows/ci.yml`), then
offline `terraform validate` and SARIF upload.

---

## 1. Scope & baseline

| | Value |
|---|---|
| Suite size (pre-work) | 251 tests |
| Suite size (after P0→P2) | **284 tests** (+33) |
| Suite size (gaps closed) | **300 tests** (+16) |
| Runtime | ~8 s, fully offline |
| New feature files | `test_drift.py`, `test_schema.py`, `test_mcp.py` |
| Extended files | `test_features.py`, `test_runner.py`, `test_cli.py`, `test_wiring.py` |

---

## 2. Test matrix (by feature)

### 2.1 Remediation guidance (P0) — `cis_cloud/remediation.py` + `data/config/remediation.yml`

| # | Case | Assertion | Status |
|---|---|---|---|
| R1 | exact control id rule | `for_control("tencent", ctl4.1)` returns the COS/ACL text | ✅ `test_features.py` |
| R2 | glob rule match | `for_control("tencent", ctl5.6)` hits the `5.*` rule | ✅ |
| R3 | reference URL | `reference_for` returns the console URL | ✅ |
| R4 | unknown cloud → generic fallback | returns manual "verify in console" | ✅ |
| R5 | remediable control → apply hint | mentions `cis-cloud apply` + stack | ✅ |
| R6 | attached to scan findings | `_with_severity` adds `remediation` | ✅ |
| R7 | **rule file lint** | `remediation.yml` parses and every remediable/detectable control resolves to *some* remediation | ✅ |
| R8 | HTML scan report renders fix | `_scan_html` contains the `fix:` text | ✅ |
| R9 | markdown column | `_scan_markdown` emits a Remediation column | ✅ |

### 2.2 Drift detection (P0) — `cis_cloud/drift.py` + `check-drift` command

| # | Case | Assertion | Status |
|---|---|---|---|
| D1 | regression detected | PASS→FAIL appears in `regressions`, exit 1 | ✅ `test_drift.py` |
| D2 | clean (no new fail) | no regressions, exit 0 | ✅ |
| D3 | new failing control counts | a previously-absent id now FAILing is a regression | ✅ |
| D4 | still-failing not counted | persistent FAIL not a regression | ✅ |
| D5 | offline CLI (two paths) | `check-drift BASE CUR` → exit 1 + stdout | ✅ |
| D6 | live `--baseline` (FakeRunner) | runs a scan, flags regression | ✅ `test_runner.py` |
| D7 | render JSON | `render_drift(..., "json")` parseable | ✅ |
| D8 | missing baseline file | clear error, exit 2 | ✅ |
| D9 | `--baseline` CLI end-to-end | subprocess `check-drift --baseline base.json` | ✅ |

### 2.3 Risk score (P1) — `cis_cloud/severity.py`

| # | Case | Assertion | Status |
|---|---|---|---|
| S1 | severity→score map | critical=100 … low=10, unknown→low | ✅ `test_features.py` |
| S2 | `weighted()` FAIL-only | sums only FAIL severity weights | ✅ |
| S3 | finding carries score | `_with_severity` sets `score` | ✅ |
| S4 | **compliance risk_score value** | `Compliance.global_()["risk_score"]` equals the weighted FAIL sum | ✅ |
| S5 | table SCORE column | `_scan_table` renders a SCORE header + values | ✅ |

### 2.4 Structured resource (P1) — `cis_cloud/runner.py` / `suppress.py`

| # | Case | Assertion | Status |
|---|---|---|---|
| RC1 | from `evidence_detail[].resource` | `_normalize` sets `resource` | ✅ `test_runner.py` |
| RC2 | from top-level `resource` | falls back to row field | ✅ |
| RC3 | absent → `""` | empty string, no crash | ✅ |
| RC4 | suppression via structured resource | rule matches `f["resource"]` | ✅ `test_features.py` |
| RC5 | reporter table RESOURCE column | header appears when any finding has a resource | ✅ |
| RC6 | csv column | `_scan_csv` header includes resource | ✅ |

### 2.5 Richer custom ruleset (P1) — `cis_cloud/tfcheck.py`

| # | Case | Assertion | Status |
|---|---|---|---|
| C1 | load metadata | `--checks` rule title/severity/remediation/framework parsed | ✅ `test_features.py` |
| C2 | reject bad severity | non-LEVELS severity → `ValueError` | ✅ |
| C3 | scan uses metadata | finding carries custom title/severity/remediation | ✅ |
| C4 | reject non-string metadata | e.g. numeric `title` → `ValueError` | ✅ |
| C5 | framework passthrough | rule `framework` exposed on `tfcheck.Finding` + `to_dict` | ✅ |

### 2.6 Canonical schema (P2) — `cis_cloud/schema.py`

| # | Case | Assertion | Status |
|---|---|---|---|
| SC1 | fills all keys | `normalize_finding` returns every `FINDING_KEYS` | ✅ `test_schema.py` |
| SC2 | preserves values | existing severity/score/resource pass through | ✅ |
| SC3 | unknown severity→low | falls back to low + score 10 | ✅ |
| SC4 | derives score | missing score filled from severity | ✅ |
| SC5 | constants | `STATUSES`/`SEVERITIES` shape | ✅ |
| SC6 | **cross-command key parity** | a scan, check and compliance finding each carry `FINDING_KEYS` | ✅ |

### 2.7 MCP surface (P2) — `cis_cloud/mcp.py`

| # | Case | Assertion | Status |
|---|---|---|---|
| M1 | `tools/list` | returns the 5 tools | ✅ `test_mcp.py` |
| M2 | `tools/call` list | returns controls + summary | ✅ |
| M3 | `tools/call` scan (dry-run) | returns detectable ids | ✅ |
| M4 | unknown tool | JSON-RPC `-32601` error | ✅ |
| M5 | stdio round-trip | two requests → two responses | ✅ |
| M6 | malformed line | `-32700` parse error | ✅ |
| M7 | initialize handshake | `initialize` returns capabilities | ✅ |
| M8 | tool error surfaces | `tools/call` `diff` with a missing file → `-32603` | ✅ |

---

## 3. Gap-coverage tests (all now landed)

All 16 gap tests from the original plan are implemented and green. Summary:

1. **R7** — `test_remediation_every_control_resolves`: lints `remediation.yml`,
   asserting every control across all 5 clouds resolves to non-empty
   remediation (exact/glob/fallback).
2. **R3** — `test_remediation_reference_url`; **R8/R9** —
   `test_scan_html_renders_remediation_fix` / `test_scan_markdown_renders_remediation_column`.
3. **S4** — `test_compliance_risk_score_value`; **S5/RC5/RC6** —
   `test_scan_table_shows_score_column`, `test_scan_table_shows_resource_column_only_when_present`,
   `test_scan_csv_has_resource_column`.
4. **D7/D8/D9** — `test_render_drift_json_is_parseable`,
   `test_check_drift_missing_baseline_exits_two`,
   `test_check_drift_baseline_flag_parses_and_errors_cleanly`.
5. **C4/C5** — `test_load_checks_rejects_non_string_metadata`,
   `test_scan_passes_framework_through` (adds `framework` to `tfcheck.Finding`).
6. **SC6** — `test_scan_check_compliance_findings_all_carry_schema_keys`.
7. **M7/M8** — `test_initialize_handshake`, `test_tools_call_diff_missing_file_surfaces_error`.

All are cheap, offline unit tests — no cloud calls.

---

## 4. Execution & CI

```bash
# local, fast, offline
pytest test_py -q

# a single feature area
pytest test_py/test_drift.py -q
pytest test_py/test_mcp.py -q
pytest test_py/test_schema.py -q

# targeted regression (shared runner/reporter/schema touched by 2.3/2.4/2.6)
pytest test_py/test_runner.py test_py/test_features.py -q
```

CI (`.github/workflows/ci.yml`) runs the whole suite on Ubuntu + Python 3.11 +
Terraform 1.5.7, then offline `terraform validate` on every module/stack, then
uploads the `cis-cloud check` SARIF to GitHub Code Scanning.

### E2E layer — `scripts/e2e_test.py`

Above the fast unit suite sits a real-command end-to-end script:

- **`--mode offline`** (default, no credentials): runs the actual installed CLI
  end-to-end — `list`, `scan --dry-run`, `plan --dry-run`, `check --tf`,
  `mcp tools/list`, `diff` and `check-drift` — and asserts exit codes + output
  shape. Catches real-command wiring bugs the mocked unit suite misses.
- **`--mode live`** (opt-in, needs a real account): drives a real
  `scan` → baseline → `check-drift` → guarded `apply` → re-`scan` cycle, and
  always `destroy`s the hardening stacks it applied (unless `--keep-on-failure`
  and the run failed).

```bash
python3 scripts/e2e_test.py --mode offline              # fast, no creds
python3 scripts/e2e_test.py --mode live --cloud aws --only 6.1.1   # real account
```

## 5. Sign-off gate

- `pytest test_py -q` → **300 green** (all existing + all new).
- No cloud, no credentials, no `terraform` execution in any unit test
  (CLI tests use `--dry-run` / FakeRunner / direct module calls).
- Every feature covers its full matrix from §2; the §3 gap tests are landed.
