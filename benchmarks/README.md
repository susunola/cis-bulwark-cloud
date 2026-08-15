# Benchmarks

Machine-readable control catalogs (`catalog.json`) extracted from each CIS
benchmark Summary Table, one per cloud.

> **Note:** The CIS benchmark **PDFs are not redistributed in this repository**.
> They are &copy; The Center for Internet Security, Inc. and may not be posted
> on websites per the CIS Security Benchmarks Terms of Use. Obtain them from
> [cisecurity.org](https://www.cisecurity.org) under their terms, then run the
> extractor locally to regenerate the catalogs.

| Cloud | Benchmark | Version | Controls |
|---|---|---|---|
| Tencent Cloud | CIS Tencent Cloud Enterprise Foundation Benchmark | v1.0.0 | 91 |
| Amazon Web Services | CIS Amazon Web Services Foundations Benchmark | v7.0.0 | 64 |
| Alibaba Cloud | CIS Alibaba Cloud Foundation Benchmark | v2.0.0 | 78 |
| Google Cloud Platform | CIS Google Cloud Platform Foundation Benchmark | v5.0.0 | 84 |
| Microsoft Azure | CIS Microsoft Azure Foundations Benchmark | v6.0.0 | 70 |

Regenerate the catalogs from locally-downloaded PDFs:

```bash
pdftotext -layout benchmarks/<cloud>/<file>.pdf /tmp/<cloud>.txt
python3 tools/extract_benchmark.py --txt <cloud> /tmp/<cloud>.txt   # one cloud
python3 tools/extract_benchmark.py                                  # all clouds
```

The extractor re-joins hyphenated line breaks, strips checkbox glyphs, and
fails loudly (`exit 1`) on any structural problem — duplicate ids, section
gaps, out-of-enum assessment/profile, or title residue. `test/benchmarks_test.rb`
guards every committed `catalog.json` against the same rules.

Only the Tencent Cloud catalog feeds `config/controls.yml` today (via
`tools/generate_controls.py`); the other four are published as reference
catalogs for upcoming provider mappings.
