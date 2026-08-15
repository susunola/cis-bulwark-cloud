# Changelog

本项目所有值得注意的变更都会记录在此文件中。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### Added

- 新增 **SARIF 2.1.0** 输出（`--format sarif`），可接入 GitHub Code Scanning /
  CI 内联 PR 注释。CI 工作流已添加 SARIF 生成与上传步骤。
- 新增 **`diff`** 命令：对比两次 `scan` 的 JSON 结果，报告 新增 / 仍失败 /
  已修复 / 已消失 的控制项，并输出机器可读的汇总。
- **结构化证据**：`tfcheck` 与扫描结果新增 `evidence_detail` 字段
  （`{resource, attribute, expected, actual}`），同时保留原有 `evidence`
  字符串以向后兼容。
- **`--plan-check`**（配合 `--tf`）：`plan` 前先跑静态 tfcheck，命中 FAIL 即
  阻断，把安全左移到 apply 之前。
- **自定义检查**（`--checks FILE`）：加载 YAML 定义的用户规则，合并进内置
  `check` 规则。
- **多框架视图**（`--framework nist|pci|djcp` / `CIS_FRAMEWORK`）：把控制项
  映射到 NIST SP 800-53、PCI DSS v4.0、等保 2.0 等其它合规框架。
  - 框架视角现会标注在 `list` 输出中：table / markdown / html 表头追加
    `— <框架正式标题> view`，JSON 输出新增 `framework` 字段。
- **修复指引**（remediation）：每个 scan 结果都携带 `remediation` 修复建议，
  来自 `config/remediation.yml`（按云 + 控制项 id/glob 派生，含兜底文案），
  在 `--format json`/`markdown` 与 HTML 报告中展示。
- **风险分**（risk score）：每个 finding 带数值 `score`（critical=100…low=10），
  scan 表新增 SCORE 列；compliance 报告按云与全局给出加权 `risk_score` 总量，
  便于把安全态势收敛为单一数字长期跟踪。
- **结构化资源**（structured resource）：finding 新增 `resource` 字段（来源
  有值时记录具体的 bucket/实例/策略），在 scan 报告中展示，并作为更精确的
  suppress 匹配目标。
- **漂移检测**（`check-drift`）：对照基线 scan JSON 与当前 scan，仅报告
  *回归*（基线未失败、现在失败的 control）。`--baseline PATH` 实时对比，
  或离线 `BASE CUR` 两文件对比；有回归即退出码 1，便于 CI 门禁。
- **自定义规则元数据**（policy-as-code）：`--checks FILE` 的自定义规则现可带
  `title`/`severity`/`remediation`/`framework` 元数据，使自有策略以一等控制项
  呈现，而不仅是 resource/args 检查。
- **多账户批量**（`batch --accounts a,b,c --out DIR`）：逐账户扫描并聚合为
  跨账户合规视图；`scan` 新增 `--push DIR` 落盘时间戳 JSON 结果。

### Fixed

- 修复 `terraform fmt` 测试在 Terraform 1.5.x 下失败的问题。
  `terraform fmt` 1.5.x 会把目录参数按固定的 `../..` 偏移解析，传入绝对路径
  会报 `No file or directory`。现改为先 `chdir` 进目标目录再传 `.`。
- 修正 `CIS_CLOUD_ROOT` 环境变量的文档说明。它应指向**数据根**（即 checkout
  中的 `cis_cloud/data`，直接包含 `config/`、`stacks/`、`modules/`），而非
  仓库根目录（仓库根没有这些目录）。

## [0.1.0] - 2026-08-15

### Added

- 用纯 Terraform + 薄 Python 封装实现五个 CIS 基础基线扫描/加固工具：
  Tencent Cloud (v1.0.0, 91 项)、AWS (v7.0.0, 64 项)、Azure (v6.0.0, 70 项)、
  GCP (v5.0.0, 84 项)、Alibaba Cloud (v2.0.0, 78 项)。
- 命令：`list`、`scan`、`plan`、`apply`、`destroy`、`check`（预部署静态检查）、
  `compliance`（跨云汇总）。
- 输出格式：table、json、markdown、html、csv、junit。
- 控制项过滤：`--only` / `--exclude` / `--section` / `--tag` / `--profile`，
  以及对应的 `CIS_*` 环境变量。
- 抑制（suppress）规则：按云/控制项/资源排除，SUPPRESSED 不触发退出码门禁。
- 数据层：benchmarks/ 目录存放从 CIS PDF 提取的 catalog，
  `tools/extract_benchmark.py` 与 `tools/generate_controls.py` 生成并校验控制项注册表。
