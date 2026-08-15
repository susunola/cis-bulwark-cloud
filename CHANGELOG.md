# Changelog

本项目所有值得注意的变更都会记录在此文件中。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

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
