## Why

vNext control 已经落地并逐步覆盖 Domain/IPRULES/Metrics/Stream 等 surface，但 legacy control（`sucre-snort-control` / `60606`）仍会被脚本/调试工具误连与依赖；同时 `BLOCKIPLEAKS/GETBLACKIPS/MAXAGEIP` 等历史模块在当前融合阶段已裁决为“冻结并强制关闭（无作用）”，若仍可被设置/落盘/restore 改写，会直接破坏既定的仲裁与可观测心智模型。

本 change 的目的，是把“迁移期的固定语义”真正落到 daemon + tooling + tests 上，避免回归与文档继续漂移。

## What Changes

- Daemon：将以下 legacy 冻结项收口为**全局固定语义**（无论通过 legacy/vNext 控制面、历史落盘或 restore，都不可改写）：
  - `BLOCKIPLEAKS`：强制关闭（查询恒为 `0`；设置 `OK` 但无效果）
  - `GETBLACKIPS`：强制 `0`（查询恒为 `0`；设置 `OK` 但无效果）
  - `MAXAGEIP`：固定为默认值 `14400`（查询恒为 `14400`；设置 `OK` 但无效果）
- Legacy `HELP`：显式标注上述冻结项为 frozen/no-op，并提示 vNext 端点与推荐工具（`sucre-snort-ctl` / `sucre-snort-control-vnext` / `60607`）。
- Repo scripts/tests：收敛并明确 legacy lane vs vNext lane：
  - 公共 helper 不再隐式绑定 `60606` 文本协议；需要显式选择 lane 或提供 vNext helper。
  - 更新仍把冻结项当“可调能力”的 integration/device-module 回归用例，改为验证 fixed/no-op 语义；保留必要的 legacy 对照 lane。
- 文档：更新接口与测试模组文档，使冻结项不再被描述为可调能力。

## Capabilities

### New Capabilities
- `control-transition-surface`: 定义迁移期 legacy 冻结项（`BLOCKIPLEAKS/GETBLACKIPS/MAXAGEIP`）的固定/no-op 语义、以及 legacy HELP 的冻结提示要求。

### Modified Capabilities
- (none)

## Impact

- Affected code: `src/Settings.*`, `src/Control.cpp`（legacy HELP 与冻结项命令行为）、以及依赖这些 settings 的路径（`DnsListener`, `PacketManager` 等）。
- Affected scripts/tests: `tests/integration/*`, `tests/device-modules/ip/*`, `dev/*`（control lane 分轨与断言口径调整）。
- Affected docs: `docs/INTERFACE_SPECIFICATION.md`, `docs/testing/ip/IP_TEST_MODULE.md`（冻结项口径与提示）。

