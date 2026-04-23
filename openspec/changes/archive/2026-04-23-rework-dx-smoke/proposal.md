## Why

当前 `Device / DX` 真机测试入口仍混杂历史 `p1/p2/ip-smoke` 命名与 `vNext` 主线脚本，且 `smoke / diagnostics / 迁移源` 未系统分轨，导致 gate 语义不清、入口难记、VS Code Testing 分组不可用。

在 domain 真机覆盖与 perf/latency 路径已经“可跑”的前提下，本阶段的关键问题已从“缺不缺用例”转为“如何把 active `smoke` 收敛为可持续的 `vNext` 主入口”。

上一轮实现只完成了 `dx-smoke` 的入口骨架与最小闭环；这不足以视为 “smoke 转换完成”。本 change 的范围需要修正为：**不仅建立入口，还要把旧 smoke 入口中仍属于主功能 gate 的覆盖责任迁入 active `vNext` smoke**。否则 legacy 脚本虽然被标为迁移源，但覆盖责任实际仍未被接住。

## What Changes

- 收敛并标准化 active `smoke` 主入口：`dx-smoke`（总入口）+ `dx-smoke-platform` / `dx-smoke-control` / `dx-smoke-datapath`（固定顺序 `platform -> control -> datapath`，fail-fast，且区分 `PASS/FAIL/BLOCKED`）。
- 完成 `smoke` 覆盖责任迁移，而不是只保留最小集合：
  - `dx-smoke-control` 必须承接旧 baseline/full-smoke 中仍属于主功能 gate 的 vNext 控制面责任，尤其是 domain surface、domainSources 行为、metrics、stream 与 reset 语义。
  - `dx-smoke-datapath` 必须承接旧 IP smoke 中仍属于主功能 gate 的 datapath 责任，至少覆盖真实 Tier-1 流量下的 allow/drop/would-match、IFACE_BLOCK、BLOCK=0 bypass、reason metrics 与 per-rule stats。
  - `tests/device-modules/ip/run.sh --profile smoke` 必须成为 active vNext smoke profile；不得继续默认执行 legacy/mixed smoke case。
- **BREAKING**：移除/重命名现存 `p1/p2/ip-smoke` 等历史 `CTest` label/入口展示；不再提供长期 alias（迁移期仅保留“迁移源按需回查”入口）。
- 明确 legacy 脚本的迁移源可见性规则与归档硬门槛：未被 `vNext` 接住覆盖责任的 legacy 入口禁止归档；迁移源不得进入默认 `dx-smoke` 入口与主 quick start。
- 本 change 只处理 `smoke` 主线收敛；`diagnostics` 的归位与命名收敛由后续独立 change 处理（见路线图）。

## Capabilities

### New Capabilities

- `dx-smoke-workflow`: 定义 DX 真机 `smoke` 的主入口命名、执行顺序、gate 语义、迁移源/归档约束，以及 `CTest`/VS Code Testing 的分组与展示规则。

### Modified Capabilities

（无）

## Impact

- `tests/integration/CMakeLists.txt`：DX 相关 `CTest` tests/labels 需要重命名与重新分组。
- `tests/integration/*.sh`、`tests/device-modules/**`：`smoke` 主线入口将收敛到 `vNext`，legacy 脚本将转为迁移源或满足条件后归档；若现有 active smoke 缺少 vNext 等价能力，本 change 必须补齐对应测试入口或明确新增 DEV-only vNext test seam。
- `docs/testing/*` 与 `docs/IMPLEMENTATION_ROADMAP.md`：补齐并持续维护“DX 测试重组纲领 + 主入口索引 + 迁移源可见性规则”。
- CI/本地开发工作流：若依赖旧 `p1/p2/ip-smoke` label，需要同步更新（本 change 明确以新入口为准）。
