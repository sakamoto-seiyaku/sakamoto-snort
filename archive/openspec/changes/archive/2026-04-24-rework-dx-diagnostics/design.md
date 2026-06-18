## Context

在 `rework-dx-smoke` 之后，DX 真机 `smoke` 的 active 入口已经收敛为 `dx-smoke*` 且严格走 `vNext` 控制面（`60607 + sucre-snort-ctl`）。但 diagnostics 仍处于“入口/目录/协议混杂”的状态：

- `tests/integration/perf-network-load.sh` 仍走 legacy 文本协议（`PERFMETRICS/METRICS.PERF*`），且入口名/labels 还停留在旧 baseline 语义。
- IP 真机测试模组（`tests/device-modules/ip/`）的 diagnostics profiles（`perf/matrix/stress/longrun`）仍依赖 legacy 文本协议（`send_cmd`），与“active 体系一律 vNext”不一致。
- legacy-only 能力（冻结项、旧 HOSTS 缓存等）与 diagnostics 断言混在一起，导致后续很难判断“到底是缺 vNext surface，还是测试设计问题”。

本 change 以 `docs/testing/DEVICE_TEST_REORGANIZATION_CHARTER.md` 的原则为上位约束：active 只保留 `smoke/diagnostics` 两类，且 active 主线一律使用 `vNext`；legacy/compat 只允许作为迁移源/归档材料存在（索引可见、按需回查、默认不运行）。

## Goals / Non-Goals

**Goals:**

- 收敛 DX diagnostics 的对外入口（`CTest/VS Code Testing` 可发现）：`dx-diagnostics` 与 `dx-diagnostics-perf-network-load`。
- diagnostics 的默认执行链路严格 `vNext-only`：脚本不再依赖 `PERFMETRICS/METRICS.PERF*` 或任何 `send_cmd` 文本协议命令。
- 目录一步到位：把 diagnostics 与 IP 真机测试模组移动到最终位置，不保留兼容 wrapper/旧路径别名。
- 明确 legacy-only 覆盖的处置规则：若无 `vNext` 等价 surface，则从 active diagnostics 中移出，进入 archive/迁移源，并在索引中保留可见性。

**Non-Goals:**

- 不引入新的产品功能（daemon 行为/协议扩展不是本 change 目标；若发现缺 vNext surface，优先调整测试口径或归档 legacy-only 断言）。
- 不把 diagnostics 变成硬 gate（不设性能阈值 gate；只做形态/增长/一致性断言与记录）。
- 不在本 change 内重新设计 diagnostics 的最终“细分体系”（当前只要求入口归位 + vNext 化 + 目录归位）。

## Decisions

### D1. 对外入口只暴露 2 个（减少噪声）

选择：
- 暴露 `dx-diagnostics`（总入口）与 `dx-diagnostics-perf-network-load`（当前最稳定、可独立运行的 diagnostics 子入口）。

理由：
- diagnostics 的脚本可能很多（IP 模组 perf/matrix/stress/longrun 等），但现阶段更重要的是先建立“稳定锚点 + 可发现性 + vNext-only”的体系骨架。
- 避免把大量非稳定/高成本用例直接注册到 `CTest/VS Code Testing` 造成日常噪声；更重的 diagnostics 仍可通过脚本路径显式点名运行。

备选方案：
- 多入口全部暴露：可过滤但过于嘈杂；且会把“迁移期尚未完全稳定”的脚本直接推给用户。

### D2. diagnostics 一律 vNext-only（禁止回退 legacy）

选择：
- `perf-network-load` 使用 `CONFIG.SET(perfmetrics.enabled)` 与 `METRICS.GET/RESET(name=perf)`。
- IP 模组 diagnostics profiles 全量迁移为 `60607 + sucre-snort-ctl`，统一使用 `RESETALL/CONFIG/METRICS/IPRULES/STREAM/IFACES` vNext surface。

理由：
- 重组的目的就是完成 active 体系的 `vNext` 收敛；如果 diagnostics 继续允许 legacy 回退，会把“协议迁移成本”永久延后。
- 仓库已经具备必要的 vNext surface（`CONFIG.*`、`METRICS.*`、`IFACES.LIST`、`IPRULES.*`、`STREAM.*`）；足以承载 diagnostics 的核心断言。

备选方案：
- 保留 legacy 路径作为默认：短期省事，但会让“迁移源/归档”边界再次模糊。

### D3. 目录移动一步到位（不保留兼容 wrapper）

选择：
- 新建 `tests/device/diagnostics/` 并将 `perf-network-load` 迁入，旧路径不再保留。
- 将 `tests/device-modules/ip/` 整体迁移到 `tests/device/ip/`，统一其定位为“真机测试模组”（而不是 integration lane 的附属）。

理由：
- 兼容 wrapper 会让旧入口在日常路径里继续“看起来可用”，从而持续消耗维护成本。
- 本仓库的重组原则已经明确：active/迁移源/archive 的可见性依赖索引与 labels，不依赖“旧路径仍可跑”。

风险对冲：
- 通过更新 `CMakeLists.txt`、`docs/testing/*` 与 `docs/IMPLEMENTATION_ROADMAP.md`，确保新的入口与路径在一处即可找到。

### D4. 统一在脚本层抽一套 vNext helper（降低迁移成本）

选择：
- 在 `tests/device/ip/` 内引入共享 helper（例如 `vnext_lib.sh`），封装：
  - `find_snort_ctl` / `ctl_cmd`
  - `CONFIG.SET/GET`、`METRICS.GET/RESET`、`IFACES.LIST`
  - `IPRULES.APPLY` 返回的 `{clientRuleId -> ruleId}` 映射解析
  - `STREAM.START` 采样（`--follow --max-frames`）与断言辅助

理由：
- IP 模组现有 case 数量多，逐文件重复复制 `ctl_cmd/json_get` 会快速失控。
- vNext envelope（`ok/result/error`）需要统一解析口径，否则断言会碎片化。

### D5. legacy-only 覆盖的处置规则：无 vNext surface 则归档/迁移源

选择：
- 若某断言依赖 legacy-only 命令（例如冻结项或 HOSTS 缓存），且当前没有等价 vNext surface，则从 active diagnostics 中移出：
  - 进入 `tests/archive/device/`（物理归档），并在 `DEVICE_TEST_REORGANIZATION_CHARTER.md` / 索引中注明“仅回查”。

理由：
- 本 change 的目标是“active vNext-only”；让测试回退 legacy 会把迁移难点继续留在主路径。

## Risks / Trade-offs

- [网络不稳定导致 perf-network-load 波动/不可达] → 保留明确 `SKIP` 语义（离线/URL 不可达/缺 downloader），并在 `CTest` 侧用 `SKIP_REGULAR_EXPRESSION` 识别；不引入性能阈值 gate。
- [目录一步到位会破坏旧命令/脚本路径] → 所有入口以 `CTest` 名称与文档索引为准；更新 `docs/testing/README.md`、`tests/integration/README.md`、`docs/IMPLEMENTATION_ROADMAP.md`，确保新入口一处可查。
- [vNext IPRULES.APPLY payload 可能过大] → 现有 vNext 限制为 `16MiB`（`Settings::controlVNextMaxRequestBytes`），足以承载当前 2k/4k 规模 ruleset；若未来扩大规模，再考虑分批 apply（不在本 change 内提前实现）。
- [迁移 IP 模组会牵连 dx-smoke-datapath] → 在同一 change 内同步更新 `dx-smoke-datapath` wrapper 的路径引用，保持 smoke gate 不被破坏。
