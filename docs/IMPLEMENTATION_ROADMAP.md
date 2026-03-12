# 当前实现 Roadmap（P0/P1）

更新时间：2026-03-12  
状态：当前共识；自 2026-03-12 起，功能主线实现暂缓，优先补齐 `debug / test` 工程化基础；若后续调整顺序，必须同步更新本文件、`AGENTS.md` 与相关权威文档。

## 1. 当前最高优先级

当前主线优先级调整为：

`P0 Host-side 单元测试（当前 active change） → P1 Host-driven 集成测试（后续独立 change） → P2 恢复功能主线（A → IP rules core → C → B） → P3 原生 Debug / 真机专项验证（待设备恢复后推进）`

- 这次调整意味着：此前围绕 `A / IP rules core / C / B` 的实现任务暂时中断。
- 只有**直接服务于 debug / test lane 落地**的工作，才应在当前阶段插队进入主线。
- 关于当前测试/调试路线、边界与官方依据，以 `docs/NATIVE_DEBUGGING_AND_TESTING.md` 为权威补充文档。
- 当前仅通过 OpenSpec change `add-host-side-unit-test-foundation` 收敛 **P0 Host-side 单元测试**；在该 change 审核通过前，不进入对应实现。
- `P1 Host-driven 集成测试` 与 `P3 原生 Debug / 真机专项验证` 将在后续分别以独立 change 推进，不并入当前 P0 change。
- 由于设备返修，当前无法落地真机相关 debug / platform validation，因此这部分整体后置到 `P3`。

## 2. 当前阶段顺序与边界

- `P0 Host-side 单元测试`
  - 这是当前 active change。
  - 目标是挡住低级回归，优先覆盖低耦合模块。
  - 本地落地方式采用仓库内置 `gtest`（`CMake + FetchContent` 固定版本），不要求 host 预装 `gtest` 包。
  - 不为了测试做大重构。
- `P1 Host-driven 集成测试`
  - 这是后续独立 change，不属于当前 P0。
  - 测试代码运行在 host / WSL，目标环境优先 Android device 或 emulator。
- `P2 恢复功能主线`
  - 在测试基础可用后，恢复 `A → IP rules core → C → B` 功能实现。
- `P3 原生 Debug / 真机专项验证`
  - 由于设备返修，当前不可落地。
  - 设备恢复后，再推进 LLDB、真机 crash 复盘、`NFQUEUE / iptables / netd / SELinux / 性能` 等平台专项验证。

## 3. 为什么现在先做 debug / test

- 当前最大瓶颈不是 spec 不清，而是**开发与定位效率不足**。
- 若继续直接推进 `A / IP rules core / C / B`，会持续放大“只能看 log 反推”的成本。
- 当前设备不可用，真机相关 debug lane 暂时无法作为起步项。
- 单元测试虽然不是全部目标，但它能以最低外部依赖成本先挡住一批解析、规则、统计类回归。
- 先补齐可在本地推进的测试基础，再恢复功能主线；待设备恢复后，再补原生 debug 与平台专项验证。

## 4. 功能主线的保留顺序（在工程化基础补齐后恢复）

恢复功能主线后，顺序仍保持为：`A → IP rules core → C → B`

- `A`：Packet 可观测性基座
  - `PKTSTREAM` 的 `reasonId/ruleId/wouldRuleId/wouldDrop/ipVersion/srcIp/dstIp`
  - `METRICS.REASONS` / `METRICS.REASONS.RESET`
  - 当前 A 层验收基线按 `BLOCKIPLEAKS=0` 理解；legacy `ip-leak` 细节仍为 TBD
- `IP rules core`：IP 规则主能力
  - 控制面骨架：`IPRULES`、`IPRULES.ADD/UPDATE/REMOVE/ENABLE/PRINT/PREFLIGHT`、`IFACES.PRINT`
  - 数据面骨架：`PacketKeyV4`、preflight、snapshot、classifier、per-thread exact cache
  - 热路径边界：`IFACE_BLOCK` 前置；仅 `NoMatch` 回落到 legacy/domain
- `C`：IP 规则 per-rule runtime stats
  - `IPRULES.PRINT.stats`
  - `hit* / wouldHit*`
  - `UPDATE` 生效后清零；`ENABLE 0→1` 后清零
- `B`：DomainPolicy 常态 counters
  - `METRICS.DOMAIN.SOURCES*`
  - 复用现有 `App::blocked()` 归因顺序
  - 不把 `ip-leak` 混入 B 层口径

## 5. 当前现状

- 纲领仍收敛到 `A / B / C` 三层边界；这些功能文档结论没有被推翻。
- `add-pktstream-observability` 已按当前 A 层基线收敛。
- `add-app-ip-l3l4-rules-engine` 已明确：仅 `NoMatch` 回落 legacy/domain。
- `docs/DOMAIN_POLICY_OBSERVABILITY.md` 继续作为 B 层权威文档。
- `docs/NATIVE_DEBUGGING_AND_TESTING.md` 继续作为未来 P3 原生调试 / 平台专项验证的权威补充文档。
- 当前 active change 已收敛为 `add-host-side-unit-test-foundation`；后续 phases 将继续拆分为独立 changes。
- 当前实现优先级已正式切换：先完成 P0 Host-side 单元测试，再推进 P1 Host-driven 集成测试，随后恢复 A/B/C 与 IP 规则主线；P3 真机 debug 待设备恢复后再落地。
