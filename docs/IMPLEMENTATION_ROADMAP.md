# 当前实现 Roadmap（P0/P1）

更新时间：2026-03-12  
状态：当前共识；自 2026-03-12 起，功能主线实现暂缓，优先补齐 `debug / test` 工程化基础；若后续调整顺序，必须同步更新本文件、`AGENTS.md` 与相关权威文档。

## 1. 当前最高优先级

当前主线优先级调整为：

`Debug 基础设施 → Host-side 单元测试 → Host-driven 集成测试 → 真机/模拟器调试验证 → 恢复功能主线（A → IP rules core → C → B）`

- 这次调整意味着：此前围绕 `A / IP rules core / C / B` 的实现任务暂时中断。
- 只有**直接服务于 debug / test lane 落地**的工作，才应在当前阶段插队进入主线。
- 关于当前测试/调试路线、边界与官方依据，以 `docs/NATIVE_DEBUGGING_AND_TESTING.md` 为权威补充文档。

## 2. 当前阶段顺序与边界

- `Debug 基础设施`
  - 打通 `lldbclient.py` 的 CLI attach / run-under-debugger。
  - 打通 `VS Code WSL2 + CodeLLDB` 图形化断点调试。
  - 固化 `tombstone / stack / debuggerd.wait_for_debugger` 的 crash 定位流程。
  - 视需要补充 dev-only debug build 选项与 sanitizer lane。
- `Host-side 单元测试`
  - 目标是尽快挡住低级回归，而不是追求“大而全覆盖”。
  - 优先选择低耦合、高价值模块；不为了测试做大重构。
  - 仅在必要处允许增加小型 seam / helper，但不得把当前阶段演化成架构重写。
- `Host-driven 集成测试`
  - 测试代码运行在 host / WSL，目标环境优先 Android device / emulator。
  - 优先复用并演进现有 `dev/dev-smoke.sh` 与相关脚本，而不是另起一套完全独立流程。
  - 这一层是当前最重要的自动化回归抓手。
- `真机/模拟器调试验证`
  - 模拟器 / 虚拟设备优先承担启动期、控制面、线程/锁类问题的快速定位。
  - 真机继续承担 `NFQUEUE / iptables / netd / SELinux / 性能` 等强平台耦合问题的最终验证。

## 3. 为什么现在先做 debug / test

- 当前最大瓶颈不是 spec 不清，而是**开发与定位效率不足**。
- 若继续直接推进 `A / IP rules core / C / B`，会持续放大“只能看 log 反推”的成本。
- `Host-driven integration tests` 与当前开发循环最接近，投入产出比最高。
- 单元测试不是唯一目标，但它能以较低成本挡住一批解析、规则、统计类回归。
- 先补齐 debug / test lane，后续功能主线的实现、回归与排障效率都会显著提高。

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
- `docs/NATIVE_DEBUGGING_AND_TESTING.md` 已建立并成为当前测试/调试主线的权威补充文档。
- 当前实现优先级已正式切换：先补齐 debug / test 工程化基础，再恢复 A/B/C 与 IP 规则主线实现。
