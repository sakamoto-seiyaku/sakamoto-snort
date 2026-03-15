# 当前实现 Roadmap（Tooling + 功能主线）

更新时间：2026-03-15  
状态：当前共识；本文包含两条不混用阶段号的主线：
- `P0/P1/P2/P3`：只表示 **测试 / 集成验证 / 真机调试** 的工程化顺序；
- `A/B/C/D`：只表示 **可观测性分层**（见 `docs/OBSERVABILITY_WORKING_DECISIONS.md`），不表示测试/调试阶段号。

## 1. 当前主线顺序

`P0 Host-side 单元测试 → P1 Host-driven 集成测试（host / WSL 驱动真机） → P2 真机集成 / smoke / 兼容性验证 → P3 真机原生 Debug / crash / LLDB`

- 这四个 phase 全部围绕 **test / debug / tooling**。
- `P0/P1/P2/P3` 与 `A/B/C/D`、`add-pktstream-observability`、`add-app-ip-l3l4-rules-engine` 没有阶段对应关系。
- `A/B/C` 与 IP rules / DomainPolicy 相关功能，仍作为独立功能主线处理；推荐顺序见第 6 节。
- `D`（性能健康指标层）独立于 `P0 → P3` 与 `A/B/C` 主线排序；其对应 change 可在任意时点单独推进，不影响主线进度。
- 任何以 `P1/P2/P3` 名义推进的工作，都不得顺势夹带产品功能实现；若确需极小的 test seam / debug seam，必须先说明必要性，并把范围压到最小。

## 2. 各阶段定义与边界

- `P0 Host-side 单元测试`
  - 目标：不连设备先挡住一批低耦合回归。
  - 方式：先按现有权威文档 / 设计语义审计 pure-logic 实现，再用 host-side `gtest` 补测试；依赖由仓库管理，不要求 host 预装 `gtest`。
  - 边界：不为了测试做大重构，不把 Android / NFQUEUE / `iptables` / `netd` 强依赖塞进首批单测。
- `P1 Host-driven 真机基线集成测试`
  - 目标：测试代码跑在 host / WSL，由 host 驱动 Android 真机完成 baseline 级端到端回归。
  - 典型内容：deploy / start / health-check / control protocol 基线 / stream 健康检查 / `RESETALL` 基线。
  - 边界：虽然目标环境是真机，但它仍只覆盖 baseline integration，不进入 NFQUEUE / SELinux / `iptables` / `netd` 等平台专项，也不以此为由实现新功能。
- `P2 真机集成 / smoke / 兼容性验证`
  - 目标：在 rooted Android 真机上补齐平台专项、兼容性与更贴近真实运行环境的 smoke 验证。
  - 典型内容：NFQUEUE、`iptables`、`netd`、SELinux、权限、生命周期、性能 / 回归 smoke。
  - 边界：它与 `P1` 的区别不在于“是否使用真机”，而在于它关注平台专项 / compatibility，而不是 baseline integration。
- `P3 真机原生 Debug / crash / LLDB`
  - 目标：形成可实际使用的断点、单步、attach、run-under-debugger、tombstone symbolize 工作流。
  - 典型内容：LLDB attach / run、VS Code + CodeLLDB 准备、`debuggerd` / tombstone / `stack`、必要时 sanitizer。
  - 边界：它解决定位效率问题，不授权顺手改产品功能。

## 3. 为什么按这个顺序

- 当前最缺的不是再写一轮功能设计，而是可重复验证与可直接调试的开发链路。
- 单测先补最低成本回归保护。
- host-driven 集成测试先把“push / 起守护进程 / 发命令 / 验结果”固化下来。
- 真机 smoke / 兼容性随后补真实 Android 环境差异。
- 最后再把 LLDB / crash lane 固化，解决“只能查 log 反推”的低效率问题。

## 4. 与功能主线的关系

- `A/B/C`、`IPRULES`、DomainPolicy 相关实现属于**独立功能主线**。
- `D` 属于 observability 内的独立性能健康指标层：它不是 test/debug phase，也不参与 `A → IPRULES v1（含 C） → B` 这条主线排序。
- 因此，D 对应的 change 可以继续保留为独立 proposal / design / working decisions，并且可在任意时点单独推进；它既不阻塞主线，也不依赖主线收敛后才能开始。
- 上述功能 change 都不得复用 `P0/P1/P2/P3` 作为阶段编号，以免和测试 / 调试 roadmap 串线。
- `P0 → P3` 已收敛；A/B/C 功能主线顺序见第 6 节，但仍不得倒灌进 test / debug lane。

## 5. 当前现状

- `P0 Host-side 单元测试`：已完成并归档；当前值得测且不由 `P1/P2/P3` 覆盖的高价值 pure-logic 模块，已形成 inventory，并补齐 `PackageState`（含 ABX）、`Rule`、`Settings`、`Stats/AppStats/DomainStats` 的 host-side gtest；其余暂缓项也已记录明确原因。
- `P1 Host-driven 集成测试`：已完成并归档；主入口收敛在 `tests/integration/run.sh`，并已在 rooted 真机上完成 baseline 验证。
- `P2 真机集成 / smoke / 兼容性验证`：已以独立 change 收敛；当前主入口为 `tests/integration/device-smoke.sh`，覆盖 rooted 真机上的 root/preflight、socket、`netd` 前置、`iptables` / `ip6tables` / `NFQUEUE`、SELinux / AVC 与 lifecycle restart smoke。`libnetd_resolv.so` 挂载属于环境相关 compatibility 检查；若外部 debug-base 模块未就位，则明确标为 skip，而不是倒灌到产品实现。
- `P3 真机原生 Debug / crash / LLDB`：独立 change 与真机入口脚本已完成，继续沿真机工作流使用 `LLDB` / `CodeLLDB` / tombstone symbolize 能力。
- `VS Code/CMake` 开发者统一入口：已完成并归档（`openspec/changes/archive/2026-03-14-add-vscode-cmake-dev-workflow/`）；将 `P0/P1/P2` 以 `CTest` / VS Code Testing 方式暴露，并把 `P3` 真机调试收敛为 `F5` 工作流；对应 capability spec 为 `openspec/specs/vscode-cmake-development/spec.md`。
- `docs/NATIVE_DEBUGGING_AND_TESTING.md` 是这条 test / debug 路线的权威补充文档。

## 6. 功能主线顺序（A/B/C + IPRULES；D 独立）

基于 `docs/OBSERVABILITY_WORKING_DECISIONS.md` 与 `docs/IP_RULE_POLICY_WORKING_DECISIONS.md` 的当前共识，A/B/C 主线推荐顺序如下：

`A（Packet 判决层可观测性：add-pktstream-observability） → IPRULES v1（add-app-ip-l3l4-rules-engine，包含 C：per-rule stats） → B（DomainPolicy 层 counters：policySource） → ip-leak 融合 / IPv6 / 域名 per-rule（TBD）`

说明（对应你提议的 “IP rule → C → B”）：
- **A 必须先落地**：`reasonId/ruleId/would-match + src/dst IP` 属于后续所有规则系统的 shared 契约；先把 PKTSTREAM/metrics 基座收敛，避免 IP 规则与域名侧各自“先实现再对齐”导致返工。
- **C 不建议拆成独立里程碑**：per-rule stats 是 IP 规则引擎的 v1 必需能力（“从一开始就可解释 + 可量化”）；更合理的拆法是：在 `add-app-ip-l3l4-rules-engine` change 内部按任务拆出 “核心判决链路先跑通 → stats/输出口径补齐 → 验收/回归”。
- **B 可后置但不应长期拖欠**：它与 IPRULES 基本解耦，因此放在 IP 主线之后没问题；但建议在 IPRULES 主线落地后立刻补齐，避免域名侧长期缺乏默认可查的归因与 counters。
- **D 不参与上述排序**：D 只承载 `nfq_total_us` / `dns_decision_us` 这类性能健康指标；它在语义上独立于 A/B/C，可作为单独 change 在任意时点推进，不改变当前主线优先级。

> 注：`docs/INTERFACE_SPECIFICATION.md` 作为对外接口汇总，应在相关 change 合并并稳定后统一刷新，避免“接口文档先行”导致漂移。
