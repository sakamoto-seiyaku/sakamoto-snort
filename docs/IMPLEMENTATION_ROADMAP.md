# 当前实现 Roadmap（P0/P1/P2/P3）

更新时间：2026-03-13  
状态：当前共识；当前 `P0/P1/P2/P3` 只表示 **测试 / 集成验证 / 真机调试** 的工程化顺序，不表示功能实现阶段，也不授权推进 `A/B/C`、可观测性、`IPRULES` 等产品能力。

## 1. 当前主线顺序

`P0 Host-side 单元测试（当前 active change，tasks complete） → P1 Host-driven 集成测试（host / WSL 驱动真机） → P2 真机集成 / smoke / 兼容性验证 → P3 真机原生 Debug / crash / LLDB`

- 这四个 phase 全部围绕 **test / debug / tooling**。
- `P0/P1/P2/P3` 与 `A/B/C`、`add-pktstream-observability`、`add-app-ip-l3l4-rules-engine` 没有阶段对应关系。
- 所有与可观测性 / IP rules / `A/B/C` 相关的功能实现，统一排在整个 `P0 → P3` 之后，作为独立功能主线处理。
- 任何以 `P1/P2/P3` 名义推进的工作，都不得顺势夹带产品功能实现；若确需极小的 test seam / debug seam，必须先说明必要性，并把范围压到最小。

## 2. 各阶段定义与边界

- `P0 Host-side 单元测试`
  - 目标：不连设备先挡住一批低耦合回归。
  - 方式：先按现有权威文档 / 设计语义审计 pure-logic 实现，再用 host-side `gtest` 补测试；依赖由仓库管理，不要求 host 预装 `gtest`。
  - 边界：不为了测试做大重构，不把 Android / NFQUEUE / `iptables` / `netd` 强依赖塞进首批单测。
- `P1 Host-driven 集成测试`
  - 目标：测试代码跑在 host / WSL，由 host 驱动 Android 真机完成端到端回归。
  - 典型内容：deploy / start / health-check / control protocol 基线 / stream 健康检查 / reset 基线。
  - 边界：仍是自动化验证，不进入真机专项 debug / crash 分析，也不以此为由实现新功能。
- `P2 真机集成 / smoke / 兼容性验证`
  - 目标：在 rooted Android 真机上补齐更贴近真实运行环境的专项验证。
  - 典型内容：NFQUEUE、`iptables`、`netd`、SELinux、权限、生命周期、性能 / 回归 smoke。
  - 边界：它仍属于测试 lane，不等于产品功能实现阶段。
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

- `A/B/C`、可观测性、`IPRULES`、DomainPolicy 相关实现属于**独立功能主线**。
- 这些功能 change 可以继续保留为独立 proposal / design / working decisions，但不得再复用 `P0/P1/P2/P3` 作为阶段编号，以免和测试 / 调试 roadmap 串线。
- 若未来恢复功能主线，必须在 `P0 → P3` 完整收敛后另行排期，不得倒灌进当前 test / debug lane。

## 5. 当前现状

- `P0 Host-side 单元测试`：本轮 reopened 工作已完成；当前值得测且不由 `P1/P2/P3` 覆盖的高价值 pure-logic 模块，已形成 inventory，并补齐 `PackageState`（含 ABX）、`Rule`、`Settings`、`Stats/AppStats/DomainStats` 的 host-side gtest；其余暂缓项也已记录明确原因。
- `P1 Host-driven 集成测试`：作为独立 change 继续推进，只聚焦基线自动化验证。
- `P2 真机集成 / smoke / 兼容性验证`：待以独立 change 收敛。
- `P3 真机原生 Debug / crash / LLDB`：调研已完成，继续以独立 change 推进真机工作流。
- `docs/NATIVE_DEBUGGING_AND_TESTING.md` 是这条 test / debug 路线的权威补充文档。
