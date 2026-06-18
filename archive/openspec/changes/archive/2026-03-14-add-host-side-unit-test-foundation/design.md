# Design: Host-side unit test foundation for sucre-snort

## 0. Scope
本 change 只关注 **P0 Host-side 单元测试**：
- 保留并维护 host-side gtest 基础设施
- 梳理当前值得测、且适合 host-side 落地的纯逻辑模块清单
- 继续补齐这部分模块的单测覆盖，直到不存在“仍值得测但无人负责”的 pure-logic 缺口
- 固化本地运行方式与边界

本 change 不包含 host-driven 集成测试，不包含真机 debug，也不包含平台专项验证。

## 1. Goals
- 在不依赖真机的前提下，建立并持续扩展可落地的 host-side 单测路径。
- 以最小成本挡住当前值得测的 pure-logic 回归。
- 明确 `P1/P2/P3` 不承担这部分缺口，避免责任漂移。
- 不为了测试把当前阶段演化成架构重写。

## 2. Selection principles
- 优先选低耦合模块。
- 优先选纯逻辑、解析、匹配、统计、控制参数处理类代码。
- 先按现有权威文档 / 设计语义审计实现，再决定是补测试、记录冲突，还是先做最小纠偏。
- 若模块可在 host-side 落地且不需要大规模重构，则它应优先留在 P0，而不是后推给 `P1/P2/P3`。
- 强 Android 依赖、socket、NFQUEUE、iptables、netd 等内容不属于当前 P0 主体；若因此无法 host-side 化，应记录暂缓原因。

## 3. Constraints
- P0 不得把真机作为前置条件。
- 若某测试对象需要大规模重构才能落地，则必须显式记录暂缓原因，不能静默视为“后续 phase 会覆盖”。
- 当前方案不得要求开发机预装 `gtest` 系统包；测试依赖需要由仓库自身管理。
- 当前要避免的是“大重构”，而不是避免补齐值得测的 pure-logic 测试责任。

## 4. Implementation decision
- P0 采用 `GoogleTest` 作为测试框架。
- Host-side 运行入口采用独立 `CMake` 工程，而不是把当前阶段绑定到 Lineage / Soong host 构建。
- `gtest` 通过 `FetchContent` 固定版本拉取，由仓库侧管理依赖，不要求开发机额外安装 `gtest`。
- 通过 `tests/host/` 维护当前 pure-logic 覆盖；必要时补少量 test seam，但不得演化成主程序重构。
- P0 完成前，应有一份清晰的 host-side pure-logic 覆盖/暂缓清单。

## 5. Follow-up changes
- Phase 1：host-driven 集成测试（单独 change）
- Phase 2：真机集成 / smoke / 兼容性验证（单独 change）
- Phase 3：原生 Debug / 真机专项验证（单独 change）
