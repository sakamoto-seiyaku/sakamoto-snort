# Design: Host-side unit test foundation for sucre-snort

## 0. Scope
本 change 只关注 **P0 Host-side 单元测试基础设施**：
- 选择第一批低耦合测试对象
- 建立最小可运行的 host-side test target
- 固化本地运行方式与边界

本 change 不包含 host-driven 集成测试，不包含真机 debug，也不包含平台专项验证。

## 1. Goals
- 在不依赖真机的前提下，先建立一条能落地的自动化验证路径。
- 以最小成本挡住一批纯逻辑回归。
- 不为了测试把当前阶段演化成架构重写。

## 2. Selection principles
- 优先选低耦合模块。
- 优先选纯逻辑、解析、匹配、统计类代码。
- 避免把强 Android 依赖、socket、NFQUEUE、iptables、netd 等内容塞进当前 P0。

## 3. Constraints
- 设备当前不可用，因此当前 change 不得把真机作为前置条件。
- 若某测试对象需要大规模重构才能落地，则应降级优先级或推迟。
- 第一批测试应优先追求“跑起来并稳定”，而不是追求覆盖面。
- 当前方案不得要求开发机预装 `gtest` 系统包；测试依赖需要由仓库自身管理。

## 4. Implementation decision
- P0 采用 `GoogleTest` 作为测试框架。
- Host-side 运行入口采用独立 `CMake` 工程，而不是把当前阶段绑定到 Lineage / Soong host 构建。
- `gtest` 通过 `FetchContent` 固定版本拉取，由仓库侧管理依赖，不要求开发机额外安装 `gtest`。
- 当前只为测试目标引入最小构建脚手架，不改变 `sucre-snort` 主二进制的现有 Soong 构建方式。

## 5. Follow-up changes
- Phase 1：host-driven 集成测试（单独 change）
- Phase 2：功能主线恢复
- Phase 3：原生 Debug / 真机专项验证（单独 change，待设备恢复）
