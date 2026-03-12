## ADDED Requirements

### Requirement: Project supports a host-side unit test entry without requiring a device or host-installed gtest
项目 MUST 提供至少一个 host-side 单元测试入口，使开发者在不连接 Android 设备的情况下运行第一批低耦合测试，且该入口不得要求开发者在 host 上额外安装 `gtest` 系统包。

#### Scenario: Run unit tests without device
- **GIVEN** 开发者当前没有可用的 Android 真机
- **WHEN** 开发者执行仓库约定的 host-side 单元测试入口
- **THEN** SHALL 能运行至少一批低耦合单元测试

#### Scenario: Run unit tests without host-installed gtest package
- **GIVEN** 开发机具备 `cmake`、`git` 与标准 C++ 编译器，但没有预装 `gtest` 系统包
- **WHEN** 开发者执行仓库约定的 host-side 单元测试入口
- **THEN** 仓库 SHALL 通过自身管理的依赖方式完成 `gtest` 准备并运行测试

### Requirement: First-wave unit tests prioritize low-coupling modules
项目 MUST 明确第一批单元测试的选型原则：优先覆盖低耦合、高价值、可在当前代码结构下直接测试的模块。

#### Scenario: Test selection avoids heavy Android coupling
- **WHEN** 开发者查阅当前 P0 单元测试方案
- **THEN** SHALL 能明确看到强 Android 依赖、socket、NFQUEUE、iptables、netd 等模块不属于第一批测试对象

### Requirement: Host-side unit test introduction must not require broad refactor
项目 MUST 在引入第一批 host-side 单元测试时避免大规模架构重构。

#### Scenario: Unit test foundation is introduced with limited seam changes
- **WHEN** 开发者实施当前 P0 单元测试 change
- **THEN** 方案 SHALL 以最小必要改动落地，而不是以重构主架构为前提
