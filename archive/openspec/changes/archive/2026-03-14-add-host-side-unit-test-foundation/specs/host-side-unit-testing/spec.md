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

### Requirement: P0 owns the remaining worthwhile host-side pure-logic coverage
项目 MUST 明确：凡是当前值得测、且可在不做大规模重构前提下以 host-side 落地的 pure-logic 模块，只要尚未被覆盖，它们就仍属于 `P0` 责任范围，而不是由 `P1/P2/P3` 吸收。

#### Scenario: Review phase boundaries for remaining pure-logic gaps
- **WHEN** 开发者对照 `P0/P1/P2/P3` 边界审查尚未覆盖的 pure-logic 模块
- **THEN** SHALL 能明确看到这些缺口仍属于 `P0`，而不是被视为后续 phase 已覆盖

#### Scenario: Marking P0 complete requires closing remaining worthwhile pure-logic gaps
- **WHEN** 仓库中仍存在当前值得测、且适合 host-side 落地的 pure-logic 模块未被覆盖
- **THEN** `P0` SHALL NOT 被标记为 completed 或 archived

### Requirement: Host-side unit test introduction must not require broad refactor
项目 MUST 在引入第一批 host-side 单元测试时避免大规模架构重构。

#### Scenario: Unit test foundation is introduced with limited seam changes
- **WHEN** 开发者实施当前 P0 单元测试 change
- **THEN** 方案 SHALL 以最小必要改动落地，而不是以重构主架构为前提


### Requirement: P0 maintains an explicit host-side pure-logic coverage inventory
项目 MUST 维护一份当前值得测的 host-side pure-logic 覆盖清单，使每个候选模块都有明确结论：已覆盖，或因大规模重构/强 Android 依赖而暂缓；该清单还 MUST 记录对应文档依据，以及是否存在文档语义与实现现状冲突。

#### Scenario: Review current host-side unit-test scope
- **WHEN** 开发者查阅当前 P0 单测方案
- **THEN** SHALL 能明确看到哪些 pure-logic 模块已纳入 gtest，哪些模块暂缓以及原因
- **AND** SHALL 能看到每个模块对应的文档依据，以及是否存在需要先纠偏再补测的实现冲突
