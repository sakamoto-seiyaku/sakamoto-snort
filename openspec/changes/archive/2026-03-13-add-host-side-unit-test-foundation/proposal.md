# Change: Host-side unit test foundation for sucre-snort

## Why
由于设备返修，当前无法落地真机相关 debug / platform validation。因此在当前阶段，最现实、颗粒度也最合适的起步项，是一个**独立的 P0 host-side 单元测试 change**。

这样做的原因是：
- 不依赖当前不可用的真机环境；
- 不要求先做大重构；
- 能尽快为低耦合逻辑建立最小回归保护网；
- 能为后续 `P1 Host-driven 集成测试` 与功能主线恢复提供更稳定的基础。

## What Changes
- 新增并固化 `sucre-snort` 的 host-side 单元测试基础设施。
- 建立至少一个可运行的 host-side test target，并提供明确的本地运行入口。
- 使用仓库管理的 `gtest` 依赖（不要求开发机预装 `gtest` 系统包）。
- 明确第一批测试对象应优先选择低耦合、高价值模块，例如：
  - 解析逻辑
  - 规则匹配逻辑
  - 统计/计数逻辑
  - 其他不依赖 Android 运行时与真机环境的纯逻辑模块
- 明确当前阶段不为了测试做大重构；只允许必要且小范围的 test seam / helper。

## Relationship to future work
- `P1 Host-driven 集成测试` 不属于本 change，后续单独立 change。
- `P3 原生 Debug / 真机专项验证` 不属于本 change，待设备恢复后再单独推进。
- 本 change 为后续功能主线恢复提供最小回归底座，但不改变既有功能 specs 的结论。

## Non-Goals
- 不在本 change 中引入真机相关 LLDB / crash / platform validation。
- 不在本 change 中建设 host-driven integration harness。
- 不要求先把 `sucre-snort` 改造成完全脱离 Android/Lineage 的普通 Linux 项目。
- 不要求高覆盖率，也不追求一次性补齐所有测试。

## Impact
- Affected docs：`docs/IMPLEMENTATION_ROADMAP.md`, `AGENTS.md`
- Affected tooling/code（实现时）：`tests/host/CMakeLists.txt`, `tests/host/`, `dev/dev-host-unit-tests.sh`, `docs/`
