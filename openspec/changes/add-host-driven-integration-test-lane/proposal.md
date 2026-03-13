# Change: Host-driven integration test lane for sucre-snort

## Why
`P0` 已经补上 host-side 单元测试底座，但当前最大的验证缺口仍然是：**daemon 进程、Android 目标环境、控制面协议与状态变更**能否一起稳定工作。

对 `sucre-snort` 来说，这类问题无法只靠纯 host 单元测试覆盖；现在真机已恢复可用，因此下一阶段最合适的颗粒度是一个**独立的 P1 host-driven integration test change**：测试代码跑在 host / WSL，由 host 驱动 Android 真机执行集成测试。

## What Changes
- 新增并固化 `sucre-snort` 的 host-driven 集成测试入口。
- 测试驱动运行在 host / WSL，目标环境为 Android 真机。
- 当前 P1 主路径收敛为真机集成测试。
- 优先复用并收敛现有 smoke / deploy 路径，而不是另起一套完全割裂的新流程；其中测试入口优先落在 `tests/integration/`，而非长期停留在 `dev/`。
- 为集成测试补齐最小必需的目标 preflight、deploy、健康检查、状态 reset/cleanup 与结果汇总能力。
- 允许按 group / case 运行测试，便于本地迭代与后续 CI 接入。

## Relationship to other phases
- `P0 Host-side 单元测试` 已完成并单独提交，不并入本 change。
- `P2 真机集成 / smoke / 兼容性验证` 仍保持独立，不并入本 change。
- `P3 原生 Debug / 真机专项验证` 仍保持独立；即使 P1 使用真机做集成测试，LLDB / tombstone / platform-specific debug 仍后置到 P3。

## Non-Goals
- 不在本 change 中引入 LLDB、断点调试、tombstone 流程固化。
- 不在本 change 中覆盖必须依赖真机的平台专项行为，例如 NFQUEUE 性能、SELinux 特殊问题、极端流量压测。
- 不要求当前阶段把仓库测试体系整体迁移到 Tradefed / Soong / atest。
- 不为了 P1 重写现有 smoke 脚本或大规模改造主程序结构。
- 不以当前 change 为理由推进 `A/B/C`、可观测性、`IPRULES` 或其他产品功能实现。
- 除非绝对必要且范围可解释，否则不修改 `src/` 主实现。

## Impact
- Affected docs：`docs/IMPLEMENTATION_ROADMAP.md`, `docs/NATIVE_DEBUGGING_AND_TESTING.md`, `dev/README.md`
- Affected tooling/code（实现时）：`tests/integration/`, `dev/dev-deploy.sh`, 以及相关文档 / 兼容 wrapper
