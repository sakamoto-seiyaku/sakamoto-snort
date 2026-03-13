# Change: Host-side unit test foundation for sucre-snort

## Why
当前已经确认：`P1/P2/P3` 分别负责 host-driven 集成测试、真机 smoke/兼容性验证、以及真机 native debug；它们**都不负责补齐剩余纯逻辑的 host-side 单测覆盖**。

这意味着：如果仓库里仍存在“当前值得测、且可在不做大重构前提下于 host-side 落地”的纯逻辑模块未被覆盖，那么这些缺口仍然属于 **P0**，不能被视为已经由后续 phases 吸收，也不能把 `P0` 标记为完成。

因此需要把 `P0` 恢复为 active change，并把完成定义改准：
- 不要求先接真机；
- 不要求先做大重构；
- 但必须把当前值得测、且适合 host-side 的纯逻辑测试责任收回到 P0；
- 在这类缺口补齐之前，`P0` 不应归档。

## What Changes
- 保留并扩展 `sucre-snort` 的 host-side 单元测试基础设施。
- 继续使用仓库管理的 `gtest` 依赖（不要求开发机预装 `gtest` 系统包）。
- 建立并维护一份 **当前值得测、且适合 host-side 落地的纯逻辑模块清单**。
- 清单与测试用例都必须先对照现有权威文档 / 设计语义做审计，不能仅按当前代码形态补测试。
- 对清单中的模块执行以下二选一收敛：
  - 已纳入 `P0` host-side gtest 覆盖；或
  - 明确记录暂缓原因（例如需要大规模重构、仍强依赖 Android/真机环境），且不得把责任转嫁给 `P1/P2/P3`
- 在不做大重构的前提下，继续补充解析、匹配、计数、控制参数等纯逻辑测试。
- 维持清晰的本地运行入口与文档说明。

## Relationship to future work
- `P1 Host-driven 集成测试` 不属于本 change，且不替代剩余纯逻辑的 host-side 单测覆盖。
- `P2 真机集成 / smoke / 兼容性验证` 不属于本 change，且不替代剩余纯逻辑的 host-side 单测覆盖。
- `P3 原生 Debug / 真机专项验证` 不属于本 change，且不替代剩余纯逻辑的 host-side 单测覆盖。
- 本 change 仍为后续功能主线提供回归底座，但在当前值得测的 pure-logic 缺口补齐前，不应视为完成。

## Non-Goals
- 不在本 change 中引入真机相关 LLDB / crash / platform validation。
- 不在本 change 中建设 host-driven integration harness。
- 不要求先把 `sucre-snort` 改造成完全脱离 Android/Lineage 的普通 Linux 项目。
- 不追求“全仓库覆盖率指标”；但当前值得测、且适合 host-side 的纯逻辑模块不能继续处于无人负责状态。

## Impact
- Affected docs：`docs/IMPLEMENTATION_ROADMAP.md`, `AGENTS.md`
- Affected tooling/code（实现时）：`tests/host/CMakeLists.txt`, `tests/host/`, `dev/dev-host-unit-tests.sh`, `docs/`
