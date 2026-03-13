<!-- OPENSPEC:START -->
# OpenSpec Instructions

These instructions are for AI assistants working in this project.

Always open `@/openspec/AGENTS.md` when the request:
- Mentions planning or proposals (words like proposal, spec, change, plan)
- Introduces new capabilities, breaking changes, architecture shifts, or big performance/security work
- Sounds ambiguous and you need the authoritative spec before coding

Use `@/openspec/AGENTS.md` to learn:
- How to create and apply change proposals
- Spec format and conventions
- Project structure and guidelines

Keep this managed block so 'openspec update' can refresh the instructions.

<!-- OPENSPEC:END -->

## Roadmap Reference

- 当前实现顺序、阶段现状与边界说明统一记录在 `docs/IMPLEMENTATION_ROADMAP.md`
- 当前项目优先级已切换为：`P0 Host-side 单元测试（当前 active change，tasks complete） → P1 Host-driven 集成测试（host / WSL 驱动真机） → P2 真机集成 / smoke / 兼容性验证 → P3 真机原生 Debug / crash / LLDB`
- 若后续任务涉及主线优先级、阶段状态、实现顺序、测试主线或原生调试流程，agent 应先读取 `docs/IMPLEMENTATION_ROADMAP.md` 与 `docs/NATIVE_DEBUGGING_AND_TESTING.md`，并确认当前任务是否仅属于 test / debug / tooling 范围；`A/B/C`、可观测性、`IPRULES` 等功能线不属于当前 `P0/P1/P2/P3`
