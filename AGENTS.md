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
- 当前项目优先级已切换为：`P0 Host-side 单元测试（当前独立 change） → P1 Host-driven 集成测试（后续独立 change） → P2 功能主线恢复 → P3 原生 Debug / 真机专项验证（待设备恢复）`
- 若后续任务涉及主线优先级、阶段状态、实现顺序、测试主线或原生调试流程，agent 应先读取 `docs/IMPLEMENTATION_ROADMAP.md` 与 `docs/NATIVE_DEBUGGING_AND_TESTING.md`，并确认当前 active change 的粒度边界与设备可用性约束，再结合相关权威文档推进
