## 1. OpenSpec docs (this change)
- [x] 1.1 完成 `proposal.md` / `tasks.md` / `design.md` 与 capability spec delta（`specs/host-side-unit-testing/spec.md`）
- [x] 1.2 依据“P0 reopened”结论修订 proposal/design/tasks/spec，并重新通过 `openspec validate add-host-side-unit-test-foundation --strict`

## 2. Roadmap alignment
- [x] 2.1 初始已更新 `docs/IMPLEMENTATION_ROADMAP.md`，建立 `P0/P1/P2/P3` 测试/调试顺序
- [x] 2.2 初始已更新 `AGENTS.md`，明确以 roadmap 为准
- [x] 2.3 初始已更新 `docs/NATIVE_DEBUGGING_AND_TESTING.md`，明确测试/调试 phase 定义
- [x] 2.4 取消 P0 归档，恢复为 active change
- [x] 2.5 更新 roadmap / AGENTS，明确：只要仍存在当前值得测且不由 `P1/P2/P3` 覆盖的 pure-logic 缺口，P0 就不能标记完成

## 3. Phase 0 implementation
- [x] 3.1 已建立 host-side gtest 基础设施（`tests/host/CMakeLists.txt` + `dev/dev-host-unit-tests.sh`）
- [x] 3.2 已新增至少一个 host-side test target 与最小可运行样例
- [x] 3.3 已提供本地运行入口与使用说明
- [x] 3.4 已确认当前测试方案不要求大规模重构
- [x] 3.5 梳理当前所有“值得测且适合 host-side 落地”的 pure-logic 模块，形成带文档依据 / 冲突审计结果的覆盖清单
- [x] 3.6 对清单中尚未覆盖的高价值 pure-logic 模块，必要时先做最小纠偏，再补充 gtest
- [x] 3.7 对暂时无法纳入 P0 的模块记录明确原因（例如需大规模重构或强 Android 依赖），避免责任漂移到 `P1/P2/P3`
- [x] 3.8 重新执行 host-side 单测，并以此作为 P0 重新完成/再次归档前提
