## 1. OpenSpec docs (this change)
- [x] 1.1 完成 `proposal.md` / `tasks.md` / `design.md` 与 capability spec delta（`specs/host-driven-integration-testing/spec.md`）
- [x] 1.2 `openspec validate add-host-driven-integration-test-lane --strict` 通过

## 2. Phase 1 design alignment
- [x] 2.1 明确当前 P1 的目标拓扑：host / WSL 驱动，Android 真机为唯一目标环境
- [x] 2.2 明确当前 P1 复用现有 `dev-smoke` / `dev-deploy` 路线，而非另起重型框架
- [x] 2.3 明确 P1 与 P3 的边界：真机专项 debug / platform validation 不属于当前 change

## 3. Phase 1 implementation
- [x] 3.1 梳理现有 `dev/dev-smoke.sh` 与 `dev/dev-smoke-lib.sh`，提炼可重复执行的 group / case 入口
- [x] 3.2 补齐目标 preflight / deploy / start / health-check / cleanup 的标准流程
- [x] 3.3 提供至少一条可在真机上执行的 host-driven 集成测试入口
- [x] 3.4 输出明确退出码与结果汇总，便于本地与 CI 调用
- [x] 3.5 文档化运行前提、目标选择方式与当前边界
