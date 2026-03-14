## ADDED Requirements

### Requirement: Project provides a host-driven integration test entry for Android real devices
项目 MUST 提供至少一个 host-driven 集成测试入口，使测试代码运行在 host / WSL，并驱动 Android 真机完成端到端验证。

#### Scenario: Run integration tests against a connected real device
- **GIVEN** 开发者有一台可连接的 Android 真机
- **WHEN** 开发者执行仓库约定的 host-driven 集成测试入口
- **THEN** SHALL 能从 host 侧驱动真机完成至少一批集成测试

#### Scenario: Select a specific connected real device by serial
- **GIVEN** 开发环境中连接了多台 Android 真机
- **WHEN** 开发者使用仓库约定的 host-driven 集成测试入口并指定目标 serial
- **THEN** SHALL 能将测试执行收敛到指定真机，而不是依赖默认模糊选择

### Requirement: Phase 1 reuses the existing smoke/deploy workflow instead of introducing a heavy new framework
项目 MUST 优先基于现有 `dev-smoke` / `dev-deploy` 路线建设 P1，而不是在当前阶段引入与仓库工作流割裂的重型新框架。

#### Scenario: Integration test lane evolves from existing scripts
- **WHEN** 开发者查阅当前 P1 方案
- **THEN** SHALL 能明确看到现有 smoke / deploy 路径是首选演进基础，且 host-driven 集成测试入口优先位于 `tests/integration/`

### Requirement: Phase 1 provides repeatable target lifecycle handling and scriptable results
项目 MUST 为 host-driven 集成测试提供可重复的目标 preflight / deploy / health-check / cleanup 流程，并输出适合脚本调用的执行结果。

#### Scenario: Run selected test group with deterministic setup and exit status
- **GIVEN** 开发者只想验证某一个 smoke group
- **WHEN** 开发者执行仓库约定的 host-driven 集成测试入口并选择该 group
- **THEN** 系统 SHALL 对目标环境执行必要的准备与健康检查，并以明确退出码反映成功或失败

### Requirement: Phase 1 excludes native debug and deep platform-specific validation
项目 MUST 明确：即使当前 `P1` 运行在真机上，它仍只承担 baseline integration；真机专项 debug、性能压测与深度平台专项验证属于后续 `P2/P3`。

#### Scenario: Review P1 scope boundaries
- **WHEN** 开发者查阅当前 P1 设计
- **THEN** SHALL 能明确看到 LLDB、tombstone 流程、NFQUEUE 性能、SELinux 疑难问题等仍不属于本 change
- **AND** SHALL 能明确看到 `P1` 与 `P2` 的区别在于 baseline integration vs platform-specific / compatibility，而不是是否使用真机


### Requirement: Phase 1 must remain a test/tooling lane
项目 MUST 明确 `P1` 只属于测试 / tooling 路线，不得被解读为产品功能实现授权。

#### Scenario: Review P1 against product feature work
- **WHEN** 开发者查阅当前 P1 change 与相关文档
- **THEN** SHALL 能明确看到 `A/B/C`、可观测性、`IPRULES` 等产品功能不属于本 change

#### Scenario: Review P1 code-change expectations
- **WHEN** 开发者实施当前 P1 change
- **THEN** SHALL 以测试脚本、文档与最小必要 seam 为主，而不是对 `src/` 做广泛产品改造
