## ADDED Requirements

### Requirement: Project provides a rooted real-device platform smoke entry
项目 MUST 提供 rooted 真机平台专项 smoke 入口，使开发者可以在 host / WSL 上驱动 Android 真机执行 `P2` 的 compatibility / smoke 验证。

#### Scenario: Run P2 smoke from host against a rooted device
- **WHEN** 开发者执行仓库约定的 `P2` 真机 smoke 入口
- **THEN** 系统 SHALL 能从 host / WSL 驱动 Android 真机执行测试
- **AND** SHALL 支持按 group / case 筛选测试

### Requirement: P2 verifies real-device platform prerequisites and runtime wiring
项目 MUST 在 `P2` 中验证 rooted 真机上的平台前置和运行态接线，而不只停留在控制协议 baseline。

#### Scenario: Verify runtime prerequisites on a real device
- **GIVEN** 真机上已经部署并运行 `sucre-snort-dev`
- **WHEN** 开发者执行 `P2` smoke
- **THEN** SHALL 能检查 root/preflight、daemon 健康、control/DNS socket 状态与 `netd` 相关前置条件

### Requirement: P2 verifies firewall and NFQUEUE smoke on a real device
项目 MUST 在 rooted 真机上检查 `iptables` / `ip6tables` / `NFQUEUE` 是否建立，并通过最小真实流量 smoke 验证计数器变化。

#### Scenario: Verify NFQUEUE wiring with real-device traffic
- **GIVEN** 真机上已存在 `sucre-snort` 自定义链与 `NFQUEUE` 规则
- **WHEN** 开发者执行 `P2` firewall smoke
- **THEN** SHALL 能检查 hook / chain / `NFQUEUE` 规则存在
- **AND** SHALL 能通过最小真实流量观测至少一个 `NFQUEUE` 计数器增长

### Requirement: P2 verifies SELinux and lifecycle compatibility without product changes
项目 MUST 提供 SELinux / AVC 与 lifecycle restart smoke，但不得借此扩展成产品实现改造。

#### Scenario: Verify SELinux health and restart lifecycle
- **WHEN** 开发者执行 `P2` smoke
- **THEN** SHALL 能检查 SELinux 模式、运行态上下文与相关 AVC 记录
- **AND** SHALL 能执行 shutdown / redeploy / restart smoke 并恢复 daemon 可用状态

### Requirement: Phase 2 remains a test/debug lane
项目 MUST 明确 `P2` 只负责 rooted 真机 smoke / compatibility / test tooling，不得被解读为产品功能实现授权。

#### Scenario: Review P2 against product feature work
- **WHEN** 开发者查阅当前 `P2` change 与相关文档
- **THEN** SHALL 能明确看到 `A/B/C`、可观测性、`IPRULES` 等产品功能不属于本 change

#### Scenario: Review P2 code-change expectations
- **WHEN** 开发者实施当前 `P2` change
- **THEN** SHALL 以测试脚本、文档与最小必要工具链为主，而不是对 `src/` 做广泛产品改造
