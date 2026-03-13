## ADDED Requirements

### Requirement: Project provides a real-device native debug entry for LLDB workflows
项目 MUST 提供真机原生调试入口，使开发者可以在 host / WSL 上驱动 AOSP LLDB 工作流，附加到已运行的 `sucre-snort-dev`，或直接以调试模式启动它。

#### Scenario: Attach to running sucre-snort-dev on a real device
- **GIVEN** 真机上已经运行 `sucre-snort-dev`
- **WHEN** 开发者执行仓库约定的 native debug attach 入口
- **THEN** 系统 SHALL 能解析 PID 并拼装/执行 LLDB attach 工作流

#### Scenario: Run sucre-snort-dev under LLDB on a real device
- **GIVEN** 真机上存在 `/data/local/tmp/sucre-snort-dev`
- **WHEN** 开发者执行仓库约定的 native debug run 入口
- **THEN** 系统 SHALL 能拼装/执行 LLDB run 工作流

### Requirement: Project provides a VS Code preparation entry without making VS Code mandatory
项目 MUST 支持为 VS Code + CodeLLDB 生成调试准备，但不得把 VS Code 作为唯一调试路径。

#### Scenario: Generate VS Code debug preparation
- **WHEN** 开发者执行仓库约定的 VS Code 调试准备入口
- **THEN** 系统 SHALL 能通过 `lldbclient.py --setup-forwarding vscode-lldb --vscode-launch-file ...` 收敛该流程

### Requirement: Project provides a tombstone pull and symbolize entry
项目 MUST 提供 tombstone 拉取与 `stack` 符号化入口，便于真机 crash 复盘。

#### Scenario: Pull latest tombstone and symbolize it
- **GIVEN** 真机上存在 tombstone 文件
- **WHEN** 开发者执行仓库约定的 tombstone 拉取或符号化入口
- **THEN** 系统 SHALL 能拉取最新 tombstone，并对本地文件执行 `stack` 符号化


### Requirement: Phase 3 must remain a debug lane
项目 MUST 明确 `P3` 只负责真机 native debug / crash / symbolization 工作流，不得被解读为产品功能实现授权。

#### Scenario: Review P3 against product feature work
- **WHEN** 开发者查阅当前 P3 change 与相关文档
- **THEN** SHALL 能明确看到 `A/B/C`、可观测性、`IPRULES` 等产品功能不属于本 change

#### Scenario: Review P3 code-change expectations
- **WHEN** 开发者实施当前 P3 change
- **THEN** SHALL 以调试入口、文档与最小必要 debug seam 为主，而不是对 `src/` 做广泛产品改造
