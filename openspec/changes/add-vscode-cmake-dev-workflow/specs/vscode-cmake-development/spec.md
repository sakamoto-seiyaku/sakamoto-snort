## ADDED Requirements

### Requirement: Project provides a CMake-orchestrated developer workflow without replacing Android production build
项目 MUST 提供一个由 `CMake` 托管主要开发者编排入口的工作流，但不得把真实 Android 产物构建主线从 `Android.bp + Soong` 改写为纯 `CMake`。

#### Scenario: Open the repo as a VS Code C++ workspace
- **GIVEN** 开发者在 VS Code WSL 窗口中打开仓库根目录
- **WHEN** 仓库的 development facade 已完成配置
- **THEN** 开发者 SHALL 能以 repo-root 为入口使用 CMake/CTest/Debug 工作流

#### Scenario: Preserve Android production build authority
- **WHEN** 开发者查阅当前 shared workspace 配置与文档
- **THEN** SHALL 能明确看到 `CMake` 负责开发者日常编排入口，而不替代 `Android.bp + Soong`

### Requirement: Project surfaces host-side unit tests through VS Code Testing
项目 MUST 将现有 host-side `gtest` 测试以 `CTest` / VS Code Testing 可发现的形式暴露，而不是只保留脚本入口。

#### Scenario: Discover host-side unit tests in VS Code
- **GIVEN** 开发者已完成 CMake configure
- **WHEN** VS Code 读取当前 workspace 的测试信息
- **THEN** SHALL 能在 Testing 面板中看到 `P0` host-side unit tests

#### Scenario: Run a single host-side unit test from VS Code
- **GIVEN** 某个 `P0` gtest case 已被发现
- **WHEN** 开发者在 VS Code Testing 面板中运行该 case
- **THEN** 系统 SHALL 能通过 workspace 定义的测试入口执行对应测试

### Requirement: Project surfaces named real-device integration tests through CTest-first orchestration
项目 MUST 为 `P1/P2` 提供优先由 `CTest` 托管、可被 IDE 统一消费的命名测试入口，并明确真机缺失或权限前置不满足时的行为。

#### Scenario: Discover real-device integration lanes
- **GIVEN** 当前 workspace 已配置 integration test facade
- **WHEN** 开发者查看测试列表
- **THEN** SHALL 能区分看到 `P1` baseline integration 与 `P2` real-device smoke 测试入口

#### Scenario: Run a real-device integration test with a ready device
- **GIVEN** rooted Android 真机在线且前置满足
- **WHEN** 开发者从 VS Code 触发某个 `P1` 或 `P2` 测试
- **THEN** 系统 SHALL 能通过 `CTest` 优先承载的统一测试入口驱动对应真机测试

#### Scenario: Run a real-device integration test without prerequisites
- **GIVEN** 真机不在线、无 root、或关键前置未满足
- **WHEN** 开发者触发某个 `P1` 或 `P2` 测试
- **THEN** 系统 SHALL 以清晰一致的 skip/fail 语义报告结果，而不是静默挂起

### Requirement: Project provides a VS Code F5 workflow for real-device native debug with CMake-managed orchestration
项目 MUST 将现有 `P3` 真机 native debug backend 收敛为 VS Code `F5` 工作流，并尽量把可托管的调试编排迁入 `CMake` / VS Code 配置，而不是要求开发者手工组合多条命令。

#### Scenario: Start attach debug from VS Code
- **GIVEN** 真机在线且 `sucre-snort-dev` 正在运行
- **WHEN** 开发者在 VS Code 中选择 real-device attach debug 配置并按下 `F5`
- **THEN** 系统 SHALL 通过 checked-in debug configuration 与前后置任务完成调试准备并进入 attach 会话

#### Scenario: Start run-under-debugger from VS Code
- **GIVEN** 真机在线且 `/data/local/tmp/sucre-snort-dev` 可执行
- **WHEN** 开发者在 VS Code 中选择 real-device run debug 配置并按下 `F5`
- **THEN** 系统 SHALL 能进入 run-under-debugger 工作流，而不要求开发者手工拼装底层命令

### Requirement: Project separates shared workspace config from user-local machine config
项目 MUST 清晰分离 checked-in shared workspace 配置与每位开发者本机专属配置。

#### Scenario: Override local machine settings without editing checked-in files
- **GIVEN** 两位开发者的 `LINEAGE_ROOT`、`ADB_SERIAL` 或默认 lunch target 不同
- **WHEN** 他们分别配置本地工作区
- **THEN** 系统 SHALL 支持通过 user-local 配置覆盖这些值，而不要求修改仓库内共享配置文件
