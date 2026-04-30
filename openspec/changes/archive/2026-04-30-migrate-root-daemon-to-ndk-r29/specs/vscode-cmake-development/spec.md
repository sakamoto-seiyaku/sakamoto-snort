## MODIFIED Requirements

### Requirement: Project provides a CMake-orchestrated developer workflow without redefining Android production build
项目 MUST 提供一个由 `CMake` 托管主要开发者编排入口的工作流。当前 daemon 构建入口 MUST 委托到 NDK r29 daemon workflow，而不是 Android source / Soong daemon workflow。

#### Scenario: Open the repo as a VS Code C++ workspace
- **GIVEN** 开发者在 VS Code WSL 窗口中打开仓库根目录
- **WHEN** 仓库的 development facade 已完成配置
- **THEN** 开发者 SHALL 能以 repo-root 为入口使用 CMake/CTest/Debug 工作流

#### Scenario: Preserve NDK daemon build authority
- **WHEN** 开发者查阅当前 shared workspace 配置与文档
- **THEN** SHALL 能明确看到 `CMake` 负责开发者日常编排入口，并委托到 NDK r29 daemon 构建
- **AND** SHALL NOT advertise `Android.bp + Soong` as the active daemon build authority

#### Scenario: Trigger delegated NDK daemon build from the workspace
- **GIVEN** repo-root `CMakeLists.txt` 与 presets 已经引入
- **WHEN** 开发者从 VS Code 或 `cmake --build` 触发 workspace build
- **THEN** 系统 SHALL 能通过 `snort-build-ndk` 委托调用 `dev/dev-build-ndk.sh`

#### Scenario: Repo-root CMake does not expose Soong daemon targets
- **GIVEN** repo-root `CMakeLists.txt` 与 presets 已经引入
- **WHEN** 开发者查看 workspace 暴露的目标与文档
- **THEN** SHALL NOT expose `snort-build`, `snort-build-clean`, or `snort-build-regen-graph` as active daemon targets
