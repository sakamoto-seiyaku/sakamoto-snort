# Reference Audit: VS Code + CMake scaffolds

## 1. Audit snapshot
本次对以下开源脚手架做了本地下载与结构审计，下载目录为 `/tmp/sucre-snort-vscode-cmake-references`。

- `josephgarnier/cpp-starter-project-cmake` @ `b587beb`
- `cpp-best-practices/cmake_template` @ `0a32e3f`
- `gvcallen/CMake-VSCode-Tutorial` @ `0ee068e`
- `filipdutescu/modern-cpp-template` @ `0fab2c3`
- `TheLartians/ModernCppStarter` @ `12cf5de`

本次梳理只关注与当前 change 直接相关的部分：
- repo-root `CMakeLists.txt` 的工作区组织方式
- `CMakePresets.json` / `CMakeUserPresets.json` 的分层方式
- checked-in `.vscode` 的最小集合
- `gtest` / `CTest` 的组织方式
- debug 入口是 IDE 主入口还是脚本主入口

## 2. 直接采用的模式
### 2.1 Hidden base preset + concrete presets
参考 `cpp-starter-project-cmake` 与 `cmake_template`，本 change 采用：
- `CMakePresets.json` 中使用 hidden base preset
- 在 base preset 之上派生共享的 developer presets
- 通过 preset 统一 `binaryDir` / `build type` / 常用 cache variables

这样可以把 repo-root workspace 组织得稳定、可发现，并避免把路径和设备信息散落到脚本参数里。

### 2.2 CTest-first 作为 VS Code Testing 暴露层
参考 `modern-cpp-template` 与 `ModernCppStarter`，本 change 继续坚持：
- host-side `gtest` 通过 `CTest` 暴露给 VS Code Testing
- `P1/P2` 也优先通过命名化 `CTest` 测试暴露，而不是把 task 当测试树
- 测试分组优先依赖 `CTest` test name + label，而不是自定义 VS Code 扩展

### 2.3 Checked-in `.vscode/extensions.json`
参考 `cpp-starter-project-cmake`，本 change 采用 checked-in 扩展推荐，但保持最小集合：
- `ms-vscode.cmake-tools`
- `ms-vscode.cpptools`
- `vadimcn.vscode-lldb`

这能把当前 workflow 需要的最小 VS Code 依赖显式化。

## 3. 改造后采用的模式
### 3.1 Checked-in `.vscode/settings.json`，但保持极简
参考 `CMake-VSCode-Tutorial`，本 change 会提供 checked-in `.vscode/settings.json`，但只保留工作流强相关项，例如：
- 让 CMake Tools 成为配置提供者
- 优先使用 presets
- 仅保留能改善当前仓库工作流的最小设置

不会把开发者个人偏好、格式化器或 UI 习惯放进共享设置。

### 3.2 Checked-in `launch.json`，但切换到 Android real-device debug 语义
参考 `CMake-VSCode-Tutorial` 的“checked-in `launch.json` 是 IDE 主入口”这一组织方式，但不复用其桌面 `gdb/cppdbg` 形态。

本仓库的 `P3` 调试入口将继续围绕：
- CodeLLDB
- Android 真机 `lldb-server`
- 现有 `dev/dev-native-debug.sh` / `dev/dev-lldbclient-wrapper.py` backend

也就是说，借鉴的是“checked-in launch config 作为主入口”的组织方式，而不是其桌面本地调试参数。

### 3.3 repo-managed gtest，而不是依赖 host 预装
参考模板项目的 `add_subdirectory(test)` / `enable_testing()` 组织方式，但不采用 `find_package(GTest REQUIRED)` 作为前提。

本仓库仍保持：
- `gtest` 依赖由仓库管理
- 优先通过 `FetchContent` / repo-controlled dependency 获取
- 不要求开发者先在 host 手工安装 `gtest`

### 3.4 CTest labels 作为 phase 分层手段
多个模板都把测试交给 `CTest` 统一承载，但没有直接覆盖我们的 Android 真机场景。本 change 进一步细化为：
- `p0`
- `p1`
- `p2`
- `device`
- `root-required`
- `debug-prep`

这样既能服务 VS Code Testing，也能保留 `ctest -L ...` 的批量执行能力。

## 4. 明确不采用的模式
### 4.1 不把脚本目录继续当主 UX
`cpp-starter-project-cmake` 有较重的脚本 + task 目录编排；我们只借鉴其“可发现入口”的优点，不继承“脚本目录本身就是主入口”的形态。

在本 change 中：
- 脚本允许继续存在
- 但应尽量下沉为 backend helper
- 开发者主入口应转到 `CMake/CTest/launch.json`

### 4.2 不引入新的通用依赖管理框架
`ModernCppStarter` 使用 `CPM.cmake`，`modern-cpp-template` 预留 Conan/Vcpkg 组织方式；这些对当前目标都属于越界。

本 change 明确不引入：
- `CPM.cmake`
- Conan
- Vcpkg
- 任何与当前 test/debug 目标无关的 package-management 框架

### 4.3 不让 repo-root CMake 重写产品构建定义
多个模板都把 repo-root `CMakeLists.txt` 作为真实产物构建入口；本仓库不这么做。

repo-root `CMakeLists.txt` 在当前 change 中负责：
- workspace 组织
- 统一 build 入口（委托调用现有 Android / Soong 流程）
- host tests
- named integration tests
- debug preparation targets

它不替代 `Android.bp + Soong` 的构建定义。

### 4.4 不提交 user-local preset / device-specific config
部分模板仓库会提交 `CMakeUserPresets.json` 示例或携带更强的本机化配置；这不适合当前仓库。

本 change 明确要求：
- `CMakeUserPresets.json` 只作为本地文件使用
- `ADB_SERIAL`、`LINEAGE_ROOT`、默认 lunch target 等只放在 user-local 覆盖层
- checked-in 配置中不出现开发者个人设备信息

## 5. Concrete mapping back to this change
### 5.1 Workspace foundation
- `2.1` repo-root `CMakeLists.txt`：采用“root orchestration + subdirectory”模式，统一托管 build/test/debug；其中 build 委托到现有 Android / Soong 流程
- `2.2` `CMakePresets.json`：采用 hidden-base 继承结构与稳定的 build 目录布局
- `2.3` checked-in `.vscode`：采用最小扩展推荐和极简共享设置
- `2.4` shared vs local config：明确 user-local override 只放本地

### 5.2 Phase 0 / Phase 1 / Phase 2
- `3.x`：沿用 `gtest + CTest` 的 IDE 暴露方式
- `4.x`：把 `P1/P2` 变成命名化 `CTest` 测试，并补 label / skip/fail 语义

### 5.3 Phase 3
- `5.x`：采用 checked-in `launch.json` + `preLaunchTask/postDebugTask` 作为用户主入口
- backend 脚本只保留 Android 真机细节处理，不再作为首选日常入口

## 6. Outcome for implementation
后续实现阶段应优先追求以下结果：
- 开发者打开 repo root 后，先看到的是 `CMake/CTest/Debug` 工作区，而不是脚本目录
- `P0/P1/P2` 都能通过 `CTest` 被统一发现与运行
- `P3` 以 VS Code `F5` 为主入口，但继续复用现有真实可用的 Android backend
- 全程不把工作扩展到 `src/` 产品逻辑或新的功能实现
