# Design: VS Code + CMake development workflow for sucre-snort

## 0. Scope
本 change 关注的是 **CMake 托管的开发者统一入口**，底层可以继续调用 Android 真实产物构建层：
- 在 VS Code 中把当前仓库组织成更接近传统 `C/C++ + CMake` 项目的形态；
- 让 `build`、`P0` 单测、`P1/P2` 真机测试、`P3` 真机 debug 尽量都通过 `CMake/CTest/launch` 的标准入口使用；
- 允许改造、收缩甚至替换当前编排脚本，把能托管进 `CMake/CTest` 的部分尽量托管进去；
- 但保留与 Android/Lineage 真机构建和调试直接相关的必要 backend helper。

本 change 不把 `Android.bp + Soong` 的构建定义重写成 `CMake`；但允许 repo-root `CMake` 通过 target / task 调用现有 Android 构建流程，也不授权产品代码重构。

## 1. Goals
- 开发者打开仓库根目录后，能够把该仓库当成一个 VS Code C++ workspace 使用。
- 开发者能够通过 VS Code / CMake 的统一 build 入口触发现有 Android / Soong 构建流程。
- `P0` host-side `gtest` 被 `CMake + CTest` 直接托管，并出现在 VS Code Testing 面板中。
- `P1/P2` 真机集成测试尽量被 `CMake/CTest` 直接托管，而不是只能手敲脚本。
- `P3` 真机调试稳定收敛成 `F5` 工作流，脚本只保留为 backend helper。
- 把 user-specific 的路径 / 设备信息和 checked-in 配置清楚分层。

## 2. Non-Goals
- 不把主程序的 Android 构建定义从 `Android.bp + Soong` 重写为纯 `CMake`；统一入口层允许调用既有流程。
- 不承诺“零脚本”；脚本可继续作为 Android / 真机适配 backend 存在。
- 不为了 Testing / Debug UI 去引入大规模 `src/` test seam。
- 若 `CTest` 能满足 VS Code Testing 需求，则当前阶段不引入自定义 VS Code Testing 扩展。

## 3. Officially verified constraints
### 3.1 VS Code Testing UI 不是 task 列表
根据 VS Code 官方 Testing API / Testing 文档，Testing 视图中的测试实体由扩展/测试控制器提供，而不是任意 task 自动生成。

因此：
- 仅仅把 `P1/P2` 写成 `tasks.json`，并不能满足“在 Testing 面板里看到并运行测试”的目标；
- 当前阶段更合适的做法是优先通过 `CTest` 把测试暴露给 VS Code，而不是继续堆 task。

### 3.2 CMake Presets 天然适合区分 checked-in 与 user-local 配置
根据 CMake 官方文档：
- `CMakePresets.json` 适合提交到仓库，保存共享 preset；
- `CMakeUserPresets.json` 适合保存每个开发者的本地差异项。

因此：
- `LINEAGE_ROOT`、`ADB_SERIAL`、设备型号、特定 lunch target 之类 user-local 信息，不应硬编码进 checked-in 共享配置；
- 应通过 `CMakeUserPresets.json`、env 或 `.vscode` 本地覆盖承接。

### 3.3 CMake Tools / CTest 适合承担第一阶段 Testing UI 集成
结合 VS Code CMake Tools 官方仓库文档与其 CTest/Test Explorer 相关说明，当前阶段可以优先依赖：
- repo-root `CMakeLists.txt`
- `CTest`
- VS Code CMake Tools

来把 `P0` 与命名化的 `P1/P2` 测试暴露进 VS Code 测试体验。

### 3.4 VS Code Debug 配置支持前后置 task
根据 VS Code 官方调试文档与 release notes：
- `launch.json` 支持 `preLaunchTask`
- 也支持 `postDebugTask`

因此 `P3` 的理想形态应是：
- `preLaunchTask` 负责真机 debug 准备（forward / lldb-server / config prep）
- `F5` 启动调试
- `postDebugTask` 收尾

### 3.5 外部脚手架审计已经形成 adopt/adapt/reject 结论
本 change 已基于以下开源参考仓库完成本地下载与结构审计，详见 `reference-audit.md`：
- `cpp-starter-project-cmake`
- `cmake_template`
- `CMake-VSCode-Tutorial`
- `modern-cpp-template`
- `ModernCppStarter`

审计后的结论是：
- **采用**：hidden-base `CMakePresets`、checked-in `.vscode/extensions.json`、`CTest` 作为 VS Code Testing 暴露层；
- **改造后采用**：极简 `.vscode/settings.json`、checked-in `launch.json` 作为 IDE 主入口、repo-managed `gtest`、`CTest` labels；
- **明确不采用**：script-first UX、`CPM/Conan/Vcpkg` 等新依赖管理框架、提交 user-local presets、把 repo-root `CMakeLists.txt` 变成产品构建定义替代物。

## 4. Architecture decision
### 4.1 引入 repo-root CMake orchestration，而不是替换真实构建定义
新增 repo-root `CMakeLists.txt` / `CMakePresets.json`，其职责不是“只做展示层包装”，而是尽量直接托管：
- 统一 build 入口（可委托到现有 Android / Soong 构建流程）
- host-side 测试入口
- 集成测试入口
- debug 准备入口
- IDE/Testing 组织层

它不是 `sucre-snort` Android 真实产物的权威编译定义。真实构建仍以 `Android.bp` / Lineage 为准；但开发者日常 build/test/debug orchestration 应尽量通过 `CMake` 暴露。

结合 CMake 官方文档，第一阶段实现统一 build 入口时，应优先使用 `add_custom_target()` 这类 build-time orchestration 目标来委托现有 Android 流程；`ExternalProject_Add()` 虽然也能驱动外部构建步骤，但更适合 external project / superbuild 场景，不应在当前阶段无谓放大复杂度。

### 4.2 `P0` 继续以 `gtest + CTest` 为核心
当前 `tests/host/CMakeLists.txt` 已经具备 `gtest_discover_tests` 基础。
下一阶段应把它纳入 repo-root workspace，并确保：
- CMake configure/build/test 在 VS Code 内直接可用；
- 测试在 Testing 面板中按 case 粒度可见。

### 4.3 `P1/P2` 优先以命名 `CTest` 测试托管，而不是只保留 shell 入口
现有 `tests/integration/*.sh` 与 `dev/*.sh` 可以作为过渡 backend。
但方向上不应停留在“CMake 调一个旧脚本”这一步，而应尽量收敛为：
- `add_test(NAME p1-... COMMAND ...)`
- `add_test(NAME p2-... COMMAND ...)`
- 必要时把通用逻辑迁到 `cmake/` helper、`cmake -P` 脚本或更稳定的测试驱动层
- 必要时配合 label（如 `p1`, `p2`, `device`, `root-required`）

这样开发者能：
- 在 VS Code Testing 面板里直接看到测试；
- 通过 `ctest -L p1` / `ctest -L p2` 做分组运行；
- 逐步把“脚本是主入口”演化为“CTest 是主入口，脚本只是 backend helper”。

### 4.4 `P3` 以 `launch.json + tasks.json + CMake target` 为用户主入口
`dev/dev-native-debug.sh` 等 backend 可以继续存在，但不应再作为开发者首选入口。
用户主入口应转为：
- checked-in `.vscode/launch.json`
- checked-in `.vscode/tasks.json`
- 必要时由 `CMake` 暴露 debug prep target
- `F5` attach/run 真机

backend 要继续处理：
- `envsetup + lunch`
- AOSP Python
- APatch `su -c`
- 非 root `adbd` 下的 `tcp:<port>` transport fallback
- symbol mirror

这些 Android-specific 细节不应再次暴露给普通日常操作；能前移到 `CMake` target / task orchestration 的部分，应前移过去。

### 4.5 shared config 与 user-local config 分层
建议分层：
- checked-in：`CMakePresets.json`, `.vscode/launch.json`, `.vscode/tasks.json`, `.vscode/settings.json`, `.vscode/extensions.json`
- user-local：`CMakeUserPresets.json` 或本地环境变量

user-local 典型项：
- `LINEAGE_ROOT`
- `ADB_SERIAL`
- 默认 lunch target
- 本机特定工具链路径

这里还应明确一条实现约束：
- 不提交 `CMakeUserPresets.json`、设备串号、私有路径或开发者个人偏好；
- checked-in 配置只保留团队共享且与当前 workflow 强相关的最小集合。

### 4.6 参考脚手架回填后的具体组织约定
结合 `reference-audit.md`，后续实现应遵循以下具体组织约定：
- repo-root `CMakeLists.txt` 负责 workspace / build / test / debug orchestration；其中 build 入口可以委托到现有 Android 流程，但不新增替代 `Android.bp` 的产品构建定义；
- `CMakePresets.json` 使用 hidden-base preset + concrete developer presets 的继承结构，并给出稳定的 build 目录布局；
- `.vscode/settings.json` 保持极简，只放 CMake Tools / IntelliSense / preset workflow 强相关项；
- `.vscode/extensions.json` 只推荐最小必要扩展：`CMake Tools`、`C/C++`、`CodeLLDB`；
- `.vscode/launch.json` 是 `P3` 的用户主入口，backend 脚本只保留 Android 真机细节处理；
- `P1/P2` 的 CTest 暴露应配合 labels（至少 `p1`、`p2`、`device`、`root-required`），以便在 VS Code 与命令行两侧统一分组运行。

### 4.7 `dev/` 目录收敛与脚本归档原则
当前 `dev/` 同时混杂了 build、deploy、host tests、integration、smoke、diagnostics、debug 辅助脚本，后续在本 change 收尾阶段应做一次目录收敛。

清理原则如下：
- 若某个 `dev/` 脚本的能力已经被 `CMake` target、`CTest` 入口、`.vscode` workflow 或其它稳定入口完全替代，则不再保留为主入口，并归档到 `archive/dev/`；
- 若某个脚本仍然有价值，但语义上更属于 `tests/host/`、`tests/integration/`、`cmake/` helper 或其他更清晰的位置，则迁移到正确目录；
- `dev/` 最终只保留少量确实属于 Android 真机 backend helper、诊断辅助、或调试底层适配的脚本；
- 清理时必须同步更新调用链和文档，避免留下重复入口与失效文档；
- 若某脚本暂时仍被新 workflow 间接调用，或仍被下游待实现 change 文档明确引用，则在完全替代前不得提前归档。

这样做的目标不是“删除脚本越多越好”，而是让目录职责更清晰：
- `CMake/CTest/.vscode` 负责开发者主入口；
- `tests/` 负责测试资产与测试驱动；
- `dev/` 只保留少量真正的 backend / diagnose / device-debug helper；
- `archive/dev/` 用于安置已被替代但仍值得保留历史上下文的旧脚本。

## 5. Delivery strategy
为了满足“颗粒度小、不越界”的要求，该 change 的实现应按以下顺序小步提交：
1. repo-root CMake orchestration foundation
2. `P0` → `CMake + CTest + VS Code Testing`
3. `P1/P2` → `CTest` 托管的真机测试
4. `P3` → `F5` / debug orchestration
5. `dev/` script cleanup / archive / relocation

每一步都应保持：
- 不碰 `src/` 产品逻辑；
- 优先把可托管的部分收进 `CMake/CTest`；
- 对暂时不能收进去的部分，才保留 backend helper；
- 可单独回滚。

## 6. Risks and trade-offs
- `P1/P2` 即便进入 Testing 面板，本质上仍依赖真机在线与 root 权限；因此要明确 fail/skip 语义。
- 把集成测试放入 `CTest` 只是“对 IDE 友好的暴露层”，不意味着它们变成纯 host-side 测试。
- `P3` 的 `F5` 仍然会依赖真机状态、USB/ADB、Lineage tree 与符号目录；所以 UI 更统一，不代表 Android 前置条件消失。
- 如果后续发现 `CTest` 对 `P1/P2` 的 UI 表达仍不够理想，再评估是否需要自定义 VS Code Testing 扩展；但这不应作为当前第一阶段前置条件。

## 7. References
- Local audit summary: `openspec/changes/add-vscode-cmake-dev-workflow/reference-audit.md`
- VS Code Testing API: https://code.visualstudio.com/api/extension-guides/testing
- VS Code Testing: https://code.visualstudio.com/docs/debugtest/testing
- VS Code tasks/debug integration: https://code.visualstudio.com/docs/debugtest/debugging
- VS Code `postDebugTask`: https://code.visualstudio.com/updates/v1_31#_postdebugtask
- CMake Presets: https://cmake.org/cmake/help/latest/manual/cmake-presets.7.html
- CMake `add_custom_target()`: https://cmake.org/cmake/help/latest/command/add_custom_target.html
- CMake `ExternalProject`: https://cmake.org/cmake/help/latest/module/ExternalProject.html
- Android native tests with GoogleTest: https://source.android.com/docs/core/tests/development/gtest
- CMake Tools repo: https://github.com/microsoft/vscode-cmake-tools
- Reference scaffold: https://github.com/josephgarnier/cpp-starter-project-cmake
- Reference scaffold: https://github.com/cpp-best-practices/cmake_template
- Reference scaffold: https://github.com/gvcallen/CMake-VSCode-Tutorial
- Reference scaffold: https://github.com/filipdutescu/modern-cpp-template
- Reference scaffold: https://github.com/TheLartians/ModernCppStarter
