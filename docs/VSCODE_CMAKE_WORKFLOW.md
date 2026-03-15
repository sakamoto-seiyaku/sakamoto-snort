# VS Code + CMake workspace config boundary

## Scope
这份文档只说明 **repo-root VS Code + CMake workspace** 的 shared config / user-local config 边界。

当前原则是：
- `CMake` 作为开发者统一入口；
- 底层真实 Android 构建仍委托现有 `Android.bp + Soong` 流程；
- user-specific 路径、设备和 lunch 选择不进入 checked-in 配置。

## Checked-in shared config
以下文件可以提交到仓库，用于团队共享 workflow：

- `CMakeLists.txt`
- `CMakePresets.json`
- `.vscode/extensions.json`
- `.vscode/settings.json`
- `.vscode/tasks.json`
- `.vscode/launch.json`

这些文件只应该表达：
- workspace 结构
- shared build/test/debug 入口
- VS Code 推荐扩展
- 团队共享的最小 workflow 约定

## User-local config
以下内容只允许放在本地，不进入仓库：

- `CMakeUserPresets.json`
- `LINEAGE_ROOT`
- `DEV_LUNCH_TARGET`
- `DEV_LUNCH_PRODUCT`
- `DEV_TARGET_DEVICE`
- `DEV_PACKAGE_BINARY_PATH`
- `DEV_DIRECT_NINJA_TARGET`
- `DEV_COMBINED_NINJA_PATH`
- `DEV_SOONG_NINJA_PATH`
- `DEV_BUILD_OUTPUT_PATH`
- `DEV_BUILD_JOBS`
- `ADB_SERIAL`

这些变量对应的是开发者私有环境差异：
- 本机 Lineage/AOSP checkout 路径
- 默认 lunch target / 设备代号
- 特定设备串号
- 某些机型专属的 out 路径或 direct-ninja 目标路径

## Local override example
本地若需要为 VS Code/CMake workspace 指定自定义环境，请创建未提交的 `CMakeUserPresets.json`，或在启动 VS Code 前导出环境变量。

## Host-side unit tests in VS Code
当前 repo-root workspace 已将 `tests/host/` 纳入 CMake/CTest。

推荐工作流：
- 在 VS Code WSL 窗口打开仓库根目录；
- workspace 会默认使用 `dev-debug` preset（见 `.vscode/settings.json`）；
- 首次进入时可执行 task `snort-configure-dev-debug`，或直接让 `F5` / 其他 checked-in task 自动触发 configure；
- 完成 configure 后，VS Code Testing 应通过 `CTest` 看到 host-side gtest case；
- 可在 Testing 面板按 case 运行，也可通过 checked-in CMake task/target 触发 build。

等价 CLI 验证方式：
- `cmake --preset dev-debug`
- `cmake --build --preset dev-debug --target snort-host-tests`

## Real-device integration lanes in VS Code
当前 repo-root workspace 已将 lane 级真机测试暴露为 `CTest`：
- `p1-baseline`（baseline integration；历史命名）
- `p2-device-smoke`（platform smoke；历史命名）

推荐工作流：
- rooted 真机在线；
- 在同一个 repo-root CMake workspace 中完成 configure；
- host/device lane 也可直接走 checked-in targets：`snort-host-tests`、`snort-p1-tests`、`snort-p2-tests`；
- 在 VS Code Testing 中也可按 label/名称运行 `p1-baseline` 或 `p2-device-smoke`。

等价 CLI 验证方式：
- `cmake --preset dev-debug`
- `cmake --build --preset dev-debug --target snort-p1-tests`
- `cmake --build --preset dev-debug --target snort-p2-tests`

当前 skip/fail 约定：
- 未检测到真机、多台真机未指定串号、无法获取 root 等前置不满足场景，`CTest` 会按 skip 语义处理；
- 已进入测试流程后的 deploy / daemon / firewall / selinux 等异常，按 fail 处理；
- deploy 现在会在健康检查里执行一次真实 `HELLO`，并在检测到遗留 `lldb-server` / `TracerPid` 时先清理残留 debugger，避免“进程在 `tracing stop` 但表面仍存活”的假健康状态。

## F5 real-device debug in VS Code
当前 checked-in VS Code 配置已经提供：
- `.vscode/settings.json` 默认启用 `CMake Presets`，并把 workspace 默认 preset 固定到 `dev-debug`
- `.vscode/tasks.json` 中的 `snort-configure-dev-debug`、`snort-build`、`snort-deploy-stage`、`snort-debug-attach-workflow`、`snort-debug-run-workflow`、`snort-debug-cleanup`、`snort-host-tests`、`snort-p1-tests`、`snort-p2-tests`
- `.vscode/launch.json` 中的 `Sucre Snort: Attach (real device)` / `Sucre Snort: Run (real device)`

当前工作流是：
- 按下 `F5` 后，`preLaunchTask` 会先进入 checked-in VS Code task；该 task 先执行 `cmake --preset dev-debug`，再通过 `cmake --build --preset dev-debug --target ...` 调起对应 workflow target
- `Run` 配置会顺序执行：cleanup → incremental build → stage-only deploy → prepare run
- `Attach` 配置会顺序执行：cleanup → prepare attach
- VS Code helper 会直接在设备上拉起 `arm64-lldb-server`、建立 `adb forward tcp:<port> tcp:<port>`，并生成 CodeLLDB 所需的 launch 片段
- `Run` 模式会保留启动时的 `SIGSTOP`（让进程先停在入口），以便 VS Code/CodeLLDB 在继续运行前安装断点；同时会屏蔽 `SIGCHLD` 噪音，避免被频繁的子进程信号打断
- `Run` 模式同时会设置 `target.skip-prologue=false`，这样像 `src/sucre-snort.cpp:49` 这类 `main` 入口行断点也能停在函数入口，而不是被默认跳到序言后的首个可执行点
- helper 还会把编译时源码前缀 `system/sucre-snort` 映射回当前工作区根目录，确保 VS Code 里用工作区绝对路径下的断点也能正确绑定到 DWARF 中的源码路径
- 在 attach / run 前，backend 会先清理设备上的残留 `lldb-server`、残留 `TracerPid`，并在 run 模式下顺带停掉旧的 `sucre-snort-dev` 与旧 socket
- helper 会把生成的 CodeLLDB 配置片段转成稳定的 `.lldb` 命令文件，供 checked-in `launch.json` 使用
- `launch.json` 的 `preRunCommands` 会把 CodeLLDB 的 `Restart` 生命周期接回真机（重建真机 `lldb-server` + 可选的增量编译/部署）：
  - `Run` 的 `Restart` 会重新执行 incremental build → stage-only deploy → 设备侧 `lldb-server` 重建；
  - `Attach` 的 `Restart` 会清理上一次附加残留并重新 attach；
- `Stop` 则由 `postDebugTask` 触发 `snort-debug-cleanup`，完成真机侧收尾与 helper 退出。
- 调试结束后，`postDebugTask` 会执行 cleanup，向后台 helper 发送换行并收尾

当前边界：
- 该流程依赖 `LINEAGE_ROOT` 可用；
- 默认继续使用 `dev/dev-native-debug.sh` 中的端口 / host binary 约定；对于 `/data/local/tmp/*` 开发态二进制，backend 会优先使用 `build-output/sucre-snort.debug`，若缺失则按 Build ID 自动回退到 Soong `unstripped` 产物；
- `launch.json` 本身不再直接依赖 `${env:LINEAGE_ROOT}` 去做 `sourceMap`，而是由 helper 把实际 `sourceMap` 物化到 `.lldb` 命令文件里；
- 若需要机型差异覆盖，仍通过本地环境变量处理，而不是改 checked-in 配置。

## Legacy wrappers

已被当前 workflow 完全替代的旧 `dev/` 测试 wrapper 已迁到 `archive/dev/`：
- `dev-host-unit-tests.sh`
- `dev-integration-tests.sh`
- `dev-device-smoke.sh`

当前开发者主入口应优先使用 repo-root `CMake + CTest + .vscode`，以及 `tests/integration/` 下的实际测试脚本。

## Version note
- repo-root `CMakeLists.txt` 当前保持 `cmake 3.18` 可配置；
- `CMakePresets.json` 需要 `cmake 3.19+` 才能被 `cmake --preset ...` 或 VS Code CMake preset workflow 直接消费。

如果本机 `cmake` 版本较旧，可以先用普通 `cmake -S . -B ...` 完成基础配置；但当前 checked-in VS Code / task workflow 已默认基于 presets，因此要完整使用这套入口，仍建议使用支持 presets / build presets / test presets 的版本。
