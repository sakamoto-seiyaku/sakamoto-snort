# `dev/` backend helpers

`dev/` 不再承担“所有开发入口都放这里”的职责。

当前约定是：

- 开发者主入口优先使用 repo-root `CMake + CTest + .vscode`
- 测试资产优先放在 `tests/`
- `dev/` 只保留少量 Android / 真机相关的 backend helper、诊断工具和 debug 底层适配

## 当前主入口

- 构建
  - 首选：repo-root CMake target `snort-build`
  - backend：`dev/dev-build.sh`
- `P0` host-side 单测
  - 首选：repo-root `CTest` / `snort-host-tests`
  - 实际测试资产：`tests/host/`
- `P1` host-driven 真机 baseline
  - 首选：repo-root `CTest` 的 `p1-baseline`
  - 实际入口：`tests/integration/run.sh`
- `P2` rooted 真机 smoke / compatibility
  - 首选：repo-root `CTest` 的 `p2-device-smoke`
  - 实际入口：`tests/integration/device-smoke.sh`
- `P3` 真机 native debug
  - 首选：VS Code `F5`
  - backend：`dev/dev-vscode-debug-task.py` + `dev/dev-native-debug.sh`

## `dev/` 中保留的内容

### Build / deploy backend

- `dev-build.sh`
  - 委托现有 Android / Soong 编译流程
  - 默认产出 `build-output/sucre-snort`，并在找到同 Build ID 的 `unstripped` 产物时额外产出 `build-output/sucre-snort.debug`
- `dev-deploy.sh`
  - 推送、启动、健康检查
  - 当前会额外执行真实 `HELLO` 检查
  - 若发现遗留 `lldb-server` / `TracerPid`，会先清理再停启守护进程
- `dev-android-device-lib.sh`
  - ADB / APatch root / rooted 真机公共辅助
- `dev-netd-resolv.sh`
  - 开发态准备 `libnetd_resolv.so` / SELinux permissive

### Diagnose / debug backend

- `dev-diagnose.sh`
  - 查看当前真机上的进程、`TracerPid`、socket、日志、iptables、依赖状态
- `dev-native-debug.sh`
  - Android native debug backend；手工 `attach/run` 继续兼容 AOSP `lldbclient.py`，VS Code helper 则走更快的直连 `lldb-server` 路径
  - 对 `/data/local/tmp/*` 开发态二进制，会优先使用 `build-output/<name>.debug`；若默认 host binary 已 strip，则按 Build ID 自动回退到 Soong `unstripped` 产物做符号解析
- `dev-lldbclient-wrapper.py`
  - AOSP `lldbclient.py` 兼容包装
- `dev-vscode-debug-task.py`
  - VS Code task helper
- `dev-tombstone.sh`
  - tombstone 拉取与符号化

## 已归档的旧 wrapper

以下脚本已被当前 workflow 完全替代，已迁到 `archive/dev/`：

- `dev-host-unit-tests.sh`
- `dev-integration-tests.sh`
- `dev-device-smoke.sh`
- `dev-smoke.sh`
- `dev-smoke-lib.sh`

## 常用命令

```bash
# 1) repo-root CMake preset configure（host 侧固定使用 Clang）
cmake --preset dev-debug

# 2) delegated Android build / deploy / debug helpers
cmake --build --preset dev-debug --target snort-build
cmake --build --preset dev-debug --target snort-deploy-stage
cmake --build --preset dev-debug --target snort-debug-run-workflow
cmake --build --preset dev-debug --target snort-debug-attach-workflow
cmake --build --preset dev-debug --target snort-debug-cleanup

# 3) P0 / P1 / P2
cmake --build --preset dev-debug --target snort-host-tests
cmake --preset host-asan-clang
cmake --build --preset host-asan-clang --target snort-host-tests
cmake --build --preset dev-debug --target snort-p1-tests
cmake --build --preset dev-debug --target snort-p2-tests

# 4) diagnose / deploy
bash dev/dev-diagnose.sh
bash dev/dev-deploy.sh

# 5) VS Code debug backend fallback
python3 dev/dev-vscode-debug-task.py prepare attach
python3 dev/dev-vscode-debug-task.py cleanup
```

## 边界

- `dev/` 只做 test / debug / tooling 的 backend helper，不承载产品逻辑实现。
- 若后续某个脚本已被 `CMake` / `CTest` / `.vscode` 主入口完全替代，应继续迁出或归档，而不是把 `dev/` 重新堆回“大杂烩”。
