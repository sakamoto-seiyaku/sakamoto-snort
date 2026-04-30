# `dev/` backend helpers

`dev/` 只保留 Android / 真机相关 backend helper、诊断工具和 debug 底层适配。
开发者主入口优先使用 repo-root `CMake + CTest + .vscode`，测试资产优先放在
`tests/`。

## 当前主入口

- Daemon build：`cmake --build --preset dev-debug --target snort-build-ndk`
  或 `bash dev/dev-build-ndk.sh`
- Daemon deploy：`bash dev/dev-deploy.sh`
- Real-device smoke：`bash tests/integration/dx-smoke.sh --skip-deploy --cleanup-forward`
- IP matrix：`bash tests/device/ip/run.sh --profile matrix --skip-deploy --cleanup-forward`
- Native debug：VS Code `F5`，backend 为 `dev/dev-vscode-debug-task.py` +
  `dev/dev-native-debug.sh`
- Host tests：`cmake --build --preset dev-debug --target snort-host-tests`

## Build / Deploy

- `dev-setup-ndk.sh`
  - 初始化 / 校验 NDK r29 环境
  - 默认本机 SDK root: `/home/js/.local/share/android-sdk`
  - 默认本机 NDK: `/home/js/.local/share/android-sdk/ndk/29.0.14206865`
- `dev-ndk-env.sh`
  - NDK r29 discovery helper
  - discovery 顺序：`ANDROID_NDK_HOME`、`ANDROID_NDK_ROOT`、
    `$ANDROID_SDK_ROOT/ndk/29.0.14206865`、
    `$ANDROID_HOME/ndk/29.0.14206865`、默认本机路径
- `dev-build-ndk.sh`
  - 使用 NDK r29 / CMake 构建 root daemon
  - 产出 `build-output/sucre-snort-ndk`
  - 同步 stage APK-native artifact:
    `build-output/apk-native/lib/arm64-v8a/libsucre_snortd.so`
- `dev-build-iptest-*.sh` / `dev-build-telemetry-consumer.sh` /
  `dev-build-dx-netd-inject.sh`
  - 使用同一套 NDK r29 discovery helper 构建真机测试辅助二进制
  - 不依赖 Android source tree 或非 SDK/NDK prebuilts
- `dev-deploy.sh`
  - 默认部署 `build-output/sucre-snort-ndk`
  - 支持 `--binary <path>` 作为诊断覆盖
  - 推送、启动、健康检查，并执行真实 vNext `HELLO`

## Debug / Diagnostics

- `dev-native-debug.sh`
  - 使用 NDK r29 host `lldb` 与设备侧 `lldb-server`
  - 不依赖 Android source tree setup 或归档 debug wrapper
  - 默认 host binary: `build-output/sucre-snort-ndk`
- `dev-vscode-debug-task.py`
  - VS Code task helper；`Run` 会先执行 NDK build + stage-only deploy
- `dev-diagnose.sh`
  - 查看当前真机进程、`TracerPid`、socket、日志、iptables、依赖状态
- `dev-tombstone.sh`
  - tombstone 拉取与 NDK r29 `ndk-stack` 符号化

## 常用命令

```bash
cmake --preset dev-debug
cmake --build --preset dev-debug --target snort-build-ndk
bash dev/dev-build-ndk.sh
bash dev/dev-deploy.sh

bash tests/integration/dx-smoke.sh --skip-deploy --cleanup-forward
bash tests/device/ip/run.sh --profile matrix --skip-deploy --cleanup-forward

cmake --build --preset dev-debug --target snort-host-tests
cmake --preset host-asan-clang
cmake --build --preset host-asan-clang --target snort-host-tests

bash dev/dev-setup-ndk.sh --check
eval "$(bash dev/dev-setup-ndk.sh --print-env)"

python3 dev/dev-vscode-debug-task.py workflow run
python3 dev/dev-vscode-debug-task.py workflow attach
python3 dev/dev-vscode-debug-task.py cleanup
```

## 已归档的旧 wrapper

旧 Android source / Soong daemon build 和 AOSP `lldbclient.py` wrapper 已迁到
`archive/dev/`，只保留历史上下文，不再作为活跃 daemon workflow。
旧 daemon `Android.bp` / `sucre-snort.rc` material 已迁到 `archive/soong/`。

## 边界

- `dev/` 不承载产品逻辑实现。
- 当前 daemon 构建路径只有 NDK r29；不要在活跃 workflow 中恢复 Soong daemon build target。
