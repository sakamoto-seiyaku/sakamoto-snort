# VS Code + CMake Workspace Config Boundary

## Scope

This document describes the checked-in repo-root VS Code + CMake workflow.
The active daemon build path is NDK r29; the old Android source / Soong daemon
workflow is archived and is not exposed as a supported build target.

## Checked-In Shared Config

Shared workflow files:

- `CMakeLists.txt`
- `CMakePresets.json`
- `.vscode/extensions.json`
- `.vscode/settings.json`
- `.vscode/tasks.json`
- `.vscode/launch.json`

These files define workspace structure, shared build/test/debug entrypoints,
recommended VS Code extensions, and team workflow defaults.

## User-Local Config

Keep local-only values out of checked-in config:

- `CMakeUserPresets.json`
- `ANDROID_SDK_ROOT`
- `ANDROID_HOME`
- `ANDROID_NDK_HOME`
- `ANDROID_NDK_ROOT`
- `ADB_SERIAL`
- `SNORT_VSCODE_WORKSPACE_ROOT`

The default local SDK root is `/home/js/.local/share/android-sdk`; CI and other
machines should provide the same NDK version through SDK-root or NDK env vars.

## Build And Tests

Recommended CLI equivalents:

```bash
cmake --preset dev-debug
cmake --build --preset dev-debug --target snort-build-ndk
cmake --build --preset dev-debug --target snort-host-tests
cmake --build --preset dev-debug --target snort-dx-smoke
```

The default VS Code build task is `snort-build-ndk`. The active daemon build
uses the NDK workflow directly and does not call archived Soong wrappers or
Android source graph rebuild targets.

## F5 Real-Device Debug

Checked-in launch configs:

- `Sucre Snort: Attach (real device)`
- `Sucre Snort: Run (real device)`

Workflow:

- `Run` performs cleanup, NDK build, stage-only deploy, then prepares LLDB.
- `Attach` prepares LLDB against an already running daemon.
- `dev/dev-native-debug.sh` resolves NDK r29 through `dev/dev-ndk-env.sh`.
- Host debugging uses NDK `lldb`.
- Device debugging uses NDK `aarch64/lldb-server`, pushed to
  `/data/local/tmp/arm64-lldb-server` when missing.
- Generated `.lldb` command files live under `build-output/vscode-debug/`.

The debug flow does not require Android source tree setup or archived AOSP
debug wrappers. The default host binary is `build-output/sucre-snort-ndk`.

## Archived Wrappers

Historical wrappers are under `archive/dev/`. They are retained only for audit
context and should not be used as active daemon workflow.
