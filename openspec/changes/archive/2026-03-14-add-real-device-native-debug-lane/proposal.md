# Change: Real-device native debug lane for sucre-snort

## Why
`P3` 的目标不是继续扩展集成测试，而是把 `sucre-snort` 的真机原生调试流程固化下来：在遇到 native 问题时，开发者可以直接 attach / run / breakpoint / tombstone symbolize，而不是只能靠日志反推。

现在真机已经恢复可用，因此可以把这一阶段独立收敛为 **real-device native debug lane**，并继续保持与 `P1` 集成测试的边界分离。

## What Changes
- 提供面向真机的原生调试入口脚本。
- 支持 LLDB attach 到已运行的 `sucre-snort-dev`。
- 支持以 LLDB 方式在真机上直接启动 `/data/local/tmp/sucre-snort-dev`。
- 支持为 VS Code + CodeLLDB 生成调试准备。
- 提供 tombstone 拉取与 `stack` 符号化入口。
- 明确当前项目的原生调试主线统一收敛为 Android 真机，不再维护模拟器专项流程。

## Non-Goals
- 不在本 change 中解决所有平台 bug。
- 不在本 change 中要求引入新的 IDE 或重写现有 build/deploy 流程。
- 不在本 change 中将 P3 与 P1 合并成一个单一脚本。
- 不以当前 change 为理由推进 `A/B/C`、可观测性、`IPRULES` 或其他产品功能实现。
- 除非绝对必要且范围可解释，否则不修改 `src/` 主实现。

## Impact
- Affected docs：`docs/NATIVE_DEBUGGING_AND_TESTING.md`, `dev/README.md`, `docs/IMPLEMENTATION_ROADMAP.md`
- Affected tooling/code（实现时）：`dev/dev-native-debug.sh`, `dev/dev-tombstone.sh`, 以及相关 device/ADB 辅助脚本
