## Why

当前后端已经有大量 C/C++ 逻辑进入 host-side 测试，但测试工作流仍缺少明确的 Clang 覆盖率产物链路，也缺少一套把 host 可测模块缺口系统补齐的计划。由于内存安全是当前主要风险之一，运行 host 单测时也需要把 ASAN 作为一等入口一并纳入，而不是靠单独手工命令临时补跑。

## What Changes

- 为 host 单测新增明确的 Clang/LLVM 覆盖率产物链路，包括可复现命令与产物位置。
- 补齐不依赖 Android 真机前置的 host-side 单元测试覆盖缺口。
- 保持 Device / DX 真机测试与本 change 分离；真机测试相关 CMake 与脚本不在本 change 中修改。
- 将测试工作流呈现为两个清晰入口：
  - 普通 host `gtest/CTest` 单测入口
  - 同一套 host 单测的 ASAN 入口
- 增加一个高频 host gate，使“跑 host 单测”可以明确地同时覆盖普通 host 与 ASAN。
- 保持产品行为不变；本 change 只涉及 host 测试与工具链。

## Capabilities

### New Capabilities

- `host-test-workflow`：定义 host-side 单测工作流、ASAN 伴随入口、Clang 覆盖率产物链路，以及 host 可测模块覆盖边界。

### Modified Capabilities

None.

## Impact

- 影响范围：
  - `CMakeLists.txt` 中 host-only 的测试/工具入口
  - `CMakePresets.json` 中 host-only 的 preset / workflow
  - `tests/host/`
  - `docs/testing/`
  - 为低耦合模块补测所需的最小 host-test-only seam
- 预期工具链依赖：
  - Clang/LLVM coverage tooling
- 不涉及 Android 真机、daemon 控制协议、前端、产品 API 或运行时功能语义变更。
- 不修改真机测试注册/运行路径，例如 `tests/integration/` 与 `tests/device-modules/`。
