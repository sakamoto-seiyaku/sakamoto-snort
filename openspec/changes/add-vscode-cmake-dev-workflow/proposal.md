# Change: VS Code + CMake development workflow for sucre-snort

## Why
当前 `P0/P1/P2/P3` 的底层能力已经分别存在：
- `P0` 有 host-side `gtest`；
- `P1/P2` 有 host / WSL 驱动真机的集成测试入口；
- `P3` 有真机 `LLDB` / `CodeLLDB` 调试 backend。

但开发者实际看到的仍然主要是“分别调用若干脚本”，而不是一个更接近传统 `C/C++ + CMake + VS Code` 项目的工作形态：
- 单元测试不能直接作为 VS Code Testing 面板中的一等对象来查看和运行；
- 真机集成测试还没有被提升成 VS Code 内可直接触发的测试入口；
- 真机 native debug 虽然已具备 backend，但还没有收敛为稳定的 `F5` 工作流；
- 当前工程体验容易被理解成“一切都靠脚本”，而不是“脚本只是 Android/真机适配层，IDE 主入口仍是标准 C/C++ 工作流”。

因此需要新增一个独立 change，把现有 `P0/P1/P2/P3` 能力收敛为 **VS Code + CMake orchestrated workflow**：
- 对开发者呈现尽量接近传统 `C/C++ + CMake` 项目的日常工作流；
- `CMake/CTest` 不只是“再包一层 UI”，而是尽量接管 build/test/debug 的日常编排；
- 但不改写真实的 Android / Lineage / Soong 产物构建主线。

## What Changes
- 在 repo root 引入面向开发者主入口的 **VS Code + CMake orchestrated workspace**。
- 提供 checked-in 的 `CMakeLists.txt` / `CMakePresets.json` / `.vscode` 基础配置，使仓库根目录可直接作为 VS Code C++ 工作区打开。
- 将现有 `P0` host-side `gtest` 真正纳入 `CMake + CTest`，并暴露为 VS Code Testing 面板中的可发现测试。
- 将现有 `P1/P2` 真机集成测试尽量托管到 `CMake/CTest` 命名测试入口，而不是继续让开发者把 shell 脚本当作主入口。
- 将现有 `P3` 真机调试 backend 收敛为 checked-in 的 `launch.json + tasks.json` 工作流，使开发者可以在 VS Code 中直接 `F5` 进入真机 attach / run debug。
- 允许为此改造、收缩或替换当前 `dev/` / `tests/` 中的编排脚本：目标是让能被 `CMake/CTest` 托管的部分尽量托管，而不是要求“旧脚本原封不动，再在外面包一层”。
- 明确区分“CMake 托管的开发者工作流”和“真实 Android 构建层”：前者负责开发者日常编排，后者仍然以 `Android.bp + Lineage/Soong` 为准。

## Relationship to current phases
- 本 change **不替代** `P0/P1/P2/P3` 的阶段定义，而是把它们现有的 test/debug 能力提升为更统一的 VS Code/CMake 开发体验。
- `P0/P1/P2/P3` 仍然表示测试 / 调试阶段顺序；本 change 只是为这些 phase 提供统一入口与工程化外观。
- `P3` 已有的真机调试 backend 不废弃；本 change 在其之上补齐 IDE 主入口。

## Non-Goals
- 不把 `sucre-snort` 的真实产物构建从 `Android.bp + Soong` 改写为纯 `CMake`。
- 不要求保留所有现有脚本的表面形态；但若脚本继续存在，应尽量下沉为 backend helper，而不是开发者主入口。
- 不在本 change 中推进任何 `src/` 产品功能、可观测性、`IPRULES`、`A/B/C` 或其他业务实现。
- 不把当前仓库升级为一个自定义 VS Code 扩展仓库；若 `CTest` 足以承载 Testing UI，则不引入额外扩展开发。
- 不以“更像传统 CMake 项目”为理由，触发与当前目标无关的大规模架构重构。

## Impact
- Affected docs：`docs/NATIVE_DEBUGGING_AND_TESTING.md`, `docs/IMPLEMENTATION_ROADMAP.md`, `dev/README.md`, `tests/host/README.md`, `tests/integration/README.md`
- Affected tooling/code（实现时）：repo-root `CMakeLists.txt`, `CMakePresets.json`, `.vscode/`, `tests/host/`, `tests/integration/`, `dev/`
