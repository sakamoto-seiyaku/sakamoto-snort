## 1. OpenSpec docs (this change)
- [x] 1.1 完成 `proposal.md` / `tasks.md` / `design.md` 与 capability spec delta（`specs/vscode-cmake-development/spec.md`）
- [x] 1.2 `openspec validate add-vscode-cmake-dev-workflow --strict` 通过

## 2. Workspace foundation
- [ ] 2.1 新增 repo-root `CMakeLists.txt`，作为 developer workflow orchestration 入口
- [ ] 2.2 新增 `CMakePresets.json`，区分 shared preset 与 user-local override 约定
- [ ] 2.3 新增 checked-in `.vscode` 基础配置（extensions/settings）
- [ ] 2.4 文档化 shared config / user-local config 的边界（如 `CMakeUserPresets.json`、`ADB_SERIAL`、`LINEAGE_ROOT`）

## 3. Phase 0 in VS Code Testing
- [ ] 3.1 将现有 `tests/host/` 纳入 repo-root CMake workspace
- [ ] 3.2 确认 `gtest + CTest` 在 VS Code Testing 面板中可发现、可运行
- [ ] 3.3 文档化 P0 的 VS Code 工作流（configure/build/run tests）

## 4. Phase 1 / Phase 2 in VS Code Testing
- [ ] 4.1 为 `P1` baseline integration 提供命名化的 `CTest` 入口
- [ ] 4.2 为 `P2` real-device smoke 提供命名化的 `CTest` 入口
- [ ] 4.3 能迁入 `CMake/CTest` 的测试编排逻辑尽量迁入，仅保留必要 backend helper
- [ ] 4.4 为真机缺失 / 无 root / 前置不满足场景定义清晰的 skip/fail 语义
- [ ] 4.5 文档化在 VS Code 中直接运行 `P1/P2` 的方法

## 5. Phase 3 with F5
- [ ] 5.1 提供 checked-in `.vscode/launch.json` 真机 attach/run 配置
- [ ] 5.2 提供 `preLaunchTask` / `postDebugTask`，收敛真机调试准备与清理
- [ ] 5.3 能迁入 `CMake target` / VS Code orchestration 的 debug 编排逻辑尽量迁入，仅保留必要 backend helper
- [ ] 5.4 文档化 `F5` 真机调试工作流

## 6. Validation
- [ ] 6.1 在 VS Code / WSL 工作区验证 P0 test discovery
- [ ] 6.2 在真机在线条件下验证 P1/P2 从 VS Code 触发
- [ ] 6.3 在真机在线条件下验证 P3 `F5` attach/run
- [ ] 6.4 确认整个 change 未对 `src/` 产品逻辑产生越界改动
