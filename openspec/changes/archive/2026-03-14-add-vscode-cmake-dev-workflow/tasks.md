## 1. OpenSpec docs (this change)
- [x] 1.1 完成 `proposal.md` / `tasks.md` / `design.md` 与 capability spec delta（`specs/vscode-cmake-development/spec.md`）
- [x] 1.2 `openspec validate add-vscode-cmake-dev-workflow --strict` 通过
- [x] 1.3 完成外部 VS Code/CMake/gtest 脚手架审计，并将 adopt/adapt/reject 结论固化到 `reference-audit.md` 与 change 文档

## 2. Workspace foundation
- [x] 2.1 新增 repo-root `CMakeLists.txt`，作为 developer workflow 统一入口，托管 build/test/debug；其中 build 允许调用现有 Android / Soong 流程，但不重写产品构建定义
- [x] 2.2 新增 `CMakePresets.json`，采用 hidden-base preset 继承结构，并区分 shared preset 与 user-local override
- [x] 2.3 新增 checked-in `.vscode` 基础配置（extensions/settings），最小推荐集覆盖 `CMake Tools + C/C++ + CodeLLDB`
- [x] 2.4 文档化 shared config / user-local config 的边界（如 `CMakeUserPresets.json` 仅本地使用、`ADB_SERIAL`、`LINEAGE_ROOT`）

## 3. Phase 0 in VS Code Testing
- [x] 3.1 将现有 `tests/host/` 纳入 repo-root CMake workspace
- [x] 3.2 确认 `gtest + CTest` 在 VS Code Testing 面板中可发现、可运行
- [x] 3.3 文档化 P0 的 VS Code 工作流（configure/build/run tests）

## 4. Phase 1 / Phase 2 in VS Code Testing
- [x] 4.1 为 `P1` baseline integration 提供命名化的 `CTest` 入口，并补充可过滤的 `CTest` labels
- [x] 4.2 为 `P2` real-device smoke 提供命名化的 `CTest` 入口，并补充 `device` / `root-required` 等 labels
- [x] 4.3 能迁入 `CMake/CTest` 的测试编排逻辑尽量迁入，仅保留必要 backend helper
- [x] 4.4 为真机缺失 / 无 root / 前置不满足场景定义清晰的 skip/fail 语义
- [x] 4.5 文档化在 VS Code 中直接运行 `P1/P2` 的方法

## 5. Phase 3 with F5
- [x] 5.1 提供 checked-in `.vscode/launch.json` 真机 attach/run 配置，作为开发者主入口
- [x] 5.2 提供 `preLaunchTask` / `postDebugTask`，收敛真机调试准备与清理
- [x] 5.3 能迁入 `CMake target` / VS Code orchestration 的 debug 编排逻辑尽量迁入，仅保留必要 backend helper
- [x] 5.4 文档化 `F5` 真机调试工作流

## 6. Validation
- [x] 6.1 在 VS Code / WSL 工作区验证 P0 test discovery
- [x] 6.2 在真机在线条件下验证 P1/P2 从 VS Code 触发
- [x] 6.3 在真机在线条件下验证 P3 `F5` attach/run
- [x] 6.4 确认整个 change 未对 `src/` 产品逻辑产生越界改动

## 7. `dev/` script cleanup
- [x] 7.1 审计 `dev/` 下现有脚本，按 build / test / debug / diagnose / backend helper 分类，并识别重复入口
- [x] 7.2 对已被 `CMake` / `CTest` / `.vscode` workflow 完全替代的脚本迁移到 `archive/dev/`
- [x] 7.3 对仍有价值但放错位置的脚本迁移到更合适的目录（如 `tests/`、`cmake/` 或其他位置）
- [x] 7.4 收敛 `dev/` 目录职责，仅保留少量真正的 backend helper / diagnose / device-debug 脚本
- [x] 7.5 同步更新文档与调用入口，避免保留重复主入口或失效说明
