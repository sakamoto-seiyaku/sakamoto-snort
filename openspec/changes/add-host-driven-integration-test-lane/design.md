# Design: Host-driven integration test lane for sucre-snort

## 0. Scope
本 change 只关注 **P1 Host-driven 集成测试**：
- 从 host / WSL 驱动 Android 目标环境执行集成测试
- 建立可重复执行的 deploy / preflight / smoke / cleanup 流程
- 逐步把现有 `dev/dev-smoke.sh` 收敛为可筛选、可自动运行的测试 lane

本 change 不包含真机 LLDB / crash debug，不包含性能专项，不包含必须依赖真机的平台专项验证。

## 1. Context
- Android 官方测试拓扑中，host-driven / host-side 测试由 host 发起并驱动 Android 目标环境执行验证；当前 P1 目标环境收敛为 Android 真机。
- 当前开发环境是 `Codex CLI + VS Code + WSL2`，仓库中已经存在 `dev/dev-smoke.sh`、`dev/dev-smoke-lib.sh`、`dev/dev-deploy.sh` 这套脚本化验证路径。
- 现在真机已恢复可用，因此 P1 主路径直接收敛到真机。
- 对当前项目而言，最现实的路径不是先迁移到完整 Tradefed 套件，而是先把现有 smoke lane 收敛为更稳定、可重复、可脚本化调用的 host-driven integration lane。

## 2. Goals
- 在 host 侧提供一个统一入口，驱动 Android 真机完成端到端验证。
- 优先覆盖 daemon 生命周期、控制面协议、状态修改与基本流式接口行为。
- 让本地迭代可以按 group / case 选择测试，而不是每次都跑完整大脚本。
- 输出可靠的退出码与结果汇总，便于后续并入 CI。

## 3. Non-Goals
- 不在当前 change 里覆盖真机专项平台行为：NFQUEUE 性能、iptables 链兼容性、SELinux 疑难问题等。
- 不在当前 change 里要求完整 AOSP Tradefed/atest 接入。
- 不把当前脚本体系整体重写成另一套框架。
- 不以当前 change 为理由推进 `A/B/C`、可观测性、`IPRULES` 或其他产品功能实现。
- 若确需 test seam，只允许最小、可解释、可审计的范围，且不得顺势扩展为功能重构。

## 4. Implementation decisions
- 测试驱动继续运行在 host / WSL。
- 目标环境抽象为单一 Android target 接口，底层通过 `adb` 与真机通信。
- P1 当前仅维护真机集成测试路径。
- 现有 `dev/dev-smoke.sh` 与 `dev/dev-smoke-lib.sh` 作为实现基底，优先做收敛和结构化，而不是废弃重写。
- 测试入口需要至少支持：target preflight、deploy/start、健康检查、按组执行、失败退出、可选 cleanup/reset。

## 5. Suggested first-wave coverage
- daemon deploy / start / stop
- `HELLO` / `HELP`
- 全局开关与基础参数读写
- `APP.*` 基础查询
- `RESETALL` / save / restore 的基本语义
- `DNSSTREAM` / `PKTSTREAM` / `ACTIVITYSTREAM` 的最小健康检查（仅覆盖基础可用性，不覆盖真机专项平台细节）

## 6. References
- AOSP GoogleTest: https://source.android.com/docs/core/tests/development/gtest
- AOSP Host-side deviceless tests: https://source.android.com/docs/core/tests/tradefed/testing/through-tf/host-side-deviceless-test
- Android Trade Federation overview: https://source.android.com/docs/core/tests/tradefed/architecture/advanced/tf-overview
- ATest guide: https://source.android.com/docs/core/tests/development/atest
