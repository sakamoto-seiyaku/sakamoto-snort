# Change: Real-device platform smoke lane for sucre-snort

## Why
`P1` 已经把 host-driven baseline integration 固化下来，但 rooted Android 真机上的平台专项仍缺一条可重复执行的 smoke / compatibility lane：

- `NFQUEUE` / `iptables` / `ip6tables` 链路是否真的接上；
- socket、权限、SELinux 上下文是否处于可运行状态；
- `netd` 相关前置条件是否就位；
- 真机上的 shutdown / redeploy / restart 是否稳定。

这些问题已经超出 `P1` 的 baseline integration 范围，但也不应该等到 `P3` live debug 时再靠手工排查。因此 `P2` 需要作为一个**独立的 rooted real-device platform smoke change** 收敛下来。

## What Changes
- 新增 rooted 真机平台专项 smoke 入口，落在 `tests/integration/device-smoke.sh`。
- 测试代码继续运行在 host / WSL，由 host 驱动 Android 真机执行验证。
- 复用现有 `dev/dev-deploy.sh` 与 `dev/dev-android-device-lib.sh`，不另起一套割裂框架。
- 覆盖 root/preflight、daemon 健康、socket、`netd` 前置、`iptables` / `ip6tables` / `NFQUEUE`、SELinux / AVC、以及 lifecycle restart smoke。
- 支持按 group / case 运行，并保留 `dev/` 下的兼容 wrapper。

## Relationship to other phases
- `P0 Host-side 单元测试` 已完成并单独提交，不并入本 change。
- `P1 Host-driven 真机基线集成测试` 已完成并单独提交，不并入本 change。
- `P3 真机原生 Debug / crash / LLDB` 仍保持独立，不并入本 change。

## Non-Goals
- 不在本 change 中改动 `src/` 主实现或推进任何产品逻辑。
- 不引入模拟器路径；当前 `P2` 只面向 rooted Android 真机。
- 不把仓库测试体系迁移到另一套重型框架。
- 不把外部 debug-base 模块的安装逻辑塞进当前测试脚本。
- 不把 `P2` 和 `P3` 合并成一个脚本入口。

## Impact
- Affected docs：`docs/IMPLEMENTATION_ROADMAP.md`, `tests/integration/README.md`, `dev/README.md`
- Affected tooling/code：`tests/integration/device-smoke.sh`, `dev/dev-device-smoke.sh`
