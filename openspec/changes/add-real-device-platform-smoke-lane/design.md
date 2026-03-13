# Design: Real-device platform smoke lane for sucre-snort

## 0. Scope
本 change 只关注 `P2` 的 rooted 真机平台专项 / compatibility / smoke：
- rooted 真机 preflight 与 daemon 健康
- control / DNS socket 存在性检查
- `netd` 相关前置条件检查
- `iptables` / `ip6tables` / `NFQUEUE` 链路 smoke
- SELinux / AVC 健康检查
- shutdown / redeploy / restart lifecycle smoke

## 1. Constraints
- 当前目标环境统一为 rooted Android 真机。
- 继续复用 `tests/integration/` 作为测试入口，`dev/` 仅保留兼容 wrapper 或非测试工具。
- 不修改 `sucre-snort` 主程序架构，不为 `P2` 引入产品逻辑改造。
- `P2` 与 `P3` 都运行在真机上，但前者关注 platform smoke / compatibility，后者关注 LLDB / tombstone / live debug。

## 2. Implementation decisions
- 新增 `tests/integration/device-smoke.sh` 作为 `P2` 主入口，并沿用 `P1` 的 `--serial`、`--skip-deploy`、`--group`、`--case`、`--cleanup-forward` 习惯用法。
- 复用 `tests/integration/lib.sh` 提供的日志、control socket、ADB forward 与 preflight 能力。
- 复用 `dev/dev-deploy.sh` 完成 deploy / restart；`P2` 不另写自己的部署逻辑。
- `NFQUEUE` 验证不假设固定 queue 编号，而是校验：
  - `iptables` / `ip6tables` 链和 hook 已建立；
  - 自定义链里存在 `NFQUEUE` 规则；
  - 通过真机上发起一笔最小 TCP 出站流量，观察 `NFQUEUE` 计数器增长。
- `netd` 相关检查拆成两层：
  - 仓库内可控的 DNS socket 存在性，作为必测项；
  - 外部 debug-base 模块带来的 `libnetd_resolv.so` 挂载，作为环境相关的 compatibility 检查；若缺失则明确 `skip`，而不是借题发挥去改主程序。
- lifecycle smoke 放在最后执行，并在 case 内负责把 daemon 恢复到可用状态。

## 3. Validation strategy
- 在当前 rooted 真机上执行 `bash tests/integration/device-smoke.sh --serial <serial>`。
- 至少验证：
  - socket / SELinux / firewall case 全部通过；
  - `NFQUEUE` 计数 smoke 能观测到计数增长；
  - lifecycle restart 后 daemon 重新可用；
  - `openspec validate add-real-device-platform-smoke-lane --strict` 通过。
