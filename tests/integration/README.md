# Host-driven integration tests

这里是 `P1` / `P2` 真机测试的主入口目录。

- `P1`：host-driven 真机 baseline integration
- `P2`：rooted 真机平台专项 / compatibility / smoke

## 当前入口

- `tests/integration/run.sh`
  - `P1` host-driven baseline
  - 支持 `--group` / `--case` / `--skip-deploy` / `--serial`
- `tests/integration/device-smoke.sh`
  - `P2` rooted 真机平台 smoke / compatibility
  - 覆盖 root/preflight、socket、`netd` 前置、`iptables` / `ip6tables` / `NFQUEUE`、SELinux / AVC、lifecycle restart
- `tests/integration/full-smoke.sh`
  - 更广的控制协议冒烟回归
  - 不替代 `P2` 的平台专项 smoke
- `tests/integration/lib.sh`
  - integration 公共辅助函数

## 相关工具

- `dev/dev-deploy.sh`
  - 推送 + 启动 + 健康检查
- `dev/dev-android-device-lib.sh`
  - ADB / rooted device 公共辅助
- `dev/dev-device-smoke.sh`
  - `P2` 兼容 wrapper → `tests/integration/device-smoke.sh`

## 示例

```bash
# P1 baseline（推荐）
bash tests/integration/run.sh --skip-deploy --group core,config,app,streams

# P2 rooted 真机平台 smoke
bash tests/integration/device-smoke.sh --serial <serial>

# 只跑 P2 firewall / selinux
bash tests/integration/device-smoke.sh --skip-deploy --group firewall,selinux

# 若 P2-04 因 libnetd_resolv.so 未挂载而 skip，先准备开发态依赖
bash dev/dev-netd-resolv.sh prepare
```

## 边界

- 这里只做测试 / tooling，不推进产品逻辑实现。
- `P1` 与 `P2` 的区别是 baseline integration vs platform-specific / compatibility，而不是是否使用真机。
- 真机原生调试、LLDB、tombstone 仍属于 `P3`。
