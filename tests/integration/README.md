# Host-driven integration tests

这里是 `P1` / `P2` 真机测试的主入口目录。

- `P1`：host-driven 真机 baseline integration
- `P2`：rooted 真机平台专项 / compatibility / smoke

## 当前入口

repo-root CMake workspace 现在已经暴露了 lane 级 `CTest` 入口：
- `p1-baseline`
- `p2-device-smoke`

对应到底层脚本仍然是：
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
  - 推送 + 启动 + 健康检查（现在还会做控制协议 `HELLO` 检查，并在需要时清理遗留 debugger）
- `dev/dev-android-device-lib.sh`
  - ADB / rooted device 公共辅助
- `dev/dev-diagnose.sh`
  - 当前真机状态诊断（进程、`TracerPid`、socket、日志、iptables）

已被替代的旧 `dev/` 测试 wrapper 已迁到 `archive/dev/`。

## 示例

```bash
# P1 baseline（repo-root CTest 入口）
cd build-output/cmake/p12 && ctest --output-on-failure -L p1

# P2 rooted 真机平台 smoke（repo-root CTest 入口）
cd build-output/cmake/p12 && ctest --output-on-failure -L p2

# 继续直接调用底层脚本也可以
bash tests/integration/run.sh --skip-deploy --group core,config,app,streams
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
