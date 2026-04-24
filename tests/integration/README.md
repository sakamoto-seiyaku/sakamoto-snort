# Host-driven integration tests

这里是真机集成测试 / 平台专项验证的主入口目录（测试代码运行在 host/WSL，通过 ADB 驱动真机）。

## 当前入口

repo-root CMake workspace 已暴露 lane 级 `CTest` 入口：
- `dx-smoke`（DX smoke 总入口；固定顺序 `platform -> control -> datapath`；vNext-only）
- `dx-smoke-platform`（平台 gate；vNext-only）
- `dx-smoke-control`（vNext 控制面基线；vNext-only）
- `dx-smoke-datapath`（IP 模组 datapath 闭环：`--profile smoke`；vNext-only）
- `dx-diagnostics`（DX diagnostics 总入口；当前只聚合 `perf-network-load`；vNext-only）
- `dx-diagnostics-perf-network-load`（真机真实下载负载下的 perf metrics 观测；vNext-only）

对应到底层脚本仍然是：
- `tests/integration/dx-smoke.sh`
  - 总入口（只做聚合与顺序 gate）
- `tests/integration/dx-smoke-platform.sh`
  - 平台 gate：root/preflight、socket、`iptables/ip6tables`/`NFQUEUE`、SELinux/AVC、lifecycle restart
- `tests/integration/dx-smoke-control.sh`
  - wrapper：调用 `tests/integration/vnext-baseline.sh`
- `tests/integration/dx-smoke-datapath.sh`
  - wrapper：调用 `tests/device/ip/run.sh --profile smoke`
- `tests/device/diagnostics/dx-diagnostics.sh`
  - diagnostics 总入口（只做聚合与顺序）
- `tests/device/diagnostics/dx-diagnostics-perf-network-load.sh`
  - diagnostics 子入口：真机下载负载下观测 `METRICS(name=perf)`（vNext）
- `tests/device/ip/run.sh`
  - IP/L3-L4 真机测试模组（Tier-1 `netns+veth` 受控拓扑 + 可复现流量 + perf baseline 记录）
  - 说明与 run records：`docs/testing/ip/IP_TEST_MODULE.md`
  - 已知环境 bug：Pixel 6a 上 toybox `nc -L sh -c ...` 可能触发 `sock_ioctl` kernel panic（见 `docs/testing/ip/BUG_kernel_panic_sock_ioctl.md`）；模组默认避开该模式
  - 说明：active DX smoke 走 `--profile smoke`（vNext-only）；旧 mixed/legacy 回查入口见 `tests/archive/device/ip/run_legacy.sh`
- `tests/integration/lib.sh`
  - integration 公共辅助函数

说明：
- legacy 的 `p1/p2/ip-smoke` 入口不再注册到 `CTest/VS Code Testing`；它们作为迁移源按需回查时，只能通过脚本路径显式运行。

## Archive / 回查入口（legacy）

以下脚本位于 `tests/archive/`，仅供迁移核对/历史回查，不注册到 `CTest/VS Code Testing`：

- `tests/archive/integration/run.sh`
  - legacy baseline integration（控制协议基线 / stream 健康检查 / `RESETALL` 基线）
  - 支持 `--group` / `--case` / `--skip-deploy` / `--serial`
- `tests/archive/integration/iprules.sh`
  - legacy IPRULES v1 基础验收（控制面校验 + 少量 ICMP + PKTSTREAM/overlay + 持久化）
- `tests/archive/integration/iprules-device-matrix.sh`
  - legacy IPRULES v1 真机规则矩阵（大量组合/边界：TCP/UDP/ICMP + proto/dir/iface/ifindex/CIDR/ports）
  - runbook：`docs/testing/IPRULES_DEVICE_VERIFICATION.md`
- `tests/archive/integration/device-smoke.sh`
  - rooted 真机平台 smoke / compatibility（legacy 混合职责）
  - 覆盖 root/preflight、socket、`netd` 前置、`iptables` / `ip6tables` / `NFQUEUE`、SELinux / AVC、lifecycle restart
- `tests/archive/integration/full-smoke.sh`
  - 更广的 legacy 控制协议冒烟回归
  - 不替代 `dx-smoke-platform`

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
# 首次使用先生成 repo-root CMake workspace
cmake --preset dev-debug -DSNORT_ENABLE_DEVICE_TESTS=ON

# DX smoke gate（repo-root CTest 入口）
cd build-output/cmake/dev-debug && ctest --output-on-failure -R ^dx-smoke$

# 分段入口（按需）
cd build-output/cmake/dev-debug && ctest --output-on-failure -R ^dx-smoke-platform$
cd build-output/cmake/dev-debug && ctest --output-on-failure -R ^dx-smoke-control$
cd build-output/cmake/dev-debug && ctest --output-on-failure -R ^dx-smoke-datapath$

# Diagnostics / perf baseline
cd build-output/cmake/dev-debug && ctest --output-on-failure -R ^dx-diagnostics$
cd build-output/cmake/dev-debug && ctest --output-on-failure -R ^dx-diagnostics-perf-network-load$

# 继续直接调用底层脚本也可以
bash tests/archive/integration/run.sh --skip-deploy --group core,config,app,streams
bash tests/archive/integration/device-smoke.sh --serial <serial>   # 回查入口

# 只跑 platform smoke 的 firewall / selinux
bash tests/archive/integration/device-smoke.sh --skip-deploy --group firewall,selinux

# 若 P2-04 因 libnetd_resolv.so 未挂载而 skip，先准备开发态依赖（case id 为历史命名）
bash dev/dev-netd-resolv.sh prepare
```

## 边界

- 这里只做测试 / tooling，不推进产品逻辑实现。
- baseline integration 与 platform-specific / compatibility 的区别在于覆盖范围，而不是是否使用真机。
- 真机原生调试、LLDB、tombstone workflow 见 `docs/tooling/VSCODE_CMAKE_WORKFLOW.md`。
