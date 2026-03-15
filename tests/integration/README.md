# Host-driven integration tests

这里是真机集成测试 / 平台专项验证的主入口目录（测试代码运行在 host/WSL，通过 ADB 驱动真机）。

## 当前入口

repo-root CMake workspace 已暴露 lane 级 `CTest` 入口：
- `p1-baseline`（baseline integration；历史命名）
- `p2-device-smoke`（platform smoke；历史命名）
- `perf-network-load`（perf baseline；网络下载触发 NFQ/D 端采样）

对应到底层脚本仍然是：
- `tests/integration/run.sh`
  - baseline integration（控制协议基线 / stream 健康检查 / `RESETALL` 基线）
  - 支持 `--group` / `--case` / `--skip-deploy` / `--serial`
- `tests/integration/device-smoke.sh`
  - rooted 真机平台 smoke / compatibility
  - 覆盖 root/preflight、socket、`netd` 前置、`iptables` / `ip6tables` / `NFQUEUE`、SELinux / AVC、lifecycle restart
- `tests/integration/perf-network-load.sh`
  - 真机 perf baseline：在设备侧用 `curl`/`wget`（若无则尝试 `toybox wget`）对稳定 URL 做 download，产生真实网络 I/O 负载，并读取 `METRICS.PERF`（JSON）
- `tests/integration/full-smoke.sh`
  - 更广的控制协议冒烟回归
  - 不替代 rooted 真机平台 smoke
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
# 首次使用先生成 repo-root CMake workspace
cmake --preset dev-debug

# Baseline integration（repo-root CTest 入口；label `p1` 为历史命名）
cd build-output/cmake/dev-debug && ctest --output-on-failure -L p1

# Rooted platform smoke（repo-root CTest 入口；label `p2` 为历史命名）
cd build-output/cmake/dev-debug && ctest --output-on-failure -L p2

# Perf baseline
cd build-output/cmake/dev-debug && ctest --output-on-failure -L perf

# 继续直接调用底层脚本也可以
bash tests/integration/run.sh --skip-deploy --group core,config,app,streams
bash tests/integration/device-smoke.sh --serial <serial>

# 只跑 platform smoke 的 firewall / selinux
bash tests/integration/device-smoke.sh --skip-deploy --group firewall,selinux

# 若 P2-04 因 libnetd_resolv.so 未挂载而 skip，先准备开发态依赖（case id 为历史命名）
bash dev/dev-netd-resolv.sh prepare
```

## 边界

- 这里只做测试 / tooling，不推进产品逻辑实现。
- baseline integration 与 platform-specific / compatibility 的区别在于覆盖范围，而不是是否使用真机。
- 真机原生调试、LLDB、tombstone workflow 见 `docs/VSCODE_CMAKE_WORKFLOW.md`。
