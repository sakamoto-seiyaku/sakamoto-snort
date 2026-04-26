# Testing 文档入口

更新时间：2026-04-24

当前仓库的测试讨论只区分两类运行环境：

- `Host`：本机 `gtest/CTest`；`ASAN` 是同一套 `Host` 用例的构建变体
- `Device / DX`：ADB + root 真机脚本、平台 smoke、测试模组、perf/longrun

说明：

- 仓库里现有 `p0/p1/p2` 只是历史 `CTest` label，不再作为当前路线图阶段名
- 当前默认开发 preset 已设置 `SNORT_ENABLE_DEVICE_TESTS=OFF`，因此日常 `dev-debug` / `host-asan-clang` 先聚焦 `Host`

## 当前优先阅读

- `docs/testing/HOST_TEST_SURVEY.md`
  - 当前 `Host` 端测试现状、`ASAN` 结果、覆盖缺口
- `docs/testing/DEVICE_TEST_REORGANIZATION_CHARTER.md`
  - `Device / DX` 真机测试重组纲领；记录当前关于 `smoke / diagnostics / archive`、`vNext` 主线与迁移源的共识
- `docs/testing/DEVICE_TEST_COVERAGE_MATRIX.md`
  - `Device / DX` 覆盖矩阵（feature × entrypoint）+ 当前缺口与建议归类
- `tests/host/README.md`
  - `Host` 运行方式与边界
- `tests/integration/README.md`
  - host 驱动的真机集成入口
- `docs/testing/ip/IP_TEST_MODULE.md`
  - IP `DX` 模组入口、profile 与记录口径
- `docs/testing/PERFORMANCE_TEST_RECORD.md`
  - 性能记录与基线样本

## 常用入口

### Host

```bash
cmake --preset dev-debug
cmake --build --preset dev-debug --target snort-host-tests

# ASAN：同一套 Host 用例的构建变体
cmake --build --preset dev-debug --target snort-host-tests-asan

# TSan：Conntrack 并发专项
cmake --build --preset dev-debug --target snort-host-tests-tsan

# Gate：normal -> ASAN
cmake --build --preset dev-debug --target snort-host-tests-gate
```

在 VS Code（CMake Tools Testing）里，Host 用例名会带一个 lane 前缀，便于过滤/区分：

- `dev-debug`：`H.<可执行文件>.<GTestSuite>.<TestName>`
- `host-asan-clang`：`H.ASAN.<可执行文件>.<GTestSuite>.<TestName>`
- `host-tsan-clang`：`H.TSAN.<可执行文件>.<GTestSuite>.<TestName>`
- `host-coverage-clang`：`H.COV.<可执行文件>.<GTestSuite>.<TestName>`

如果只想直接在 ASAN build dir 内跑（跳过 wrapper）：

```bash
cmake --preset host-asan-clang
cmake --build --preset host-asan-clang --target snort-host-tests
```

TSan 专项默认只跑 Conntrack stress，避免把日常 gate 拉长：

```bash
cmake --build --preset dev-debug --target snort-host-tests-tsan
```

Coverage（Clang/LLVM）：

```bash
cmake --preset host-coverage-clang
cmake --build --preset host-coverage-clang --target snort-host-coverage
```

产物位置（都在 build dir 下，不写入仓库）：

- `build-output/cmake/host-coverage-clang/coverage/summary.txt`
- `build-output/cmake/host-coverage-clang/coverage/coverage.json`

说明：

- coverage workflow 当前只产出报告，不作为数值阈值 gate。
- 需要 `llvm-profdata` / `llvm-cov` 在 PATH 中，否则 `snort-host-coverage` target 不可用。
- `tests/host/` 通过 `FetchContent` 拉取 googletest；如果运行环境无法访问 GitHub，可用 `-DFETCHCONTENT_SOURCE_DIR_GOOGLETEST=<本地 gtest 源码目录>` 覆盖下载步骤。

### Device / DX

```bash
cmake --preset dev-debug -DSNORT_ENABLE_DEVICE_TESTS=ON

# 总入口（固定顺序：platform -> control -> datapath）
cmake --build --preset dev-debug --target snort-dx-smoke

# 分段入口（需要时单跑）
cmake --build --preset dev-debug --target snort-dx-smoke-platform
cmake --build --preset dev-debug --target snort-dx-smoke-control
cmake --build --preset dev-debug --target snort-dx-smoke-datapath

# 或直接用 ctest：
cd build-output/cmake/dev-debug && ctest --output-on-failure -R ^dx-smoke$

# diagnostics（按需；不做 gate）
cd build-output/cmake/dev-debug && ctest --output-on-failure -R ^dx-diagnostics$
cd build-output/cmake/dev-debug && ctest --output-on-failure -R ^dx-diagnostics-perf-network-load$
```

说明：
- `dx-smoke-control` 复用 `tests/integration/vnext-baseline.sh`（vNext-only）。
- `dx-smoke-datapath` 调用 `tests/device/ip/run.sh --profile smoke`（vNext-only）。
- diagnostics 主入口：`dx-diagnostics` / `dx-diagnostics-perf-network-load`（vNext-only）。
- legacy 的 `p1/p2/ip-smoke` 入口不再注册到 `CTest/VS Code Testing`；仅作为迁移源按需回查（见 `docs/testing/DEVICE_TEST_REORGANIZATION_CHARTER.md`）。
- `dx-diagnostics-perf-network-load` 当前在部分设备/环境下会因为 DNS hook 不活跃而打印 `SKIP: dx-diagnostics-perf-network-load ...`（仅跳过 DNS 断言；核心 perfmetrics/METRICS(perf) 断言仍执行）。若用 CTest 运行，可能会因此被标记为 `Skipped`。
- `tests/device/ip/run.sh --profile perf` 当前在默认 `IPTEST_PERF_TRAFFIC_RULES=2000` 的大 ruleset 下可能出现 `BLOCKED: ... IPRULES.APPLY transport failed (rc=126)`；可临时用 `IPTEST_PERF_TRAFFIC_RULES=200` 验证链路，后续再专项修复大 ruleset 的 apply 路径。

当前 `Device / DX` 重组讨论与后续 change 的上层边界，统一以 `docs/testing/DEVICE_TEST_REORGANIZATION_CHARTER.md` 为准。

## 相关索引

- `docs/testing/IPRULES_DEVICE_VERIFICATION.md`
- `docs/testing/ip/CONNTRACK_CT_TIER1_VERIFICATION.md`
- `docs/testing/ip/BUG_kernel_panic_sock_ioctl.md`
- `docs/testing/DEVICE_TEST_COVERAGE_MATRIX.md`
- 归档参考：`docs/testing/archive/TEST_COMPONENTS_MANIFESTO.md`
