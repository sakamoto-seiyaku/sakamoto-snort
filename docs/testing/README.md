# Testing 文档入口

更新时间：2026-04-23

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

# Gate：normal -> ASAN
cmake --build --preset dev-debug --target snort-host-tests-gate
```

在 VS Code（CMake Tools Testing）里，Host 用例名会带一个 lane 前缀，便于过滤/区分：

- `dev-debug`：`H.<可执行文件>.<GTestSuite>.<TestName>`
- `host-asan-clang`：`H.ASAN.<可执行文件>.<GTestSuite>.<TestName>`
- `host-coverage-clang`：`H.COV.<可执行文件>.<GTestSuite>.<TestName>`

如果只想直接在 ASAN build dir 内跑（跳过 wrapper）：

```bash
cmake --preset host-asan-clang
cmake --build --preset host-asan-clang --target snort-host-tests
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
cmake --preset dev-debug

cd build-output/cmake/dev-debug && ctest --output-on-failure -L p1
cd build-output/cmake/dev-debug && ctest --output-on-failure -L p2
cd build-output/cmake/dev-debug && ctest --output-on-failure -L ip-smoke

bash tests/device-modules/ip/run.sh --profile smoke
```

`tests/device-modules/ip/run.sh` 的 profile 可按需要替换为 `smoke / vnext / matrix / stress / perf / longrun`。

当前 `Device / DX` 重组讨论与后续 change 的上层边界，统一以 `docs/testing/DEVICE_TEST_REORGANIZATION_CHARTER.md` 为准。

## 相关索引

- `docs/testing/IPRULES_DEVICE_VERIFICATION.md`
- `docs/testing/ip/CONNTRACK_CT_TIER1_VERIFICATION.md`
- `docs/testing/ip/BUG_kernel_panic_sock_ioctl.md`
- `tests/TEST_COMPONENTS_MANIFESTO.md`
