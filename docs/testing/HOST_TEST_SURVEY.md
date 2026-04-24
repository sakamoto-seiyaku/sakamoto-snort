# Host 端测试现状调查

更新时间：2026-04-23
范围：只看纯 `Host` 端 `gtest/CTest`（normal / ASAN）与 Clang 覆盖率产物链路；不涉及 `Device / DX` 真机脚本与 lane。

## 1. 结论先行

- Host 用例统一由 `tests/host/CMakeLists.txt` 通过 `gtest_discover_tests(...)` 注册，并统一打 `ctest` label：`host`。
- 当前 Host 端共有 **18 个 gtest binary / 164 个 case**（`ctest -L host`）。
- repo-root 提供 3 个高频入口（两个入口 + 一个 gate）：
  - `snort-host-tests`：普通 host lane（`ctest --output-on-failure -L host`）
  - `snort-host-tests-asan`：同一套 host 用例的 ASAN lane
  - `snort-host-tests-gate`：按顺序运行 normal → ASAN
- Clang 覆盖率 workflow：
  - preset：`host-coverage-clang`
  - target：`snort-host-coverage`
  - 产物（都在 build dir 下）：`coverage/summary.txt`、`coverage/coverage.json`
- `p0/p1/p2` 是历史 label/文档遗留用语；Host 端不再用 `p0` 作为主要过滤口径。

## 2. 当前 Host 入口是什么

### 2.1 注册方式与 label

- 所有 Host case 都在 `gtest` 下面（通过 CTest 发现/过滤）
- 推荐口径：`ctest -L host`
- 兼容说明：历史上部分文档可能仍写 `p0`，但 Host 端当前以 `host` 为准

### 2.2 日常执行入口

普通 Host：

```bash
cmake --preset dev-debug
cmake --build --preset dev-debug --target snort-host-tests
```

ASAN（推荐用 wrapper，自动配置并跑完）：

```bash
cmake --preset dev-debug
cmake --build --preset dev-debug --target snort-host-tests-asan
```

Host gate（normal -> ASAN）：

```bash
cmake --preset dev-debug
cmake --build --preset dev-debug --target snort-host-tests-gate
```

补充：如果你想直接进入 ASAN build dir 跑：

```bash
cmake --preset host-asan-clang
cmake --build --preset host-asan-clang --target snort-host-tests
```

说明：

- ASAN lane 默认设置 `ASAN_OPTIONS=detect_leaks=0`（避免某些 harness/CI 的 ptrace 环境触发 LeakSanitizer fatal）；如需 leak 检测，可在 `build-output/cmake/host-asan-clang` 内直接跑 `ctest` 并自行配置 `ASAN_OPTIONS`。

## 3. Clang 覆盖率产物链路

### 3.1 入口

```bash
cmake --preset host-coverage-clang
cmake --build --preset host-coverage-clang --target snort-host-coverage
```

### 3.2 产物

在 `build-output/cmake/host-coverage-clang/coverage/`：

- `summary.txt`：`llvm-cov report` 文本 summary
- `coverage.json`：`llvm-cov export` JSON
- `coverage.profdata`、`*.profraw`：profile 数据

说明：

- coverage workflow 当前只产出报告，不作为数值阈值 gate。
- 报告会忽略 `tests/host`、`_deps`、`third_party`（避免把测试代码和第三方库算进来）。

### 3.3 常见环境问题

- `snort-host-coverage` 依赖 `llvm-profdata` / `llvm-cov`；如果环境没装 LLVM tooling，该 target 会不可用。
- `tests/host/` 使用 `FetchContent` 获取 googletest；若环境无法访问 GitHub，可用 `-DFETCHCONTENT_SOURCE_DIR_GOOGLETEST=<本地 gtest 源码目录>` 覆盖下载步骤。

## 4. 当前已经覆盖到什么

### 4.1 有独立 Host 测试文件的模块

- `package_state_tests.cpp`
- `perf_metrics_tests.cpp`
- `reason_metrics_tests.cpp`
- `conntrack_tests.cpp`
- `ip_rules_engine_tests.cpp`（另含 `ip_rules_engine_tests_nocache`）
- `rule_tests.cpp`
- `settings_tests.cpp`
- `stats_tests.cpp`
- `domain_policy_sources_tests.cpp`
- `control_vnext_*_tests.cpp`（codec/ctl/session/stream/domain/iprules/metrics surface）
- `host_gap_tests.cpp`（本 change 新增）：补齐以下模块的 Host 覆盖缺口
  - `DnsRequest`
  - `Saver`
  - `Timer`
  - `SocketIO`
  - `Streamable`
  - `AppManager`
  - `HostManager`
  - `Packet`
  - `PacketManager`
  - `Activity` / `ActivityManager`（先锁定当前可观察/No-op 语义）
  - `CmdLine`（限定为 `/bin/true` no-crash 基线）

### 4.2 直接进入 Host test build 的 `src/*.cpp`

除原本 surface 间接覆盖的模块外，`host_gap_tests` 额外把以下模块直接链入 Host lane（便于 baseline coverage）：

- `Activity.cpp` / `ActivityManager.cpp`
- `AppManager.cpp` / `HostManager.cpp`
- `CmdLine.cpp`
- `DnsRequest.cpp`
- `Packet.cpp` / `PacketManager.cpp`
- `SocketIO.cpp`
- `Streamable.cpp`
- `Timer.cpp`

## 5. 当前明确仍偏向 Device / DX 的模块（未纳入 Host）

以下模块更像运行期接线点/真机前置，不作为本轮 Host 单测优先级：

- `Control.cpp`
- `ControlVNext.cpp`
- `ControlVNextSessionCommandsDaemon.cpp`
- `DnsListener.cpp`
- `PackageListener.cpp`
- `PacketListener.cpp`
- `sucre-snort.cpp`

## 6. 相关文档

- `docs/testing/README.md`
- `tests/host/README.md`
- `tests/host/CMakeLists.txt`
- `tests/integration/README.md`
- `docs/testing/ip/IP_TEST_MODULE.md`
