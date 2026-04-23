# Host-side unit tests

当前仓库使用 **repo-managed GoogleTest (gtest)** 建立最小可运行的 host-side 单元测试基础设施。

## 为什么使用 gtest

- Android 官方原生测试文档把 **GoogleTest** 作为 native C/C++ test 路径。
- GoogleTest 官方 `CMake` quickstart 提供了 `FetchContent` 集成方式。
- 因此当前采用 **`CMake + FetchContent` 固定版本拉取 gtest**，而不是要求开发机预装 `gtest` 系统包。

## 当前覆盖

当前 `tests/host/` 已覆盖以下文档驱动的 low-coupling pure-logic 模块：

- `PackageState`
  - `isValidPackageName()`
  - `parsePackagesListFile()`
  - `parsePackageRestrictionsFile()`（文本 XML + ABX）
- `Rule`
  - `DOMAIN / WILDCARD / REGEX` 的核心匹配语义
- `Settings` 纯 helper
  - `blockMask` / `appMask` 约束
  - per-user 持久化路径 helper
- `Stats / AppStats / DomainStats`
  - 计数更新、聚合桶、`DAY0/WEEK/ALL` 与 `reset` 语义

这些测试都不依赖 Android 真机、socket、NFQUEUE、iptables 或 netd。

当前仍以“文档先行审计 + host-side 补测”为准。模块清单、文档依据、以及暂缓原因统一记录在 `tests/host/P0_PURE_LOGIC_INVENTORY.md`。

## 运行方式

优先推荐 repo-root CMake workspace 入口：

```bash
cmake --preset dev-debug
cmake --build --preset dev-debug --target snort-host-tests
```

也可以直接在 repo-root CMake build dir 里运行：

```bash
ctest --preset dev-debug -L host
```

Host-side ASAN lane 固定使用 Clang，避免误用系统 GCC ASAN：

```bash
cmake --preset host-asan-clang
cmake --build --preset host-asan-clang --target snort-host-tests
ctest --preset host-asan-clang -L host
```

> 注：`host` 是当前 host-side unit tests 的主要 `CTest` label；历史上 `p0` 曾被用于过滤 host 测试，但不再作为主要口径，也不表示 roadmap 阶段号。

repo-root workflow 会：

1. 在同一个 workspace 下暴露 delegated build 与 host-side tests
2. 首次配置时自动下载固定版本 `googletest`
3. 通过 `CTest` 暴露 gtest case，供 VS Code Testing 发现
   - `dev-debug`：`H.<可执行文件>.<GTestSuite>.<TestName>`
   - `host-asan-clang`：`H.ASAN.<可执行文件>.<GTestSuite>.<TestName>`
   - `host-coverage-clang`：`H.COV.<可执行文件>.<GTestSuite>.<TestName>`
4. 通过 `snort-host-tests` / `ctest -L host` 运行当前 host-side 单元测试

补充入口：

- `snort-host-tests-asan`：同一套 host 用例的 ASAN lane
- `snort-host-tests-gate`：按顺序运行 normal → ASAN
- `snort-host-coverage`：Clang/LLVM 覆盖率产物（`summary.txt` + `coverage.json`）

## 当前边界

- 这是第一批低耦合测试，不追求高覆盖率
- 不为了测试做大规模重构
- 当前只要求开发机具备 `cmake`、`git` 和标准 C++ 编译器
- repo-root CMake presets 固定使用 `clang` / `clang++` 运行 host-side 测试
- 强 Android 依赖与真机相关逻辑由集成测试 / 真机验证覆盖
