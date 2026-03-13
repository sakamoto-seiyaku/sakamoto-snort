# Host-side unit tests

当前 P0 使用 **repo-managed GoogleTest (gtest)** 建立最小可运行的 host-side 单元测试基础设施。

## 为什么使用 gtest

- Android 官方原生测试文档把 **GoogleTest** 作为 native C/C++ test 路径。
- GoogleTest 官方 `CMake` quickstart 提供了 `FetchContent` 集成方式。
- 因此当前 P0 采用 **`CMake + FetchContent` 固定版本拉取 gtest**，而不是要求开发机预装 `gtest` 系统包。

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

当前 `P0` 仍以“文档先行审计 + host-side 补测”为准。模块清单、文档依据、以及暂缓原因统一记录在 `tests/host/P0_PURE_LOGIC_INVENTORY.md`。

## 运行方式

在仓库根目录执行：

```bash
bash dev/dev-host-unit-tests.sh
```

脚本会：

1. 在 `build-output/host-tests` 下配置 `CMake`
2. 首次构建时自动下载固定版本 `googletest`
3. 构建 `package_state_tests`
4. 通过 `ctest` 运行全部当前 host-side 单元测试

## 当前边界

- 这是第一批低耦合测试，不追求高覆盖率
- 不为了测试做大规模重构
- 当前只要求开发机具备 `cmake`、`git` 和标准 C++ 编译器
- 强 Android 依赖与真机相关逻辑留给后续 phases
