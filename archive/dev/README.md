# Archived `dev/` wrappers

这里存放已经被当前 `CMake` / `CTest` / `tests/` 主入口替代的旧 `dev/` wrapper。

当前已归档：

- `dev-host-unit-tests.sh`
  - 旧入口：host-side gtest wrapper
  - 当前入口：repo-root `CMake + CTest`（如 `snort-host-tests` / `ctest -L p0`）
- `dev-integration-tests.sh`
  - 旧入口：`P1` baseline wrapper
  - 当前入口：`tests/integration/run.sh` 或 repo-root `CTest` 的 `p1-baseline`
- `dev-device-smoke.sh`
  - 旧入口：`P2` rooted smoke wrapper
  - 当前入口：`tests/integration/device-smoke.sh` 或 repo-root `CTest` 的 `p2-device-smoke`
- `dev-smoke.sh`
  - 旧入口：扩展控制协议 smoke wrapper
  - 当前入口：`tests/integration/full-smoke.sh`
- `dev-smoke-lib.sh`
  - 旧入口：旧 smoke 公共库 wrapper
  - 当前入口：`tests/integration/lib.sh`

保留这些文件只是为了归档历史上下文；当前开发者不应再把它们当作主入口。
