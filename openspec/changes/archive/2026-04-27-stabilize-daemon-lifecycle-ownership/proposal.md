## Why

当前 daemon 缺少统一的 lifecycle ownership 边界：信号退出依赖周期轮询，vNext stream reset 跨线程操作 raw fd，control/DNS client 线程没有明确 active budget 与发送 deadline。出版级交付需要把这些同源风险收敛为简单、直接、可验证的运行时规则，而不是分别打补丁。

## What Changes

- 建立 main-owned shutdown：`SIGINT` / `SIGTERM` / legacy `DEV.SHUTDOWN` 只请求退出，final save 与进程退出只能由 main runtime owner 执行。
- 建立 session-owned fd：stream reset 不返回或操作 bare fd，拥有 socket 的 session 自己观察 reset/cancel 并关闭连接。
- 保留现有 thread-per-client 架构，但为 legacy control、vNext control、DNS netd client 增加 active session budget 与发送 deadline。
- 更新并验证 concurrency review 中 daemon / session lifecycle ownership 相关 findings。

## Capabilities

### New Capabilities
- `daemon-lifecycle-ownership`: daemon shutdown、session fd ownership、control/DNS active session budget 与 slow-client deadline 的发布级运行时契约。

### Modified Capabilities

## Impact

- Affected code: daemon entry/runtime (`src/sucre-snort.cpp` / runtime helpers), legacy control, vNext control/session/stream manager, DNS listener, socket I/O helpers.
- Affected docs: C++ concurrency review lifecycle findings and the new OpenSpec change artifacts.
- Public protocol impact: none; legacy and vNext command wire shapes remain unchanged.
- Runtime impact: packet/DNS verdict hot paths keep their existing semantics; extra coordination is limited to lifecycle/control/session paths.
