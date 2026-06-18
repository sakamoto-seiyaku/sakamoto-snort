## Why

当前 vNext session dispatch 会在执行多类 mutation command 前持有 `mutexListeners` 独占锁。该锁同时也是 packet / DNS 热路径进入 verdict 的全局共享锁边界，因此大 `DOMAINLISTS.IMPORT`、`IPRULES.APPLY` 或 domain apply 在解析、校验、编译、文件 I/O 期间会阻塞 datapath verdict，造成 NFQUEUE tail latency spike 与 backlog 风险。

这不是单个命令实现 bug，而是 vNext control-plane mutation serialization 与 datapath global quiesce lock 绑定过紧；需要在发布版本中明确二者职责边界。

## What Changes

- vNext mutation command 不再通过 session dispatch 外层持有 `mutexListeners` 独占锁覆盖整个 handler。
- 新增 control-plane mutation serialization 边界，用于串行化 vNext mutation 彼此之间，并与 `RESETALL` 串行化。
- `mutexListeners` 收敛为 startup / `RESETALL` / packet-DNS hot-path 短窗口使用，不再承载普通 vNext apply/import 的大 CPU 或 I/O 工作。
- 保留现有 vNext wire schema、命令名、返回 shape 和 APPLY/IMPORT 对外原子语义。
- 依赖现有 manager-local locks 与 snapshot publish；只有发现局部中间态风险时，才在对应 manager 内补 batch/atomic API。

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `control-vnext-daemon-base`: vNext daemon dispatch must separate control-plane mutation serialization from the datapath global lock, while keeping `RESETALL` as the only ordinary vNext command that can quiesce packet / DNS hot paths.

## Impact

- Affected code: vNext session dispatch, reset/save runtime coordination, and mutation command locking around domain lists/rules/policy, IPRULES, CONFIG, and METRICS reset.
- Affected docs: concurrency review and reset/runtime concurrency decision docs must describe the new lock responsibilities.
- APIs: no public protocol or JSON schema changes.
- Performance: large vNext mutation commands should no longer block packet / DNS verdict on `mutexListeners`; they may still serialize with other control-plane mutations.
