## Why

前端常态 UI 需要 Top destinations / Top ports / timeline / history 等高基数观测能力；这些能力不能继续通过 daemon 内部 metrics 聚合或 Debug Stream 承载，否则会把口径、存储、查询和热路径成本都压回 firewall 进程。

本变更基于 `docs/decisions/FLOW_TELEMETRY_WORKING_DECISIONS.md` 创建 Flow Telemetry Plane：daemon 只以 bounded、best-effort 的方式导出可持久化业务事实 records，由 consumer/前端负责落盘、查询和派生聚合。

## What Changes

- 新增 Flow Telemetry vNext control surface：`TELEMETRY.OPEN` / `TELEMETRY.CLOSE`，用于建立单 consumer telemetry session、传递 shared-memory fd、抢占旧 session，并配置/确认 `Off|Flow` level。
- 新增 fixed-size slot overwrite shared-memory ring export channel：单 consumer、全局 MPSC producers、固定 slot、transport ticket gap detection、record too large / slot busy / consumer absent 等 drop 语义。
- 新增常态业务 records：
  - `FLOW`：packet/conntrack flow 事实，payload 内部区分 `BEGIN / UPDATE / END`。
  - `DNS_DECISION`：blocked-only DNS decision timeline record。
- 新增 minimal telemetry state：通过 vNext metrics 查询暴露 `enabled / consumerPresent / sessionId / slotBytes / slotCount / recordsWritten / recordsDropped / lastDropReason / lastError?`，仅用于通道健康判断。
- 使 Flow Telemetry `Flow` level 成为 conntrack/flow observation consumer：开启后可以驱动 L4-first flow observation；关闭或无 consumer 时保持 hot-path 低成本 gating。
- 同步 `docs/INTERFACE_SPECIFICATION.md`，作为前端仓库可依赖的接口契约。
- 不实现 Debug Stream explainability、前端持久化/查询库、DNS↔IP join、Summary mode、IP_LEAK 重新设计或“全量零丢失”交付保证。

## Capabilities

### New Capabilities

- `control-vnext-telemetry-surface`: vNext `TELEMETRY.OPEN/CLOSE` 命令面、session lifecycle、fd handoff、single-consumer ownership、RESETALL rebuild 语义。
- `flow-telemetry-export-channel`: shared-memory fixed-slot overwrite ring ABI、ticket/gap、drop semantics、producer/consumer lifecycle。
- `flow-telemetry-records`: `FLOW` / `DNS_DECISION` record schema、record lifecycle、counter/export trigger 语义、DNS blocked-only timeline。

### Modified Capabilities

- `control-vnext-metrics-surface`: 新增 `METRICS.GET(name="telemetry")` minimal telemetry state；不新增 records 类型承载 health/stats。
- `l4-conntrack-core`: 明确 Flow Telemetry `Flow` level 是 conntrack/flow observation consumer；无 active consumer 时仍保持 conntrack gating。

## Impact

- Affected APIs: 新增 vNext `TELEMETRY.OPEN/CLOSE`，扩展 `METRICS.GET` name 集合，并更新接口文档。
- Affected code: vNext session/control dispatch、new telemetry exporter/ring/session modules、conntrack/PacketManager/DnsListener hooks、RESETALL lifecycle、minimal metrics/state snapshot。
- Affected tests: host ABI/ring/session tests、vNext control integration tests、device mmap reader path test、packet/DNS record producer tests、performance comparison.
- Dependencies: 使用 Android/Linux 现有 Unix domain socket fd passing 与 shared memory/fd primitives；不引入前端 NDK 要求，不运行 `snort-build-regen-graph` 除非实现阶段修改 `Android.bp`。
