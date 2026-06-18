## Why

当前 observability streams（DNSSTREAM/PKTSTREAM/ACTIVITYSTREAM）是 legacy control surface，输出格式与 vNext 约束不一致（strict JSON、netstring framing、envelope invariants），且容易在 hot path 引入 socket I/O 风险。需要一个 vNext-compatible 的 streaming surface 来支持可靠、可扩展的实时可观测性（含 replay/notice/drop 语义），并为后续 domain/ip 融合相关的可观测性工作打基础。

## What Changes

- Add vNext streaming commands `STREAM.START` / `STREAM.STOP` with a server→client event channel over the existing vNext connection.
- Implement a bounded, async stream delivery pipeline (ring + pending queue) that never performs socket I/O on dataplane/hot paths.
- Emit strict-JSON vNext stream events (netstring framed) including required `notice` semantics (`started`, `suppressed`, `dropped`) and replay rules.
- Ensure stream lifecycle integrates with `RESETALL` (force stop + clear buffers) and uses `tracked` gating for per-app events.
- Add host + integration tests for stream start/stop, notice semantics, and basic event emission.

## Capabilities

### New Capabilities

- `control-vnext-stream-surface`: Define the vNext `STREAM.*` command surface and stream event semantics (state machine, replay, notice, drop/suppress behavior, and envelope/JSON invariants).

### Modified Capabilities

- (none)

## Impact

- Control plane: `src/ControlVNextSession*` (command dispatch + session lifecycle) and new stream implementation files.
- Dataplane hooks: `src/DnsListener.cpp`, `src/PacketListener.cpp` (enqueue snapshots; counters remain gated only by BLOCK).
- Tests: new/extended `tests/host/*` and `tests/integration/*` to cover vNext streaming behavior.
