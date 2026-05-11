## Why

The daemon currently hard-splits NFQUEUE workers by INPUT and OUTPUT queue ranges, so the two directions of one flow can be processed by different listener threads. We need an explicit topology mode switch so the current behavior remains the default while an experimental shared flow pool can be enabled for stability and performance testing.

## What Changes

- Add a persisted vNext device config key `nfqueue.topology`.
- Keep the current/default mode as `split-in-out`.
- Add an experimental mode `shared-flow-pool`, where each IP family uses the same NFQUEUE queue range for INPUT and OUTPUT.
- Make the configured topology take effect only on daemon startup; no runtime hot switch is introduced.
- Require packet direction in shared mode to be derived from the NFQUEUE packet hook, not from the listener thread's queue partition.
- Preserve existing packet, IPRULES, Flow Telemetry, and Debug Stream semantics when direction is derived correctly.

## Capabilities

### New Capabilities

- `nfqueue-topology-modes`: Defines the daemon's NFQUEUE topology modes, startup queue planning, and per-packet direction derivation requirements.

### Modified Capabilities

- `control-vnext-daemon-base`: Extends device-scope `CONFIG.GET/SET` with persisted `nfqueue.topology` validation and reporting.

## Impact

- Affected code: `Settings`, vNext `CONFIG.GET/SET`, `PacketListener` queue planning/rule installation, NFQUEUE callback direction handling, host tests, and device datapath validation.
- Affected APIs: vNext `CONFIG.GET/SET` device key set adds `nfqueue.topology`.
- Affected docs: update the Chinese vNext interface contract in `docs/INTERFACE_SPECIFICATION.md` with the new key, enum values, and next-start-only semantics.
- Affected behavior: default startup behavior remains `split-in-out`; `shared-flow-pool` changes INPUT/OUTPUT queue range assignment after a daemon restart.
- Dependencies: no new third-party dependencies.
