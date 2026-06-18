# control-vnext-telemetry-surface Specification

## Purpose
Defines the vNext Flow Telemetry control surface used to open and close the shared-memory telemetry export channel.

## Requirements

### Requirement: Daemon exposes TELEMETRY.OPEN and TELEMETRY.CLOSE
The daemon MUST implement vNext `TELEMETRY.OPEN` and `TELEMETRY.CLOSE` commands.

`TELEMETRY.OPEN.args` MUST be an object with:
- `level` (required string): `off` or `flow`
- `config` (optional object): telemetry parameters; omitted fields use daemon defaults

`config`, when present, MAY contain only:
- `slotBytes` (u32)
- `ringDataBytes` (u64)
- `pollIntervalMs` (u32)
- `bytesThreshold` (u64)
- `packetsThreshold` (u64)
- `maxExportIntervalMs` (u32)
- `blockTtlMs` (u32)
- `pickupTtlMs` (u32)
- `invalidTtlMs` (u32)
- `maxFlowEntries` (u32)
- `maxEntriesPerUid` (u32)

The daemon MUST follow vNext envelope and strict reject rules for unknown top-level or args keys.

#### Scenario: Unknown args key is rejected
- **WHEN** client sends `{"id":1,"cmd":"TELEMETRY.OPEN","args":{"level":"flow","x":1}}`
- **THEN** daemon SHALL respond `ok=false` with `error.code="SYNTAX_ERROR"`

#### Scenario: Unknown telemetry level is rejected
- **WHEN** client sends `{"id":2,"cmd":"TELEMETRY.OPEN","args":{"level":"debug"}}`
- **THEN** daemon SHALL respond `ok=false` with `error.code="INVALID_ARGUMENT"`

### Requirement: TELEMETRY.OPEN establishes a single-consumer session and returns the ring descriptor
On successful `TELEMETRY.OPEN(level="flow")`, the daemon MUST create a new telemetry session and return:
- `actualLevel`
- `sessionId`
- `abiVersion`
- `slotBytes`
- `slotCount`
- `ringDataBytes`
- `maxPayloadBytes`
- `writeTicketSnapshot`

The daemon MUST also transfer the shared-memory fd to the client using Unix domain socket ancillary data.

The consumer MUST start reading at `writeTicketSnapshot`; records produced before the successful OPEN are not part of the new session contract.

#### Scenario: OPEN flow returns session metadata and fd
- **WHEN** client sends `{"id":3,"cmd":"TELEMETRY.OPEN","args":{"level":"flow"}}` over the vNext Unix domain socket
- **THEN** daemon SHALL respond `ok=true`
- **AND** `result.actualLevel` SHALL be `"flow"`
- **AND** `result.sessionId`, `result.abiVersion`, `result.slotBytes`, `result.slotCount`, `result.ringDataBytes`, `result.maxPayloadBytes`, and `result.writeTicketSnapshot` SHALL be present
- **AND** daemon SHALL transfer one readable shared-memory fd with the response

### Requirement: TELEMETRY.OPEN requires Unix domain fd passing
`TELEMETRY.OPEN(level="flow")` MUST be supported only on vNext Unix domain socket sessions that can receive file descriptors.

If the connection cannot receive fd passing (for example TCP 60607), the daemon MUST reject `TELEMETRY.OPEN(level="flow")` with `INVALID_ARGUMENT` and a hint that telemetry OPEN requires the Unix domain socket.

#### Scenario: TCP OPEN is rejected
- **WHEN** client sends `{"id":4,"cmd":"TELEMETRY.OPEN","args":{"level":"flow"}}` over a TCP vNext connection
- **THEN** daemon SHALL respond `ok=false` with `error.code="INVALID_ARGUMENT"`
- **AND** `error.hint` SHALL mention the Unix domain socket requirement

### Requirement: TELEMETRY.OPEN has single-consumer ownership and later OPEN wins
The daemon MUST allow at most one telemetry consumer session to be active at a time.

When a second `TELEMETRY.OPEN(level="flow")` succeeds, it MUST become the only valid consumer session. The old session, old fd, old ring, and any old mmap view MUST become logically invalid.

#### Scenario: Second OPEN preempts first session
- **GIVEN** connection A has successfully opened telemetry session `s1`
- **WHEN** connection B successfully sends `TELEMETRY.OPEN(level="flow")`
- **THEN** connection B SHALL receive a new `sessionId`
- **AND** session `s1` SHALL no longer have valid telemetry data semantics

### Requirement: TELEMETRY.CLOSE disables the current consumer session idempotently
`TELEMETRY.CLOSE` MUST be idempotent.

If the caller owns the current session, the daemon MUST close that telemetry session and return `ok=true`. If no current session exists, or if the caller's session has already been preempted, the daemon MUST still return `ok=true` without affecting the newer session.

#### Scenario: CLOSE without active session succeeds
- **WHEN** client sends `{"id":5,"cmd":"TELEMETRY.CLOSE","args":{}}` before any successful OPEN
- **THEN** daemon SHALL respond `ok=true`

### Requirement: RESETALL rebuilds telemetry session state
`RESETALL` MUST invalidate the active telemetry session and ring.

After `RESETALL`, producers MUST treat telemetry as having no consumer until a new `TELEMETRY.OPEN` succeeds. The daemon MUST NOT attempt to send `FLOW END` records for every active flow as part of RESETALL.

The frontend/consumer contract is: stop ingest, clear local persisted records and active assembly state before RESETALL, then reopen after RESETALL ACK.

#### Scenario: RESETALL invalidates old ring
- **GIVEN** a telemetry session is active
- **WHEN** client sends `RESETALL` and receives `ok=true`
- **THEN** the old telemetry session SHALL be invalid
- **AND** a later `TELEMETRY.OPEN(level="flow")` SHALL create a new session with a new valid ring
