# flow-telemetry-export-channel Specification

## Purpose
Defines the bounded shared-memory export channel used by Flow Telemetry records.

## Requirements

### Requirement: Export channel uses a fixed-slot overwrite shared-memory ring
The telemetry export channel MUST use one global fixed-size slot shared-memory ring per active telemetry session.

The default ring configuration MUST be:
- `slotBytes = 1024`
- `ringDataBytes = 16 MiB`
- `slotCount = 16384`
- `maxPayloadBytes = slotBytes - slotHeaderBytes`

The ring MUST have a single consumer and MAY have multiple producers.

#### Scenario: OPEN returns default ring sizing
- **WHEN** client sends `TELEMETRY.OPEN(level="flow")` without config overrides
- **THEN** daemon SHALL return `slotBytes=1024`
- **AND** `ringDataBytes=16777216`
- **AND** `slotCount=16384`

### Requirement: Producers reserve slots using a global write ticket
Each producer write attempt MUST reserve a ticket using a global monotonic `writeTicket`.

The slot index MUST be computed as `ticket % slotCount`.

The daemon MAY overwrite an old `COMMITTED` slot. The daemon MUST NOT overwrite a slot currently marked `WRITING`; if the target slot is `WRITING`, the producer MUST drop the record without waiting or spinning.

#### Scenario: Producer drops when target slot is writing
- **GIVEN** producer A has reserved a slot and marked it `WRITING`
- **WHEN** producer B reserves a ticket whose slot index maps to the same slot before A commits
- **THEN** producer B SHALL drop its record
- **AND** verdict processing SHALL continue without blocking

### Requirement: Records cannot span slots
A telemetry record MUST fit within one slot payload.

If encoded payload size is greater than `maxPayloadBytes`, the daemon MUST drop that record and increment telemetry drop state with reason `recordTooLarge`.

#### Scenario: Oversized record is dropped
- **WHEN** daemon attempts to export a record with payload size greater than `maxPayloadBytes`
- **THEN** daemon SHALL NOT write a partial record
- **AND** telemetry drop reason SHALL record `recordTooLarge`

### Requirement: Consumer detects transport-level gaps using tickets
Each committed slot MUST expose its transport ticket.

The consumer MUST be able to detect slow-reader/ring-overwrite gaps by comparing expected ticket with the ticket in the slot it reads.

#### Scenario: Consumer observes ticket gap
- **GIVEN** consumer expects ticket `n`
- **WHEN** the slot contains committed ticket `m` where `m > n`
- **THEN** consumer can determine that at least one transport record was missed

### Requirement: ABI is explicit and independent of C++ struct padding
The shared-memory ABI MUST be defined as little-endian binary data with explicit field widths and explicit offsets.

The implementation MUST NOT require C++ `sizeof(struct)` or compiler padding to match the wire layout. Producers MUST serialize fields explicitly.

Payload evolution MUST use `payloadVersion` plus append-only fields, and consumers MUST be able to skip unknown appended fields using `payloadSize`.

#### Scenario: Consumer skips appended fields
- **GIVEN** a consumer understands `payloadVersion=1`
- **WHEN** it reads a record with a larger `payloadSize` that appends fields after all v1 fields
- **THEN** it SHALL be able to parse the known v1 prefix
- **AND** skip the unknown tail based on `payloadSize`

### Requirement: Consumer absent does not write the ring
When no telemetry consumer session is active, producers MUST NOT write records into any ring.

Instead, producers MUST drop/not-export records and increment telemetry state with reason `consumerAbsent` when counters are available.

#### Scenario: Producer sees no consumer
- **GIVEN** telemetry level is `flow` but no active consumer session exists
- **WHEN** dataplane reaches a point that would otherwise export a record
- **THEN** daemon SHALL not write any shared-memory slot
- **AND** verdict processing SHALL continue
