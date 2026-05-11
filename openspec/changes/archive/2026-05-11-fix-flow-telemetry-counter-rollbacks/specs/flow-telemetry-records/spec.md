## MODIFIED Requirements

### Requirement: FLOW records carry cumulative counters and per-flow recordSeq
`FLOW` records MUST carry cumulative `totalPackets` and `totalBytes`.

`FLOW` records MUST also carry cumulative per-direction counters:
- `inPackets`
- `inBytes`
- `outPackets`
- `outBytes`

The daemon MUST count packets with packet direction `in` into the `in*` counters and packets with packet direction `out` into the `out*` counters.

The daemon MUST ignore Flow Telemetry packet observations whose packet direction is `unknown`.

For each exported `FLOW` record whose packet direction is known, `totalPackets` MUST equal `inPackets + outPackets`, and `totalBytes` MUST equal `inBytes + outBytes`.

For the same `flowInstanceId`, records observed in increasing `recordSeq` order MUST NOT decrease `totalPackets`, `totalBytes`, `inPackets`, `inBytes`, `outPackets`, or `outBytes`.

For the same `flowInstanceId`, records observed in increasing `recordSeq` order MUST NOT decrease `lastSeenNs`.

`FLOW` records MUST NOT carry since-last-export delta counters.

Each flow instance MUST maintain a `recordSeq` that increments only after a record for that `flowInstanceId` has successfully entered the shared-memory ring.

#### Scenario: Failed write does not advance recordSeq
- **GIVEN** a flow has last successful `recordSeq = 3`
- **WHEN** daemon attempts to export an UPDATE but the ring write fails
- **THEN** the next successfully exported record for that flow SHALL use `recordSeq = 4`

#### Scenario: Direction counters are cumulative
- **GIVEN** a flow has observed two outbound packets and one inbound packet
- **WHEN** daemon exports a `FLOW` record for that flow
- **THEN** the record SHALL include cumulative `outPackets=2`
- **AND** the record SHALL include cumulative `inPackets=1`
- **AND** `totalPackets` SHALL equal the sum of inbound and outbound packets for that flow instance

#### Scenario: Unknown packet direction observations are ignored
- **GIVEN** Flow Telemetry is active
- **WHEN** daemon observes a packet telemetry event with packet direction `unknown`
- **THEN** daemon SHALL NOT create a conntrack telemetry entry for that observation
- **AND** daemon SHALL NOT export a `FLOW` record for that observation

#### Scenario: Concurrent direction exports do not roll back counters
- **GIVEN** INPUT and OUTPUT workers concurrently process packets for the same `flowInstanceId`
- **WHEN** both workers attempt to export `FLOW` records for that flow
- **THEN** records observed by increasing `recordSeq` SHALL have nondecreasing cumulative packet and byte counters
- **AND** each record with known packet direction SHALL have `totalPackets = inPackets + outPackets`
- **AND** each record with known packet direction SHALL have `totalBytes = inBytes + outBytes`

#### Scenario: Concurrent packet contexts do not roll back lastSeenNs
- **GIVEN** two workers process packets for the same `flowInstanceId` with different packet timestamps
- **WHEN** those workers export `FLOW` records in either execution order
- **THEN** records observed by increasing `recordSeq` SHALL have nondecreasing `lastSeenNs`
