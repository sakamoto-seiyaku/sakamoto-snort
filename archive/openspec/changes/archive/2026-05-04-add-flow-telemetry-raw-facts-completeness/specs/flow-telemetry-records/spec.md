## MODIFIED Requirements

### Requirement: FLOW records carry cumulative counters and per-flow recordSeq
`FLOW` records MUST carry cumulative `totalPackets` and `totalBytes`.

`FLOW` records MUST also carry cumulative per-direction counters:
- `inPackets`
- `inBytes`
- `outPackets`
- `outBytes`

The daemon MUST count packets with packet direction `in` into the `in*` counters and packets with packet direction `out` into the `out*` counters.

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

### Requirement: FLOW UPDATE is emitted on state or threshold changes
The daemon MUST emit `FLOW` records using packet-driven triggers.

The daemon MUST emit `BEGIN` when a telemetry flow entry is created.

The daemon MUST emit `UPDATE` when any of the following happens for an existing flow:
- conntrack state or direction changes
- final decision key changes
- `packetsSinceLastExport >= packetsThreshold`
- `bytesSinceLastExport >= bytesThreshold`
- a packet arrives after `maxExportIntervalMs` since last successful export

The daemon MUST emit `END` for idle timeout, TCP end detected, resource eviction, or telemetry disabled cleanup when the flow is retired and the session remains able to export the record.

`END` records MUST carry `endReason` with at least:
- `IDLE_TIMEOUT`
- `TCP_END_DETECTED`
- `RESOURCE_EVICTED`
- `TELEMETRY_DISABLED`

RESETALL, `TELEMETRY.CLOSE`, and telemetry session rebuild MUST be treated as session boundaries and MUST NOT require the daemon to emit `END` for every active flow.

Telemetry-disabled cleanup MUST be bounded by scanned buckets and scanned entries, not by the number of successfully emitted END records. Ring write failures during cleanup MUST NOT allow a cleanup pass to continue scanning beyond its configured scan budget.

#### Scenario: Counter threshold emits UPDATE
- **GIVEN** a flow has already emitted `BEGIN`
- **AND** `packetsSinceLastExport` reaches `packetsThreshold`
- **WHEN** another packet for that flow is processed
- **THEN** daemon SHALL attempt to export a `FLOW` record with kind `UPDATE`

#### Scenario: Retired flow carries END reason
- **GIVEN** a flow has emitted at least one successful `FLOW` record
- **WHEN** the flow is retired because its idle timeout expires
- **THEN** daemon SHALL attempt to export a `FLOW` record with kind `END`
- **AND** the record SHALL carry `endReason=IDLE_TIMEOUT`

#### Scenario: Resource eviction carries END reason
- **GIVEN** a flow has emitted at least one successful `FLOW` record
- **WHEN** bounded resource-pressure reclaim evicts that telemetry flow entry
- **THEN** daemon SHALL attempt to export a `FLOW` record with kind `END`
- **AND** the record SHALL carry `endReason=RESOURCE_EVICTED`

#### Scenario: Telemetry-disabled cleanup carries END reason
- **GIVEN** a flow has emitted at least one successful `FLOW` record
- **WHEN** daemon performs bounded telemetry session cleanup before invalidating the session
- **THEN** daemon SHALL attempt to export a `FLOW` record with kind `END`
- **AND** the record SHALL carry `endReason=TELEMETRY_DISABLED`

#### Scenario: RESETALL does not flood END records
- **GIVEN** Flow Telemetry has active flow entries
- **WHEN** RESETALL rebuilds the telemetry session
- **THEN** daemon SHALL invalidate the old telemetry session
- **AND** daemon SHALL NOT be required to emit one `TELEMETRY_DISABLED` END record for each active flow

#### Scenario: Cleanup write failure does not unbound scanning
- **GIVEN** telemetry-disabled cleanup has a finite scan budget
- **AND** an attempted `TELEMETRY_DISABLED` END write fails because the ring slot is busy
- **WHEN** daemon continues that cleanup pass
- **THEN** the failed write SHALL still count against the scanned entry budget
- **AND** daemon SHALL NOT scan unbounded additional flow entries looking for a successful END write

### Requirement: FLOW decision fields describe final execution result only
`FLOW` records MUST describe the final packet verdict segment and MUST NOT duplicate Debug Stream explainability fields.

The `decisionKey` for segment changes MUST include:
- `ctState`
- `ctDir`
- explicit `verdict` / action
- `reasonId`
- optional `ruleId`

`reasonId` MUST explain the final verdict cause and MUST NOT be the only field consumers need to determine allow/block action.

`FLOW` records MUST NOT include `wouldRuleId`, `wouldDrop`, candidate rules, shadow/why-not fields, `domainHint`, domain name, `domainRuleId`, or DNS->IP mapping details.

#### Scenario: Would-match is not exported in FLOW
- **GIVEN** a packet would match a blocking rule but final verdict is allow
- **WHEN** daemon exports a `FLOW` record
- **THEN** the record SHALL describe the final allow result
- **AND** the record SHALL NOT contain `wouldRuleId` or would-block fields

#### Scenario: Verdict is explicit
- **GIVEN** daemon exports a `FLOW` record for a packet accepted by policy
- **THEN** the record SHALL carry an explicit allow verdict/action
- **AND** clients SHALL NOT need to infer allow/block solely from `reasonId`

## ADDED Requirements

### Requirement: FLOW payload v1 is replaced as a breaking ABI update
The daemon MUST replace the existing 102-byte `FLOW` payload v1 layout in place.

The daemon MUST NOT dual-write old and new `FLOW` layouts.

The daemon MUST NOT provide a compatibility window for consumers that only understand the old 102-byte `FLOW` payload.

The shared-memory slot header, `recordType=FLOW`, `payloadSize`, transport ticket, and per-flow `recordSeq` semantics MUST remain unchanged.

#### Scenario: Old layout is not accepted as compatibility contract
- **WHEN** a consumer reads a `FLOW` record after this change
- **THEN** it MUST decode the replacement `FLOW` payload layout documented for this change
- **AND** it MUST NOT assume the old fixed 102-byte field offsets remain valid

### Requirement: FLOW records carry raw L4, direction, time, attribution, and lifecycle facts
Each replacement `FLOW` payload MUST carry enough raw facts for normal Activity display without requiring Debug Stream lookup:
- IP family and tuple address fields
- `proto`
- `l4Status`
- `portsAvailable`
- `srcPort` and `dstPort`, set to 0 when ports are unavailable
- `packetDir`
- `flowOriginDir`
- `firstSeenNs`
- `lastSeenNs`
- `timestampNs`
- `uid`
- `userId`
- `uidKnown`
- `ifindex`
- `ifaceKindBit`
- `ifindexKnown`
- `pickedUpMidStream`

For ICMP and ICMPv6 traffic, `FLOW` records MUST carry:
- `icmpType`
- `icmpCode`
- `icmpId`

`timestampNs` MUST describe the record event/export time. `firstSeenNs` and `lastSeenNs` MUST describe the observed packet lifetime of the flow or observation.

#### Scenario: ICMP facts are exported
- **GIVEN** daemon observes an ICMP echo flow with type, code, and id
- **WHEN** daemon exports a `FLOW` record for that flow
- **THEN** the record SHALL include `icmpType`
- **AND** the record SHALL include `icmpCode`
- **AND** the record SHALL include `icmpId`
- **AND** `srcPort` and `dstPort` SHALL be 0 unless TCP/UDP ports were safely parsed

#### Scenario: Unknown UID is distinguishable from root UID
- **GIVEN** netfilter does not provide a UID attribute for a packet
- **WHEN** daemon exports a `FLOW` record for that packet
- **THEN** the record SHALL carry `uidKnown=0`
- **AND** clients SHALL NOT need to interpret `uid=0` as root unless `uidKnown=1`

#### Scenario: END timestamp is not last packet time
- **GIVEN** a flow's last packet was observed at time `T1`
- **AND** daemon later retires the flow at time `T2`
- **WHEN** daemon exports the `FLOW` END record
- **THEN** `lastSeenNs` SHALL equal `T1`
- **AND** `timestampNs` MAY equal the later retire/export time `T2`

### Requirement: FLOW records represent L3 observations for unavailable L4
The daemon MUST be able to export `FLOW` records for packets whose L4 information is unavailable or invalid, including fragments and invalid/unavailable L4 parse results.

Such records MUST be marked with an observation kind equivalent to `L3_OBSERVATION` and MUST NOT be represented as normal L4 flow lifecycle records.

For L3 observations:
- `l4Status` MUST identify the parse status
- `portsAvailable` MUST be 0
- `srcPort` and `dstPort` MUST be 0
- records MUST still carry available L3 addresses, IP family, proto, packet direction, verdict/action, reasonId, and cumulative counters
- telemetry failure MUST NOT change packet verdict

#### Scenario: Fragment exports L3 observation
- **GIVEN** daemon observes an IPv4 or IPv6 fragment whose L4 ports are unavailable
- **WHEN** Flow Telemetry is active
- **THEN** daemon SHALL be able to export a `FLOW` record marked as `L3_OBSERVATION`
- **AND** the record SHALL carry `l4Status=fragment`
- **AND** the record SHALL carry `portsAvailable=0`
- **AND** the record SHALL NOT pretend to be a normal TCP/UDP/ICMP flow with valid ports

#### Scenario: Invalid L4 exports observation without affecting verdict
- **GIVEN** daemon observes a packet with invalid or unavailable L4 parse status
- **WHEN** telemetry fails to create or write the corresponding L3 observation record
- **THEN** daemon SHALL preserve the packet verdict that policy would otherwise produce

### Requirement: FLOW producer is independent of IPRULES enablement
When Flow Telemetry is active, the daemon MUST collect conntrack observation facts for eligible L4 packets independently of whether IP rules policy evaluation is enabled.

Disabling `iprules.enabled` MUST NOT force otherwise trackable TCP/UDP/ICMP `FLOW` records to report `ctState=INVALID` and `ctDir=ANY`.

Telemetry-only conntrack observation MUST NOT change the packet verdict.

#### Scenario: Telemetry records conntrack facts when IPRULES is disabled
- **GIVEN** `iprules.enabled=0`
- **AND** Flow Telemetry is active
- **WHEN** daemon observes an otherwise trackable TCP packet
- **THEN** the exported `FLOW` record SHALL carry the conntrack state and direction observed for that packet
- **AND** the final packet verdict SHALL remain the verdict that non-IPRULES policy would otherwise produce
