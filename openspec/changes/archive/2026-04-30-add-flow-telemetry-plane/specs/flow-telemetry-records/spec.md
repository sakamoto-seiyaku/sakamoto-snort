## ADDED Requirements

### Requirement: Telemetry records contain only business facts
The telemetry records database MUST contain only business fact records.

The MVP top-level `recordType` set MUST be:
- `FLOW`
- `DNS_DECISION`

The daemon MUST NOT emit `TelemetryHealthRecord` or `TelemetryStatsRecord`; channel health MUST be exposed through telemetry state/metrics.

#### Scenario: Health is not emitted as a record
- **WHEN** telemetry drop counters change
- **THEN** daemon SHALL expose that state through telemetry state/metrics
- **AND** daemon SHALL NOT emit a health/stats record into the telemetry ring

### Requirement: FLOW records use flowInstanceId identity and BEGIN UPDATE END kinds
Every `FLOW` payload MUST carry `flowInstanceId`.

The 5-tuple/family/uid fields are a key used for lookup and display, but they MUST NOT be treated as the stable identity of a flow instance.

`FLOW` payload MUST include an internal kind with values:
- `BEGIN`
- `UPDATE`
- `END`

#### Scenario: Same tuple can produce different flow instances
- **GIVEN** a TCP connection using a 5-tuple has ended
- **WHEN** a later connection reuses the same 5-tuple
- **THEN** daemon SHALL assign a distinct `flowInstanceId`

### Requirement: FLOW records carry cumulative counters and per-flow recordSeq
`FLOW` records MUST carry cumulative `totalPackets` and `totalBytes`.

`FLOW` records MUST NOT carry since-last-export delta counters.

Each flow instance MUST maintain a `recordSeq` that increments only after a record for that `flowInstanceId` has successfully entered the shared-memory ring.

#### Scenario: Failed write does not advance recordSeq
- **GIVEN** a flow has last successful `recordSeq = 3`
- **WHEN** daemon attempts to export an UPDATE but the ring write fails
- **THEN** the next successfully exported record for that flow SHALL use `recordSeq = 4`

### Requirement: FLOW UPDATE is emitted on state or threshold changes
The daemon MUST emit `FLOW` records using packet-driven triggers.

The daemon MUST emit `BEGIN` when a telemetry flow entry is created.

The daemon MUST emit `UPDATE` when any of the following happens for an existing flow:
- conntrack state or direction changes
- final decision key changes
- `packetsSinceLastExport >= packetsThreshold`
- `bytesSinceLastExport >= bytesThreshold`
- a packet arrives after `maxExportIntervalMs` since last successful export

The daemon MUST emit `END` for idle timeout, TCP end detected, resource eviction, or telemetry disabled cleanup.

#### Scenario: Counter threshold emits UPDATE
- **GIVEN** a flow has already emitted `BEGIN`
- **AND** `packetsSinceLastExport` reaches `packetsThreshold`
- **WHEN** another packet for that flow is processed
- **THEN** daemon SHALL attempt to export a `FLOW` record with kind `UPDATE`

### Requirement: FLOW decision fields describe final execution result only
`FLOW` records MUST describe the final packet verdict segment and MUST NOT duplicate Debug Stream explainability fields.

The `decisionKey` for segment changes MUST be:
- `ctState`
- `ctDir`
- `reasonId`
- optional `ruleId`

`FLOW` records MUST NOT include `wouldRuleId`, `wouldDrop`, candidate rules, shadow/why-not fields, `domainHint`, domain name, `domainRuleId`, or DNS→IP mapping details.

#### Scenario: Would-match is not exported in FLOW
- **GIVEN** a packet would match a blocking rule but final verdict is allow
- **WHEN** daemon exports a `FLOW` record
- **THEN** the record SHALL describe the final allow result
- **AND** the record SHALL NOT contain `wouldRuleId` or would-block fields

### Requirement: IFACE_BLOCK and BLOCK use the unified flow table
`IFACE_BLOCK` and IP rule `BLOCK` attempts MUST use the same telemetry flow/conntrack observation table as allow/default-allow flows.

`IFACE_BLOCK` MUST be represented as final decision `reasonId=IFACE_BLOCK` with no `ruleId`.

BLOCK/IFACE_BLOCK entries MUST use `blockTtlMs`; if a later packet for the same flow becomes ALLOW or DEFAULT_ALLOW, the entry MUST switch to normal flow/conntrack timeout semantics.

#### Scenario: IFACE_BLOCK exports as flow attempt
- **WHEN** a packet is dropped by interface policy
- **THEN** daemon SHALL be able to export a `FLOW` record for the observed attempt
- **AND** that record SHALL use `reasonId=IFACE_BLOCK`

### Requirement: DNS_DECISION records are blocked-only DNS timeline facts
`DNS_DECISION` records MUST be emitted only for blocked DNS decisions.

`DNS_DECISION` MAY carry a bounded inline `queryName`, with maximum encoded query name length of 255 bytes. It MUST NOT carry parsed response IP addresses or IP count.

`domainRuleId` belongs only to DNS records and MUST NOT be copied into packet/CT `FLOW` records.

#### Scenario: Allowed DNS decision does not emit DNS_DECISION
- **WHEN** daemon allows a DNS decision
- **THEN** daemon SHALL NOT emit a `DNS_DECISION` record for that decision

#### Scenario: Blocked DNS decision emits DNS_DECISION
- **WHEN** daemon blocks a DNS decision and a telemetry consumer is active
- **THEN** daemon SHALL attempt to emit a `DNS_DECISION` record
- **AND** the record SHALL NOT include response IP details

### Requirement: Flow Telemetry resource pressure never changes verdict
Failure to create a telemetry flow entry, failure to write a record, ring pressure, or consumer absence MUST NOT change packet or DNS verdict.

When a telemetry/flow table is full, the daemon MUST first do bounded sweep of expired entries. If the table is still full, it MUST refuse the new telemetry entry and increment resource pressure state; existing entries MAY continue updating.

#### Scenario: Telemetry table full does not drop packet
- **GIVEN** telemetry flow table is full
- **WHEN** a packet would otherwise be accepted by policy
- **THEN** daemon SHALL preserve the accept verdict
- **AND** telemetry MAY drop/refuse the corresponding record or flow entry
