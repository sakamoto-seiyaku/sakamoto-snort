# nfqueue-topology-modes Specification

## Purpose
Define daemon NFQUEUE topology modes, startup queue planning, and per-packet direction derivation.

## Requirements
### Requirement: Daemon supports named NFQUEUE topology modes

The daemon MUST support two NFQUEUE topology modes named `split-in-out` and `shared-flow-pool`. The default topology MUST be `split-in-out`.

#### Scenario: Default topology is split-in-out
- **WHEN** the daemon starts without a persisted `nfqueue.topology` value
- **THEN** it SHALL use `split-in-out`

#### Scenario: Shared flow pool topology can be selected for startup
- **WHEN** the persisted `nfqueue.topology` value is `shared-flow-pool`
- **THEN** the daemon SHALL use `shared-flow-pool` when installing NFQUEUE rules for that startup

### Requirement: split-in-out uses separate INPUT and OUTPUT queue ranges

In `split-in-out`, each IP family MUST keep the current queue layout where INPUT rules and OUTPUT rules use disjoint queue ranges within that family's queue range.

#### Scenario: INPUT and OUTPUT are separated in split-in-out
- **WHEN** `split-in-out` is active for an IP family with an even queue count
- **THEN** INPUT rules SHALL target the first half of that family's queue range
- **AND** OUTPUT rules SHALL target the second half of that family's queue range

### Requirement: shared-flow-pool uses the same queue range for INPUT and OUTPUT

In `shared-flow-pool`, each IP family MUST install INPUT and OUTPUT NFQUEUE rules against the same queue range so the kernel can apply NFQUEUE connection stickiness across both directions.

#### Scenario: INPUT and OUTPUT share a queue range
- **WHEN** `shared-flow-pool` is active for an IP family
- **THEN** INPUT rules SHALL target the full queue range assigned to that IP family
- **AND** OUTPUT rules SHALL target the same full queue range assigned to that IP family

#### Scenario: Listener ownership remains queue based
- **WHEN** `shared-flow-pool` is active
- **THEN** the daemon SHALL continue to start one listener thread per queue in the IP-family queue range

### Requirement: Packet direction is derived from NFQUEUE hook

Packet direction used by datapath policy and observability MUST be derived per packet from the NFQUEUE packet header hook. `NF_INET_LOCAL_IN` SHALL map to input and `NF_INET_LOCAL_OUT` SHALL map to output.

#### Scenario: LOCAL_IN packet is treated as input
- **WHEN** an NFQUEUE packet has hook `NF_INET_LOCAL_IN`
- **THEN** datapath processing SHALL treat the packet direction as input

#### Scenario: LOCAL_OUT packet is treated as output
- **WHEN** an NFQUEUE packet has hook `NF_INET_LOCAL_OUT`
- **THEN** datapath processing SHALL treat the packet direction as output

#### Scenario: Unsupported hooks do not use topology-derived direction
- **WHEN** an NFQUEUE packet has a hook other than `NF_INET_LOCAL_IN` or `NF_INET_LOCAL_OUT`
- **THEN** the daemon SHALL NOT derive direction from listener thread partition for that packet

### Requirement: Topology mode does not change datapath semantics

For packets whose direction is derived successfully, `shared-flow-pool` MUST preserve the same datapath semantics as `split-in-out` for remote IP selection, IPRULES `dir` matching, traffic counters, Flow Telemetry direction fields, and Debug Stream packet direction.

#### Scenario: Direction-dependent behavior is equivalent
- **WHEN** the same INPUT or OUTPUT packet is processed under either topology mode
- **THEN** direction-dependent policy and observability fields SHALL use the same input or output value

### Requirement: Topology correctness does not depend on same-flow same-thread affinity

The daemon MUST NOT rely on `shared-flow-pool` placing both directions of a flow on one listener thread for conntrack, telemetry, or policy correctness.

#### Scenario: Same flow can still be processed concurrently
- **WHEN** opposite directions of one flow are processed by different listener threads
- **THEN** conntrack, telemetry, and policy behavior SHALL remain correct
