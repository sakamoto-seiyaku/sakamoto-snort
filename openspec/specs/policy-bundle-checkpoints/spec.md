# policy-bundle-checkpoints Specification

## Purpose
Defines backend policy checkpoint storage, bundle contents, restore atomicity, and runtime cleanup behavior.

## Requirements
### Requirement: Policy checkpoints use fixed bounded slots
The daemon MUST provide exactly three policy checkpoint slots identified by numeric slot IDs `0`, `1`, and `2`.

Each slot MUST store at most one policy bundle. Each bundle MUST be capped at 64 MiB. The daemon MUST reject any save that would exceed the per-slot cap and MUST leave the previous slot contents unchanged.

The daemon MUST NOT store frontend checkpoint names, notes, colors, labels, history timelines, or product workflow roles in the backend slot.

#### Scenario: Slot IDs are fixed
- **WHEN** a client lists or addresses policy checkpoints
- **THEN** the daemon SHALL expose only slot IDs `0`, `1`, and `2`
- **AND** any other slot ID SHALL be rejected

#### Scenario: Oversized bundle does not replace slot
- **GIVEN** checkpoint slot `1` already contains a valid bundle
- **WHEN** the client saves a policy bundle larger than 64 MiB into slot `1`
- **THEN** the daemon SHALL reject the save with a capacity error
- **AND** the previous slot `1` bundle SHALL remain restorable

### Requirement: Policy bundle covers verdict-affecting policy state only
A policy bundle MUST include the verdict-affecting state needed to restore policy behavior:
- device verdict config
- app verdict config for known apps
- DomainRules baseline
- DomainPolicy for device and app scopes
- DomainLists metadata and list contents
- IPRULES rule definitions and rule identity allocation state

A policy bundle MUST NOT include frontend metadata, product checkpoint history, Flow Telemetry records, stream replay buffers, metrics counters, perf samples, Geo/ASN annotations, Billing state, domain/IP hit stats, IPRULES hit stats, or diagnostic export data.

#### Scenario: Bundle includes domain list contents
- **GIVEN** a DomainList contains imported domains
- **WHEN** the daemon saves a policy checkpoint
- **THEN** the bundle SHALL include the list metadata and the concrete imported domain contents
- **AND** restore SHALL NOT depend on refetching the list from its URL or etag

#### Scenario: Runtime counters are not checkpoint state
- **WHEN** the daemon saves a policy checkpoint
- **THEN** the bundle SHALL NOT include traffic counters, reason counters, domain rule hit counters, or IPRULES rule hit counters

### Requirement: Checkpoint restore is atomic-or-no-op
The daemon MUST implement policy checkpoint restore as an atomic-or-no-op operation.

Before changing live policy state, the daemon MUST fully parse and validate the selected bundle into staging state. Validation MUST include bundle version support, payload limits, cross-module references, DomainPolicy rule references, DomainLists consistency, and IPRULES preflight/canonicalization.

If parsing or validation fails, the daemon MUST leave all live policy state unchanged.

#### Scenario: Invalid bundle does not partially restore
- **GIVEN** the daemon has live policy state `A`
- **AND** checkpoint slot `0` contains an invalid or unsupported bundle
- **WHEN** a client runs `CHECKPOINT.RESTORE` for slot `0`
- **THEN** the daemon SHALL return an error
- **AND** live policy state SHALL remain `A`

#### Scenario: Cross-reference validation prevents partial commit
- **GIVEN** a checkpoint bundle contains a DomainPolicy reference to a missing DomainRules `ruleId`
- **WHEN** a client restores that checkpoint
- **THEN** the daemon SHALL reject the restore before committing any live state

### Requirement: Successful restore starts a new policy runtime epoch
After a successful checkpoint restore, the daemon MUST clear verdict-affecting transient runtime state that may reflect the previous policy epoch.

The cleanup MUST include conntrack state, learned domain/IP/host associations used by verdicts, and IPRULES decision caches. Runtime observability surfaces that cannot remain coherent across restore MUST be cleared or invalidated, including active stream state, telemetry session state, and metrics that describe the previous policy epoch.

#### Scenario: Transient verdict state is cleared after restore
- **WHEN** `CHECKPOINT.RESTORE` succeeds
- **THEN** conntrack state and learned domain/IP/host associations from before restore SHALL NOT affect later packet or DNS verdicts

#### Scenario: Stream and telemetry consumers must reopen
- **WHEN** `CHECKPOINT.RESTORE` succeeds while a stream or telemetry session is active
- **THEN** the daemon SHALL invalidate or close that runtime observability state
- **AND** clients SHALL need to reopen stream or telemetry consumers for the restored policy epoch
