## ADDED Requirements

### Requirement: DNS and packet stream events include debug explanations
For tracked apps, vNext `STREAM.START(type="dns")` and `STREAM.START(type="pkt")` events MUST include a top-level `explain` object.

The `explain` object MUST be a strict JSON object and MUST include:
- `version` (integer)
- `kind` (string)
- `inputs` (object)
- `final` (object)
- `stages` (array)

Existing stream event envelope rules remain unchanged: events MUST be netstring-framed strict JSON objects, MUST include top-level `type`, and MUST NOT include `id` or `ok`.

The `explain` object MUST be the authoritative debug evidence. Existing top-level event fields SHALL be treated as compatibility summaries and MUST NOT be expanded into a replacement for Flow Telemetry records, history, timeline, Top-K, or Metrics output.

#### Scenario: DNS event contains explain object
- **WHEN** a tracked DNS decision emits a `type="dns"` stream event
- **THEN** the event SHALL include `explain.version=1`
- **AND** `explain.kind` SHALL equal `"dns-policy"`
- **AND** the event SHALL NOT include `id` or `ok`

#### Scenario: Packet event contains explain object
- **WHEN** a tracked packet verdict emits a `type="pkt"` stream event
- **THEN** the event SHALL include `explain.version=1`
- **AND** `explain.kind` SHALL equal `"packet-verdict"`
- **AND** the event SHALL NOT include `id` or `ok`

### Requirement: Stream command compatibility is preserved with debug-only semantics
The daemon MUST keep the existing `STREAM.START` command type set:
- `dns`
- `pkt`
- `activity`

The daemon MUST NOT require a new `explain` argument to emit debug explanations for tracked `dns` or `pkt` events.

`activity` stream events MUST remain command-compatible and MUST remain outside Debug Stream explainability. They SHALL NOT gain `explain` objects or new telemetry/history responsibilities in this change.

Existing start ordering, single-subscriber, stream-mode conflict, STOP ack barrier, and `RESETALL` mechanics MUST remain command-compatible.

For `dns` and `pkt`, replay parameters MUST be documented and implemented only as bounded in-process debug prebuffer controls, not as a history or timeline API. Suppressed and dropped notices MUST remain stream delivery/debug diagnostics, not Metrics replacements.

#### Scenario: activity stream is not changed
- **WHEN** a client starts `STREAM.START(type="activity")`
- **THEN** emitted `activity` events SHALL preserve the existing activity event shape
- **AND** activity events SHALL NOT include `explain`

#### Scenario: no explain argument is required
- **WHEN** a client starts `STREAM.START(type="pkt")` without an `explain` argument
- **AND** a tracked packet event is emitted
- **THEN** that packet event SHALL include a debug `explain` object

#### Scenario: dns and pkt replay are not history queries
- **WHEN** a client starts `STREAM.START(type="pkt")` with replay parameters
- **THEN** any replayed events SHALL come from the bounded stream prebuffer
- **AND** the daemon SHALL NOT query Flow Telemetry, Metrics, or persistent state to backfill historical packet records
