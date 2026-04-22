# control-vnext-stream-surface Specification

## Purpose
TBD - created by archiving change add-control-vnext-stream. Update Purpose after archive.

## Requirements

### Requirement: Daemon implements STREAM.START and STREAM.STOP for vNext streaming
The daemon MUST implement `STREAM.START` and `STREAM.STOP` as defined in:
- `docs/decisions/DOMAIN_IP_FUSION/CONTROL_COMMANDS_VNEXT.md`
- `docs/decisions/DOMAIN_IP_FUSION/CONTROL_PROTOCOL_VNEXT.md`
- `docs/decisions/DOMAIN_IP_FUSION/OBSERVABILITY_WORKING_DECISIONS.md`

The daemon MUST follow vNext strict reject rules for args validation.

#### Scenario: Unknown args key is rejected
- **WHEN** client sends `{"id":1,"cmd":"STREAM.START","args":{"type":"dns","x":1}}`
- **THEN** daemon SHALL respond `ok=false` with `error.code="SYNTAX_ERROR"`

### Requirement: STREAM.START enforces streamType rules and per-type arg shapes
`STREAM.START.args.type` MUST be a string and MUST be one of:
- `dns`
- `pkt`
- `activity`

Per-type args:
- For `type="dns"` and `type="pkt"`:
  - `horizonSec` and `minSize` MUST be integers (u32) if present, and default to `0` when omitted.
- For `type="activity"`:
  - `horizonSec` and `minSize` MUST NOT be present.

#### Scenario: Unknown stream type is rejected
- **WHEN** client sends `{"id":2,"cmd":"STREAM.START","args":{"type":"nope"}}`
- **THEN** daemon SHALL respond `ok=false` with `error.code="INVALID_ARGUMENT"`

#### Scenario: activity start rejects replay args
- **WHEN** client sends `{"id":3,"cmd":"STREAM.START","args":{"type":"activity","horizonSec":1}}`
- **THEN** daemon SHALL respond `ok=false` with `error.code="SYNTAX_ERROR"`

### Requirement: Stream subscriptions are single-connection per streamType and single-type per connection
The daemon MUST enforce:
- Per streamType single subscriber: at most one connection MAY be subscribed to a given `type`
  at a time; a second `STREAM.START` for the same `type` MUST return `STATE_CONFLICT`.
- Per connection single active type: once a connection enters stream mode via a successful
  `STREAM.START(type=...)`, the same connection MUST NOT start another type until after
  `STREAM.STOP`; attempts MUST return `STATE_CONFLICT`.

#### Scenario: Second subscriber for same type is rejected
- **WHEN** connection A has successfully started `STREAM.START(type="dns")`
- **AND** connection B sends `{"id":4,"cmd":"STREAM.START","args":{"type":"dns"}}`
- **THEN** connection B SHALL receive `ok=false` with `error.code="STATE_CONFLICT"`

### Requirement: Stream mode forbids non-stream commands on the same connection
After a successful `STREAM.START`, the connection is in stream mode.
While in stream mode, any non-stream command (any `cmd` other than `STREAM.START`/`STREAM.STOP`)
MUST be rejected with `STATE_CONFLICT`.

#### Scenario: METRICS.GET is rejected in stream mode
- **WHEN** a client successfully starts `STREAM.START(type="dns")` on a connection
- **AND** the same connection sends `{"id":5,"cmd":"METRICS.GET","args":{"name":"traffic"}}`
- **THEN** daemon SHALL respond `ok=false` with `error.code="STATE_CONFLICT"`

### Requirement: STREAM.START ordering and started notice
On successful `STREAM.START`, the daemon MUST:
1) send the `STREAM.START` response frame (`{"id":...,"ok":true}`)
2) then send a first event frame `type="notice", notice="started"` for that stream
3) then (for `dns`/`pkt`) send replay events (if any) followed by realtime events

The started notice MUST NOT include `id/ok`.

#### Scenario: started notice is first event after START response
- **WHEN** client sends `{"id":6,"cmd":"STREAM.START","args":{"type":"dns","horizonSec":0,"minSize":0}}`
- **THEN** daemon SHALL first send a response frame with `{"id":6,"ok":true}`
- **AND** the next frame sent by the daemon SHALL be an event with `type="notice"` and `notice="started"`

### Requirement: STREAM.STOP is idempotent and its response is an ack barrier
`STREAM.STOP` MUST be idempotent: if no stream is active on the connection, the daemon SHALL still
respond `ok=true`.

STOP ack barrier:
- The daemon MUST first disable the subscription for that connection and clear its pending queue
  (dropping unsent tail is allowed).
- The daemon MUST then send the STOP response frame (`{"id":...,"ok":true}`).
- After the STOP response frame, the daemon MUST NOT send any event/notice frames on that
  connection until the next successful `STREAM.START` (or connection close).

For `type="dns"` and `type="pkt"`, STOP MUST clear the ring buffer used for replay.

#### Scenario: STOP response is the last frame
- **WHEN** a client has started a stream
- **AND** the client sends `{"id":7,"cmd":"STREAM.STOP","args":{}}`
- **THEN** the daemon SHALL send exactly one response frame with `{"id":7,"ok":true}`
- **AND** the daemon SHALL NOT send any additional event/notice frames until the next START

### Requirement: Stream events use strict JSON objects with a top-level type discriminator
All stream events (including notices) MUST be:
- netstring-framed (same framing as vNext responses)
- strict JSON objects (UTF-8)
- MUST include a top-level string field `type`
- MUST NOT include `id` or `ok`

#### Scenario: Events reject response envelope fields
- **WHEN** the daemon sends a stream event
- **THEN** that JSON object SHALL NOT contain keys `id` or `ok`
