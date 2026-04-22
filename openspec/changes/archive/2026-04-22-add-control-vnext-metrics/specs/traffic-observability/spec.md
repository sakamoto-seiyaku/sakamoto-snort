## ADDED Requirements

### Requirement: Traffic metrics are exposed via METRICS.GET(name=traffic)
The daemon MUST expose traffic counters via:
- `METRICS.GET(name=traffic)` (device-wide)
- `METRICS.GET(name=traffic, app=...)` (per-app)
- `METRICS.RESET(name=traffic)` (device-wide reset)
- `METRICS.RESET(name=traffic, app=...)` (per-app reset)

Traffic counters MUST be always-on, fixed-dimension counters:
- dimensions: `dns/rxp/rxb/txp/txb`
- each dimension value: `{allow, block}` (uint64)

Device-wide results MUST be full (include tracked + untracked apps).

#### Scenario: Device-wide traffic shape is stable
- **WHEN** client sends `{"id":1,"cmd":"METRICS.GET","args":{"name":"traffic"}}`
- **THEN** daemon SHALL respond `ok=true`
- **AND** `result.traffic` SHALL include keys `dns/rxp/rxb/txp/txb`
- **AND** each of those keys SHALL include `allow` and `block` counters

#### Scenario: Per-app traffic includes identity and traffic
- **WHEN** client sends `{"id":2,"cmd":"METRICS.GET","args":{"name":"traffic","app":{"uid":10123}}}`
- **THEN** daemon SHALL respond `ok=true`
- **AND** `result` SHALL include `uid`, `userId`, and `app`
- **AND** `result.traffic` SHALL include keys `dns/rxp/rxb/txp/txb`

### Requirement: Traffic counters semantics are locked and gated by BLOCK only
The system MUST implement the traffic counter semantics below, and MUST gate counter updates only on `settings.blockEnabled()` (BLOCK), not on `tracked`.

Semantics (v1):
- `dns` counts DNS requests (per DNS verdict); `blocked=false → allow`, `blocked=true → block`.
- `rxp/rxb` count packet allow/block on NFQUEUE INPUT direction (external→local).
- `txp/txb` count packet allow/block on NFQUEUE OUTPUT direction (local→external).
- bytes counters (`rxb/txb`) MUST use NFQUEUE payload length (same as PKTSTREAM `length`).
- would-match (log-only/would-block) MUST NOT change final verdict; therefore it MUST be counted as `allow`.

gating:
- When `settings.blockEnabled()==true`, the system MUST update traffic counters.
- When `settings.blockEnabled()==false`, the system MUST NOT update traffic counters.
- The system MUST NOT gate traffic counters on `tracked`.

#### Scenario: BLOCK=0 does not update traffic counters
- **GIVEN** `BLOCK=0`
- **WHEN** the device generates DNS and packet traffic
- **THEN** subsequent `METRICS.GET(name=traffic)` results SHALL NOT increase due to that traffic

### Requirement: Traffic counters can be reset device-wide or per-app
The daemon MUST support resetting traffic counters both device-wide and per-app, as defined below.

Reset semantics (v1):
- `METRICS.RESET(name=traffic)` MUST clear both device-wide and per-app traffic counters.
- `METRICS.RESET(name=traffic, app=...)` MUST clear only the target app's traffic counters.
- `RESETALL` MUST also clear traffic counters.

#### Scenario: METRICS.RESET(name=traffic, app=...) clears only that app
- **GIVEN** at least two apps have non-zero traffic counters
- **WHEN** client calls `METRICS.RESET` with `name=traffic` and an `app` selector for one app
- **THEN** subsequent `METRICS.GET(name=traffic, app=...)` for that app SHALL return all zeros
- **AND** subsequent `METRICS.GET(name=traffic, app=...)` for the other app SHALL remain unchanged
