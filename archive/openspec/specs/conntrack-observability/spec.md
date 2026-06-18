# conntrack-observability Specification

## Purpose
TBD - created by archiving change add-control-vnext-metrics. Update Purpose after archive.
## Requirements
### Requirement: Conntrack health counters are exposed via METRICS.GET(name=conntrack)
The daemon MUST expose conntrack health counters via `METRICS.GET(name=conntrack)`.

The response MUST be `ok=true` and MUST include `result.conntrack` with fixed fields (uint64):
- `totalEntries`
- `creates`
- `expiredRetires`
- `overflowDrops`

The response MUST also include `result.conntrack.byFamily` with:
- `byFamily.ipv4` object including the same fixed fields (uint64)
- `byFamily.ipv6` object including the same fixed fields (uint64)

#### Scenario: Conntrack metrics returns required fields (including byFamily)
- **WHEN** client sends `{"id":1,"cmd":"METRICS.GET","args":{"name":"conntrack"}}`
- **THEN** daemon SHALL respond `ok=true`
- **AND** `result.conntrack` SHALL include `totalEntries/creates/expiredRetires/overflowDrops`
- **AND** `result.conntrack.byFamily.ipv4` SHALL include `totalEntries/creates/expiredRetires/overflowDrops`
- **AND** `result.conntrack.byFamily.ipv6` SHALL include `totalEntries/creates/expiredRetires/overflowDrops`

### Requirement: Conntrack does not support independent reset in v1
The daemon MUST reject `METRICS.RESET(name=conntrack)` in v1, and conntrack counters MUST only be cleared via `RESETALL`.

Reset semantics (v1):
- `METRICS.RESET(name=conntrack)` MUST be rejected with `error.code="INVALID_ARGUMENT"`.
- `RESETALL` MUST clear conntrack counters.

#### Scenario: METRICS.RESET(name=conntrack) is rejected
- **WHEN** client sends `{"id":2,"cmd":"METRICS.RESET","args":{"name":"conntrack"}}`
- **THEN** daemon SHALL respond `ok=false` with `error.code="INVALID_ARGUMENT"`

