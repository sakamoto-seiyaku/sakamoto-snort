## MODIFIED Requirements

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

