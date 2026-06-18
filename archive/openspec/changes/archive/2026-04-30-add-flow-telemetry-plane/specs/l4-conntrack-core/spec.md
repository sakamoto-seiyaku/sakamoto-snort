## ADDED Requirements

### Requirement: Flow Telemetry Flow level is a conntrack observation consumer
When Flow Telemetry is enabled with an active `level="flow"` consumer, the daemon MUST treat Flow Telemetry as an active conntrack/flow observation consumer.

This means the packet path MAY execute conntrack/flow observation even when no active IPRULES rule uses `ct.state` or `ct.direction`.

When Flow Telemetry is off or no telemetry consumer is active, existing conntrack gating semantics MUST remain: if no active rules/function use conntrack output for a `uid+family`, the daemon MUST avoid unnecessary per-packet conntrack update.

#### Scenario: Flow Telemetry drives conntrack observation
- **GIVEN** no active IPRULES rule uses `ct.state` or `ct.direction`
- **AND** Flow Telemetry has an active `level="flow"` consumer
- **WHEN** packets for a supported IPv4 or IPv6 flow pass through the daemon
- **THEN** daemon SHALL be allowed to create/update conntrack-backed flow observation state for telemetry records

#### Scenario: No telemetry and no ct consumer preserves gating
- **GIVEN** no active IPRULES rule uses `ct.state` or `ct.direction`
- **AND** Flow Telemetry is off or has no active consumer
- **WHEN** packets for that `uid+family` pass through the daemon
- **THEN** daemon SHALL preserve existing conntrack gating and avoid unnecessary per-packet conntrack update
