## ADDED Requirements

### Requirement: IP smoke covers packet Debug Stream explainability
IP device smoke MUST include coverage proving that tracked `pkt` Debug Stream events carry enough explanation to reconstruct packet verdict decisions.

The coverage MUST verify at least:
- IPRULES enforce allow
- IPRULES enforce block
- allow with IPRULES would-block overlay
- `IFACE_BLOCK` short-circuit
- tracked disabled suppression
- self-contained IPRULES and interface-mask evidence without Flow Telemetry, Metrics, or follow-up rule queries

The test MUST use vNext control paths and MUST NOT depend on Flow Telemetry records or Metrics output to prove the explain chain.

#### Scenario: IPRULES allow explanation is visible on device
- **GIVEN** a target app has `tracked=1`
- **AND** an enforcing IPRULES allow rule matches Tier-1 traffic
- **WHEN** the traffic succeeds
- **THEN** the captured `type="pkt"` stream event SHALL include `explain.kind="packet-verdict"`
- **AND** the `iprules.enforce` stage SHALL be the winner and include the expected allow `ruleId` and rule definition snapshot

#### Scenario: IPRULES block explanation is visible on device
- **GIVEN** a target app has `tracked=1`
- **AND** an enforcing IPRULES block rule matches Tier-1 traffic
- **WHEN** the traffic is blocked
- **THEN** the captured `type="pkt"` stream event SHALL include `explain.final.reasonId="IP_RULE_BLOCK"`
- **AND** the `iprules.enforce` stage SHALL be the winner and include the expected block `ruleId` and rule definition snapshot

#### Scenario: Would-match explanation is visible on device
- **GIVEN** a target app has `tracked=1`
- **AND** an IPRULES `action=block,enforce=0,log=1` rule matches Tier-1 traffic
- **WHEN** the traffic is accepted
- **THEN** the captured `type="pkt"` stream event SHALL include `explain.final.wouldDrop=true`
- **AND** the `iprules.would` stage SHALL include the expected `wouldRuleId` and rule definition snapshot

#### Scenario: IFACE_BLOCK explanation is visible on device
- **GIVEN** a target app has `tracked=1`
- **AND** app interface policy blocks Tier-1 traffic
- **WHEN** the traffic is blocked
- **THEN** the captured `type="pkt"` stream event SHALL include `explain.final.reasonId="IFACE_BLOCK"`
- **AND** the `ifaceBlock` stage SHALL be the winner
- **AND** the `ifaceBlock` stage SHALL expose the app interface mask, packet interface bit/kind, evaluated intersection, and short-circuit reason
- **AND** lower-priority packet stages SHALL show they were not evaluated because of short-circuiting

#### Scenario: tracked disabled suppresses packet explanation
- **GIVEN** a target app has `tracked=0`
- **WHEN** Tier-1 packet traffic is triggered while `STREAM.START(type="pkt")` is subscribed
- **THEN** the stream SHALL NOT emit a per-event `pkt` explanation for that traffic
- **AND** the stream SHALL emit or preserve the existing suppressed notice behavior
