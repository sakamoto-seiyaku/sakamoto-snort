## ADDED Requirements

### Requirement: Domain smoke covers DNS Debug Stream explainability
Domain device smoke MUST include coverage proving that tracked `dns` Debug Stream events carry enough explanation to reconstruct DomainPolicy decisions.

The coverage MUST verify at least:
- app-scope rule winner
- device-wide rule winner
- mask fallback winner
- tracked disabled suppression
- self-contained rule/list/mask evidence without Flow Telemetry, Metrics, or follow-up rule queries

The test MUST use vNext control paths and MUST NOT depend on Flow Telemetry records or Metrics output to prove the explain chain.

#### Scenario: DNS app rule explanation is visible on device
- **GIVEN** a target app has `tracked=1` and app-scope DomainPolicy ruleIds
- **WHEN** device DNS injection triggers a domain that matches an app block rule
- **THEN** the captured `type="dns"` stream event SHALL include `explain.kind="dns-policy"`
- **AND** the `app.custom.blockRules` stage SHALL be the winner and include the expected `ruleId` and rule snapshot

#### Scenario: DNS device-wide explanation is visible on device
- **GIVEN** a target app has `tracked=1` and no overriding app policy for the test domain
- **AND** device-wide DomainPolicy ruleIds decide the domain
- **WHEN** device DNS injection triggers that domain
- **THEN** the captured `type="dns"` stream event SHALL include a winning `deviceWide.allow` or `deviceWide.block` stage
- **AND** the event SHALL expose the expected `policySource` and self-contained rule or list-entry attribution

#### Scenario: DNS mask fallback evidence is visible on device
- **GIVEN** a target app has `tracked=1` and no matching app or device-wide custom policy for the test domain
- **WHEN** device DNS injection triggers that domain
- **THEN** the captured `type="dns"` stream event SHALL include a winning `maskFallback` stage
- **AND** the stage SHALL expose the effective mask evidence needed to explain the final allow/block decision

#### Scenario: tracked disabled suppresses DNS explanation
- **GIVEN** a target app has `tracked=0`
- **WHEN** device DNS injection triggers a domain while `STREAM.START(type="dns")` is subscribed
- **THEN** the stream SHALL NOT emit a per-event `dns` explanation for that injected domain
- **AND** the stream SHALL emit or preserve the existing suppressed notice behavior
