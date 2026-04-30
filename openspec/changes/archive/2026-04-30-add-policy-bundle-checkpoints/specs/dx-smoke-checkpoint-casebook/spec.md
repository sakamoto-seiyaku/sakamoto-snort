## ADDED Requirements

### Requirement: Device smoke covers policy checkpoint rollback
Device smoke coverage MUST prove that policy checkpoints can save current policy, observe a policy mutation changing verdict behavior, and restore the previous verdict behavior.

The smoke MUST use vNext control commands and MUST NOT depend on frontend-local checkpoint reconstruction.

#### Scenario: Domain policy checkpoint restores DNS verdict
- **GIVEN** a device has a baseline DomainPolicy verdict for a test app and domain
- **WHEN** the smoke saves checkpoint slot `0`
- **AND** mutates DomainPolicy or DomainLists so the DNS verdict changes
- **AND** restores checkpoint slot `0`
- **THEN** the DNS verdict for that app and domain SHALL return to the checkpoint behavior

#### Scenario: IPRULES checkpoint restores packet verdict
- **GIVEN** a device has a baseline IPRULES verdict for Tier-1 packet traffic
- **WHEN** the smoke saves checkpoint slot `1`
- **AND** mutates IPRULES so the packet verdict changes
- **AND** restores checkpoint slot `1`
- **THEN** the packet verdict for that Tier-1 traffic SHALL return to the checkpoint behavior

### Requirement: Device smoke covers restore runtime epoch cleanup
Device smoke coverage MUST prove that successful checkpoint restore does not leave stale runtime state that affects later verdicts.

#### Scenario: Restore requires stream and telemetry reopen
- **GIVEN** a stream or telemetry consumer is active before checkpoint restore
- **WHEN** `CHECKPOINT.RESTORE` succeeds
- **THEN** the smoke SHALL verify that the old consumer state is invalidated or closed
- **AND** the smoke SHALL reopen the consumer before collecting post-restore observations

#### Scenario: Restore clears transient verdict state
- **GIVEN** packet or DNS runtime state exists before checkpoint restore
- **WHEN** `CHECKPOINT.RESTORE` succeeds
- **THEN** later verdict checks SHALL not depend on pre-restore conntrack or learned domain/IP/host associations
