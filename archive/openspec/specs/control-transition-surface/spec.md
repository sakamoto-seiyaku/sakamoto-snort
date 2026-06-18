# control-transition-surface Specification

## Purpose
TBD - created by archiving change stabilize-control-transition-surface. Update Purpose after archive.
## Requirements
### Requirement: Legacy ip-leak knobs are frozen to fixed/no-op semantics
The system SHALL treat the legacy knobs `BLOCKIPLEAKS`, `GETBLACKIPS`, and `MAXAGEIP` as **frozen**:
- Effective `BLOCKIPLEAKS` MUST be `0` (disabled).
- Effective `GETBLACKIPS` MUST be `0` (disabled).
- Effective `MAXAGEIP` MUST be `14400` seconds (4 hours).

The legacy control commands MUST remain wire-compatible:
- Query form (no args) MUST return the fixed value.
- Set form (with args) MUST return `OK` but MUST NOT change the effective value.

The frozen values MUST remain fixed across `RESETALL` and across settings restore from persisted state.

#### Scenario: `BLOCKIPLEAKS` set is acknowledged but has no effect
- **WHEN** a client sends legacy `BLOCKIPLEAKS 1`
- **THEN** the daemon SHALL respond `OK`
- **THEN** a subsequent legacy `BLOCKIPLEAKS` query SHALL return `0`

#### Scenario: `GETBLACKIPS` set is acknowledged but has no effect
- **WHEN** a client sends legacy `GETBLACKIPS 1`
- **THEN** the daemon SHALL respond `OK`
- **THEN** a subsequent legacy `GETBLACKIPS` query SHALL return `0`

#### Scenario: `MAXAGEIP` set is acknowledged but has no effect
- **WHEN** a client sends legacy `MAXAGEIP 1`
- **THEN** the daemon SHALL respond `OK`
- **THEN** a subsequent legacy `MAXAGEIP` query SHALL return `14400`

#### Scenario: Settings restore cannot change frozen values
- **WHEN** the daemon restores settings from persisted state that contains non-frozen values for `BLOCKIPLEAKS/GETBLACKIPS/MAXAGEIP`
- **THEN** the effective values SHALL remain `BLOCKIPLEAKS=0`, `GETBLACKIPS=0`, `MAXAGEIP=14400`

### Requirement: Legacy HELP documents frozen items and vNext guidance
The legacy `HELP` output MUST document that `BLOCKIPLEAKS`, `GETBLACKIPS`, and `MAXAGEIP` are frozen/no-op, and MUST provide guidance for using vNext control.

#### Scenario: `HELP` output contains frozen/no-op markers and vNext hints
- **WHEN** a client sends legacy `HELP`
- **THEN** the response text SHALL mention `BLOCKIPLEAKS`, `GETBLACKIPS`, and `MAXAGEIP` as frozen/no-op
- **THEN** the response text SHALL mention `sucre-snort-ctl`
- **THEN** the response text SHALL mention vNext endpoints (`sucre-snort-control-vnext` and/or port `60607`)

