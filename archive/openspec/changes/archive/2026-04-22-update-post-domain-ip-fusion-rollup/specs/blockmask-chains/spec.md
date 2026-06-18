## ADDED Requirements

### Requirement: Legacy-only masks do not introduce extra-chain bits
When all blocking lists use only the legacy bits (`1` standard and `8` reinforced) and apps only enable legacy list bits, the system SHALL NOT introduce any extra-chain bits (`2/4/16/32/64`) into `domainMask` results.

#### Scenario: Querying a domain matched only by legacy-masked lists
- **GIVEN** a domain appears only in lists whose `blockMask` is `1` or `8`
- **WHEN** the system evaluates that domain for blocking
- **THEN** the resulting `domainMask` MUST NOT contain any of `2/4/16/32/64`

