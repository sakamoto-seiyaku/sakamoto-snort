## ADDED Requirements

### Requirement: Single-user behavior remains backward compatible
On devices where only user 0 exists, multi-user support MUST NOT change the functional behavior of existing commands, except for explicitly documented additions (e.g. extra JSON fields like `userId`/`appId` and updated HELP text).

#### Scenario: APP listing on a single-user device
- **GIVEN** a device with only user 0
- **WHEN** a client queries `APP.UID`, `APP.NAME`, and `APP.A` using pre-existing call patterns
- **THEN** the results SHALL remain compatible with pre-multi-user behavior, and any returned per-app objects MUST report `userId = 0`

