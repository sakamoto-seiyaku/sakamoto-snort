## ADDED Requirements

### Requirement: Blocking list mask bits are single-bit and bounded
The system SHALL treat a blocking list's `blockMask` as a single-bit selector and reject values outside the supported set.

Supported blocking list bits:
- `1` (standard)
- `8` (reinforced)
- `2`, `4`, `16`, `32`, `64` (combinable extra chains)

The system SHALL reject:
- `0`
- any multi-bit mask (e.g. `1|8`)
- `128` (reserved for app custom-list behavior)
- any other unknown bit.

#### Scenario: Create a list with an invalid mask
- **WHEN** the controller adds/updates a blocking list with `blockMask=0` or `blockMask=3`
- **THEN** the command is rejected and the list is not created/updated.

#### Scenario: Create a list with a valid extra-chain mask
- **WHEN** the controller adds a blocking list with `blockMask=16`
- **THEN** the list is accepted and its domains contribute `16` to `domainMask` on match.

### Requirement: App mask can combine multiple list bits
The system SHALL allow an app's `blockMask` to be any bitwise combination of supported blocking list bits.

#### Scenario: App enables only one extra chain
- **GIVEN** a domain matches a list with `blockMask=32`
- **WHEN** an app has `appMask=32`
- **THEN** the domain is blocked via the `appMask & domainMask` decision.

#### Scenario: Reinforced includes standard via appMask (not listMask)
- **GIVEN** a standard list uses `blockMask=1` and a reinforced-only list uses `blockMask=8`
- **WHEN** an app has `appMask=1|8`
- **THEN** both lists can affect the app (subject to other higher-priority rules).

### Requirement: Reinforced appMask implies standard appMask
The system SHALL normalize app `blockMask` such that when bit `8` (reinforced) is set, bit `1` (standard) is also set.

#### Scenario: Setting BLOCKMASK to reinforced-only is normalized
- **WHEN** the controller sets an app `BLOCKMASK` to `8`
- **THEN** the stored/reported app mask includes `1|8` (i.e. `9`).

#### Scenario: Setting BLOCKMASKDEF to reinforced-only is normalized
- **WHEN** the controller sets `BLOCKMASKDEF` to `8`
- **THEN** the stored/reported default mask includes `1|8` (i.e. `9`).

### Requirement: No cross-listId dedupe during list writes
The system SHALL NOT perform cross-listId "skip write" deduplication when writing domains into a list.
Each listId MUST remain self-contained so that enabling/disabling/removing any single listId does not depend on other listIds.

#### Scenario: Two lists contain the same domain and are independently disabled
- **GIVEN** list A and list B both contain `ads.example` in their on-disk content
- **WHEN** list A is disabled while list B remains enabled
- **THEN** `ads.example` continues to contribute list B's `blockMask` to `domainMask`.
