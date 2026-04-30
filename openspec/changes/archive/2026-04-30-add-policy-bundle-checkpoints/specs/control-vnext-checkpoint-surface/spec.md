## ADDED Requirements

### Requirement: vNext exposes policy checkpoint commands
The daemon MUST expose vNext commands:
- `CHECKPOINT.LIST`
- `CHECKPOINT.SAVE`
- `CHECKPOINT.RESTORE`
- `CHECKPOINT.CLEAR`

All checkpoint commands MUST follow vNext netstring framing, strict JSON request parsing, response envelope invariants, and unknown-key rejection.

#### Scenario: Unknown checkpoint args are rejected
- **WHEN** a client sends a `CHECKPOINT.*` command with an unknown `args` key
- **THEN** the daemon SHALL respond `ok=false` with `error.code="SYNTAX_ERROR"`

### Requirement: CHECKPOINT.LIST reports fixed slot metadata
`CHECKPOINT.LIST` MUST accept empty `args` and return `result.slots[]` with exactly three entries sorted by `slot` ascending.

Each slot entry MUST include:
- `slot` (`0|1|2`)
- `present` (boolean)

When `present=true`, the entry MUST also include `formatVersion`, `sizeBytes`, and `createdAt`. The daemon MAY include a compact `summary` object with policy counts.

#### Scenario: Listing slots returns all fixed slots
- **WHEN** a client sends `{"cmd":"CHECKPOINT.LIST","args":{}}`
- **THEN** the daemon SHALL respond `ok=true`
- **AND** `result.slots[]` SHALL contain exactly slots `0`, `1`, and `2` in ascending order

### Requirement: CHECKPOINT.SAVE writes one bounded slot atomically
`CHECKPOINT.SAVE` MUST accept `args={"slot":0|1|2}`.

On success, the daemon MUST atomically replace the selected slot with a new policy bundle for the current policy state and return metadata for the saved slot. If serialization or capacity validation fails, the daemon MUST leave any previous slot contents unchanged.

#### Scenario: Save replaces selected slot
- **WHEN** a client saves checkpoint slot `2`
- **THEN** the daemon SHALL write only slot `2`
- **AND** the daemon SHALL return `ok=true` with metadata for slot `2`

#### Scenario: Save rejects invalid slot
- **WHEN** a client sends `CHECKPOINT.SAVE` with `slot=3`
- **THEN** the daemon SHALL respond `ok=false` with `error.code="INVALID_ARGUMENT"`

### Requirement: CHECKPOINT.RESTORE restores an existing slot atomically
`CHECKPOINT.RESTORE` MUST accept `args={"slot":0|1|2}`.

If the selected slot is empty, the daemon MUST reject the request with `error.code="NOT_FOUND"`. If the slot exists but cannot be parsed or validated, the daemon MUST reject the request without changing live policy state. On success, the daemon MUST return metadata for the restored slot.

#### Scenario: Restore missing slot returns not found
- **WHEN** a client restores a slot that has no saved bundle
- **THEN** the daemon SHALL respond `ok=false` with `error.code="NOT_FOUND"`

#### Scenario: Restore succeeds for valid slot
- **GIVEN** checkpoint slot `0` contains a valid policy bundle
- **WHEN** a client sends `CHECKPOINT.RESTORE` for slot `0`
- **THEN** the daemon SHALL respond `ok=true`
- **AND** live policy state SHALL match the checkpoint bundle

### Requirement: CHECKPOINT.CLEAR removes one slot idempotently
`CHECKPOINT.CLEAR` MUST accept `args={"slot":0|1|2}` and remove the selected slot if present.

Clearing an already empty slot MUST succeed and return metadata showing `present=false`.

#### Scenario: Clear empty slot succeeds
- **GIVEN** checkpoint slot `1` is empty
- **WHEN** a client sends `CHECKPOINT.CLEAR` for slot `1`
- **THEN** the daemon SHALL respond `ok=true`
- **AND** returned metadata SHALL show `present=false`
