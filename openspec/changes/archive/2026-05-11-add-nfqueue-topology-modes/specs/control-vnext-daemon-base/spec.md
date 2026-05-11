## MODIFIED Requirements

### Requirement: CONFIG.GET/SET supports v1 keys with strict validation
The daemon MUST implement `CONFIG.GET` and `CONFIG.SET` for the v1 key set defined in `CONTROL_COMMANDS_VNEXT.md`, including the device-scope key `nfqueue.topology`, and MUST reject unknown keys and invalid values.

`nfqueue.topology` MUST be a device-scope string enum with values `split-in-out` and `shared-flow-pool`. The value MUST be persisted through the existing settings storage and MUST take effect on the next daemon startup. `CONFIG.SET` MUST NOT rebuild active NFQUEUE listeners or iptables rules in the running daemon.

#### Scenario: CONFIG.GET device keys returns values
- **WHEN** a client sends a device-scope `CONFIG.GET` with a list of supported keys
- **THEN** the daemon SHALL return `ok=true` and include a value for each requested key

#### Scenario: CONFIG.GET returns nfqueue topology
- **WHEN** a client sends `CONFIG.GET` with `scope="device"` and key `nfqueue.topology`
- **THEN** the daemon SHALL return `ok=true`
- **AND** `result.values["nfqueue.topology"]` SHALL be either `split-in-out` or `shared-flow-pool`

#### Scenario: CONFIG.SET persists nfqueue topology
- **WHEN** a client sends `CONFIG.SET` with `scope="device"` and `set={"nfqueue.topology":"shared-flow-pool"}`
- **THEN** the daemon SHALL persist the configured topology
- **AND** a later `CONFIG.GET` for `nfqueue.topology` SHALL return `shared-flow-pool`
- **AND** the running daemon SHALL NOT rebuild active NFQUEUE listeners as part of that command

#### Scenario: CONFIG.SET rejects unsupported nfqueue topology
- **WHEN** a client sends `CONFIG.SET` with `scope="device"` and an unsupported `nfqueue.topology` value
- **THEN** the daemon SHALL respond with `ok=false` and `error.code="INVALID_ARGUMENT"`

#### Scenario: CONFIG.SET rejects app-scope nfqueue topology
- **WHEN** a client sends `CONFIG.SET` with `scope="app"` and key `nfqueue.topology`
- **THEN** the daemon SHALL respond with `ok=false` and `error.code="INVALID_ARGUMENT"`

#### Scenario: CONFIG.SET rejects unknown keys
- **WHEN** a client sends `CONFIG.SET` containing an unsupported key
- **THEN** the daemon SHALL respond with `ok=false` and `error.code="INVALID_ARGUMENT"`
