# control-vnext-daemon-base Specification

## Purpose
TBD - created by archiving change add-control-vnext-daemon-base. Update Purpose after archive.
## Requirements
### Requirement: Daemon exposes vNext control endpoints (unix + gated TCP)
The daemon MUST expose vNext control endpoints as defined by `CONTROL_PROTOCOL_VNEXT.md`:
- Unix socket `sucre-snort-control-vnext` (filesystem + abstract)
- TCP port `60607` gated by `inetControl()`

#### Scenario: Connect via unix abstract socket
- **WHEN** a client connects to `@sucre-snort-control-vnext`
- **THEN** the daemon SHALL accept the connection and speak vNext netstring framing

#### Scenario: TCP endpoint is gated by inetControl()
- **WHEN** `inetControl()` is disabled
- **THEN** the daemon SHALL NOT expose/accept vNext TCP connections on port `60607`

### Requirement: vNext framing is netstring and enforces maxRequestBytes
For all vNext connections, the daemon MUST:
- read/write frames using netstring `<len>:<payload>,`
- enforce a hard `maxRequestBytes` limit for client→server frames
- enforce a hard `maxResponseBytes` limit for server→client frames

#### Scenario: Oversized request frame disconnects without response
- **WHEN** a client sends a frame with `len > maxRequestBytes`
- **THEN** the daemon SHALL immediately close the connection and SHALL NOT send a response frame

### Requirement: HELLO returns protocol handshake and limits
The daemon MUST implement `HELLO` and SHALL return:
`protocol`, `protocolVersion`, `framing`, `maxRequestBytes`, `maxResponseBytes` in `HELLO.result`.

#### Scenario: HELLO response contains required fields
- **WHEN** the client sends `{"id":1,"cmd":"HELLO","args":{}}`
- **THEN** the daemon SHALL respond `ok=true` and include the required handshake fields in `result`

### Requirement: Meta commands exist and follow vNext envelope invariants
The daemon MUST implement vNext meta commands `QUIT` and `RESETALL` and MUST follow the vNext response invariants (`id/ok/result|error`).

#### Scenario: QUIT responds then closes connection
- **WHEN** a client sends `{"id":7,"cmd":"QUIT","args":{}}`
- **THEN** the daemon SHALL send exactly one response with `{"id":7,"ok":true}` and then close the connection

#### Scenario: RESETALL responds ok=true
- **WHEN** a client sends `{"id":9,"cmd":"RESETALL","args":{}}`
- **THEN** the daemon SHALL send exactly one response with `ok=true`

### Requirement: vNext mutation dispatch does not hold the datapath global lock

The daemon MUST separate vNext control-plane mutation serialization from the datapath global lock. Ordinary vNext mutation commands such as `CONFIG.SET`, `DOMAINRULES.APPLY`, `DOMAINPOLICY.APPLY`, `DOMAINLISTS.APPLY`, `DOMAINLISTS.IMPORT`, `IPRULES.APPLY`, and `METRICS.RESET` MUST NOT hold `mutexListeners` while parsing, validating, compiling, doing filesystem I/O, applying manager-local mutations, or constructing responses.

Those mutation commands MUST still be serialized with each other by a control-plane mutation boundary that is not used by packet / DNS hot paths. `RESETALL` MUST remain mutually exclusive with in-flight control-plane mutations and MUST remain the command that quiesces packet / DNS hot paths before resetting global runtime state.

#### Scenario: Large vNext mutation does not quiesce packet verdicts

- **WHEN** a vNext client runs a large `DOMAINLISTS.IMPORT` or `IPRULES.APPLY`
- **THEN** packet / DNS hot paths SHALL NOT wait on `mutexListeners` solely because that mutation command is parsing, validating, compiling, writing files, or constructing its response

#### Scenario: vNext mutations remain serialized with each other

- **WHEN** two vNext clients concurrently send mutation commands
- **THEN** the daemon SHALL execute their mutation effects through a single control-plane mutation serialization boundary

#### Scenario: RESETALL waits for in-flight vNext mutation before reset

- **WHEN** `RESETALL` is requested while a vNext mutation is in progress
- **THEN** `RESETALL` SHALL wait until the mutation leaves the control-plane mutation boundary before it quiesces packet / DNS hot paths and resets global runtime state

### Requirement: Inventory commands return stable shapes
The daemon MUST implement `APPS.LIST` and `IFACES.LIST` as defined in `CONTROL_COMMANDS_VNEXT.md`.

#### Scenario: APPS.LIST is stable and sorted
- **WHEN** a client requests `APPS.LIST`
- **THEN** the daemon SHALL return `result.apps[]` sorted by `uid` ascending and include `result.truncated`

#### Scenario: IFACES.LIST is sorted by ifindex
- **WHEN** a client requests `IFACES.LIST`
- **THEN** the daemon SHALL return `result.ifaces[]` sorted by `ifindex` ascending

### Requirement: CONFIG.GET/SET supports v1 keys with strict validation
The daemon MUST implement `CONFIG.GET` and `CONFIG.SET` for the v1 key set defined in `CONTROL_COMMANDS_VNEXT.md`, and MUST reject unknown keys and invalid values.

#### Scenario: CONFIG.GET device keys returns values
- **WHEN** a client sends a device-scope `CONFIG.GET` with a list of supported keys
- **THEN** the daemon SHALL return `ok=true` and include a value for each requested key

#### Scenario: CONFIG.SET rejects unknown keys
- **WHEN** a client sends `CONFIG.SET` containing an unsupported key
- **THEN** the daemon SHALL respond with `ok=false` and `error.code="INVALID_ARGUMENT"`

### Requirement: inetControl migration exemption includes 60606 and 60607
When `inetControl()` is enabled, the dataplane MUST exempt control traffic for both legacy and vNext TCP ports to avoid interfering with control connectivity.

#### Scenario: Control TCP traffic bypasses blocking decisions
- **WHEN** `inetControl()` is enabled and a TCP packet has `srcPort` or `dstPort` equal to `60606` or `60607`
- **THEN** the dataplane SHALL bypass blocking logic for that packet
