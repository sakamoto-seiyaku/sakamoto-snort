## MODIFIED Requirements

### Requirement: HELLO returns protocol handshake, limits, and daemon identity
The daemon MUST implement `HELLO` and SHALL return:
`protocol`, `protocolVersion`, `framing`, `maxRequestBytes`, `maxResponseBytes`, `daemonBuildId`, `artifactAbi`, and `capabilities` in `HELLO.result`.

`daemonBuildId` MUST be a non-empty string identifying the daemon artifact build. `artifactAbi` MUST identify the running artifact ABI, and SHALL be `arm64-v8a` for the first NDK release. `capabilities` MUST be an array of stable strings that RuntimeService can use for compatibility checks.

#### Scenario: HELLO response contains required fields
- **WHEN** the client sends `{"id":1,"cmd":"HELLO","args":{}}`
- **THEN** the daemon SHALL respond `ok=true` and include the required handshake, limit, and daemon identity fields in `result`

#### Scenario: Existing HELLO clients remain compatible
- **WHEN** an existing vNext client reads only `protocol`, `protocolVersion`, `framing`, `maxRequestBytes`, and `maxResponseBytes`
- **THEN** the added daemon identity fields SHALL NOT change the meaning or type of those existing fields
