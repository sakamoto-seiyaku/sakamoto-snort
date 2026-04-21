## ADDED Requirements

### Requirement: Netstring framing is encoded and decoded correctly
The control-vNext codec MUST encode and decode frames using the netstring format:
`<len>:<payload>,` where `<len>` is the decimal byte-length of `<payload>`.

#### Scenario: Roundtrip encode/decode of a single frame
- **WHEN** a client encodes a UTF-8 JSON payload as a netstring frame
- **THEN** a decoder SHALL reconstruct the exact original payload bytes

#### Scenario: Partial reads are supported
- **WHEN** a decoder receives a netstring frame split across multiple reads (header and payload fragmented)
- **THEN** the decoder SHALL emit exactly one complete payload once all bytes arrive

#### Scenario: Multiple frames in a single read are supported
- **WHEN** a decoder receives multiple concatenated netstring frames in a single read buffer
- **THEN** the decoder SHALL emit payloads in order, one per frame

### Requirement: Netstring framing errors are rejected deterministically
The codec MUST reject invalid netstring framing and MUST enforce a hard `maxFrameBytes` limit.

#### Scenario: Leading zeros are rejected
- **WHEN** a decoder receives a frame header with a leading zero (except the literal `0:,`)
- **THEN** the decoder SHALL reject the connection/frame as a framing error

#### Scenario: Missing terminator is rejected
- **WHEN** a decoder receives a netstring frame whose payload is not followed by the `,` terminator
- **THEN** the decoder SHALL reject the connection/frame as a framing error

#### Scenario: Oversized frames are rejected
- **WHEN** a decoder receives a header declaring `len > maxFrameBytes`
- **THEN** the decoder SHALL reject the connection/frame without attempting to buffer the full payload

### Requirement: Strict JSON parse and encode is shared and stable
The codec MUST parse and encode strict JSON for vNext control payloads:
- parse from `(char*, len)` without requiring a trailing NUL byte
- top-level MUST be a JSON object
- trailing non-whitespace bytes MUST be rejected
- encoding MUST correctly escape JSON strings (at minimum: `\"`, `\\`, `\n`, `\r`, `\t`)

#### Scenario: Non-object top-level is rejected
- **WHEN** a payload parses as valid JSON but the top-level value is not an object
- **THEN** the codec SHALL reject it as a syntax error

#### Scenario: String escaping is correct
- **WHEN** the codec encodes a JSON object containing strings with quotes, backslashes, and control characters
- **THEN** the encoded JSON SHALL be strict JSON and SHALL roundtrip through the decoder without loss

### Requirement: Envelope helpers enforce vNext invariants and strict reject
The codec MUST provide shared helpers for request/response/event envelopes that enforce:
- request: `{"id":u32,"cmd":string,"args":object}` and unknown top-level keys MUST be rejected
- response: `{"id":u32,"ok":bool}` with exactly one of `result` (when ok=true) or `error` (when ok=false)
- event: MUST contain `type` and MUST NOT contain `id` or `ok`

#### Scenario: Unknown top-level keys are rejected
- **WHEN** a client sends a request envelope with an unknown top-level key
- **THEN** the codec SHALL reject the request with a `SYNTAX_ERROR` classification

