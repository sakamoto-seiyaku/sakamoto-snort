# sucre-snort-ctl Specification

## Purpose
TBD - created by archiving change add-control-vnext-codec-ctl. Update Purpose after archive.
## Requirements
### Requirement: CLI provides vNext help without daemon HELP
`sucre-snort-ctl` MUST provide a `help` command and a `--help` flag that documents the vNext command directory and includes examples, without requiring a daemon-side `HELP` command.

#### Scenario: --help prints usage and exits
- **WHEN** a user runs `sucre-snort-ctl --help`
- **THEN** the tool SHALL print usage/help text and exit successfully

#### Scenario: help subcommand prints command directory
- **WHEN** a user runs `sucre-snort-ctl help`
- **THEN** the tool SHALL print the supported vNext command directory with examples

### Requirement: CLI can connect via unix sockets and TCP
`sucre-snort-ctl` MUST support connecting to vNext control endpoints via:
- unix domain sockets (filesystem path and/or abstract namespace)
- TCP host:port

#### Scenario: Connect over TCP
- **WHEN** the tool is invoked with a TCP target
- **THEN** it SHALL establish a TCP connection and use netstring framing for all I/O

#### Scenario: Connect over unix socket
- **WHEN** the tool is invoked with a unix socket target
- **THEN** it SHALL establish a unix socket connection and use netstring framing for all I/O

### Requirement: CLI sends requests and decodes responses/events using the shared codec
`sucre-snort-ctl` MUST use the shared `control-vnext-codec` implementation to:
- encode request envelopes into netstring frames
- decode response and event frames
- optionally pretty-print JSON while preserving strict JSON correctness

#### Scenario: Single request/response roundtrip
- **WHEN** the user issues a single vNext request (e.g. `HELLO`)
- **THEN** the tool SHALL send exactly one request frame and print exactly one decoded response frame

#### Scenario: Event frames are printed without confusing them as responses
- **WHEN** the tool receives event frames (frames containing `type` and not containing `id/ok`)
- **THEN** the tool SHALL print them as events and SHALL NOT treat them as responses

