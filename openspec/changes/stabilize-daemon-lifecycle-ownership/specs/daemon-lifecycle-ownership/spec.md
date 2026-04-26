## ADDED Requirements

### Requirement: Main-owned shutdown
The daemon MUST centralize process shutdown ownership in the main runtime. `SIGINT`, `SIGTERM`, and legacy `DEV.SHUTDOWN` MUST request shutdown and MUST NOT directly exit the process from arbitrary worker threads. The main runtime MUST wake promptly from the periodic save wait, perform one final save, and then return from the daemon entry path.

#### Scenario: Signal wakes periodic wait
- **WHEN** the daemon is waiting for the next periodic save and receives `SIGTERM` or `SIGINT`
- **THEN** the main runtime SHALL wake without waiting for the full save interval
- **AND** the main runtime SHALL perform final save before exiting

#### Scenario: DEV.SHUTDOWN uses runtime owner
- **WHEN** an authorized legacy client invokes `DEV.SHUTDOWN`
- **THEN** the command SHALL return the existing success response
- **AND** shutdown SHALL be requested through the same main-owned runtime path

### Requirement: Stream reset preserves fd ownership
The daemon MUST ensure vNext stream reset does not return, shutdown, or close bare client fd values from non-owning code. Stream reset MUST clear stream state and signal the owning session to stop; the owning session MUST close its own socket.

#### Scenario: RESETALL cancels stream without raw fd shutdown
- **WHEN** `RESETALL` clears active vNext stream subscriptions
- **THEN** stream manager SHALL clear subscription state without returning client fd values
- **AND** each affected session SHALL observe cancellation and close its own connection

### Requirement: Client workers are bounded and deadline-limited
The daemon MUST bound active detached client workers for control and DNS entry points. Accepted clients beyond the configured internal budget MUST be closed without creating a worker. Blocking send paths for control and DNS clients MUST have a total deadline so slow readers cannot keep a worker indefinitely.

#### Scenario: Client budget rejects excess workers
- **WHEN** the active client budget for an entry point is exhausted
- **THEN** a newly accepted client SHALL be closed without starting another detached client worker

#### Scenario: Slow reader cannot keep worker indefinitely
- **WHEN** a client stops reading a response
- **THEN** the daemon SHALL stop attempting to write that response after the send deadline and release the worker resources
