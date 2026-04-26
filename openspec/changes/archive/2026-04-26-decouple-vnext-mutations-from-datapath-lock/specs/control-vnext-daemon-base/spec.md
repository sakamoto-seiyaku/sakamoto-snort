## ADDED Requirements

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
