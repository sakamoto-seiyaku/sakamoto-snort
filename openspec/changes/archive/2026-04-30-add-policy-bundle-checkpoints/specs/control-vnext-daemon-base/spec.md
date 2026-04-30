## ADDED Requirements

### Requirement: Checkpoint commands use the vNext mutation and reset boundary
The daemon MUST serialize `CHECKPOINT.SAVE`, `CHECKPOINT.RESTORE`, and `CHECKPOINT.CLEAR` with ordinary vNext policy mutation commands through the control-plane mutation boundary.

`CHECKPOINT.RESTORE` MUST be mutually exclusive with in-flight control-plane mutations and MUST use the existing save/reset coordination needed to prevent periodic save from writing a mixed pre/post-restore state.

The final live-state commit and transient cleanup for `CHECKPOINT.RESTORE` MUST quiesce packet and DNS verdict publication. Expensive parsing, validation, and response construction MUST NOT hold the datapath global lock.

#### Scenario: Restore waits for in-flight mutation
- **WHEN** `CHECKPOINT.RESTORE` is requested while `DOMAINLISTS.IMPORT` or `IPRULES.APPLY` is in progress
- **THEN** restore SHALL wait until that mutation leaves the control-plane mutation boundary before committing restored policy state

#### Scenario: Save and clear do not quiesce datapath for parsing or response work
- **WHEN** a client runs `CHECKPOINT.SAVE` or `CHECKPOINT.CLEAR`
- **THEN** the daemon SHALL NOT hold the datapath global lock while constructing JSON responses or doing non-commit file work

#### Scenario: Restore commit is not interleaved with periodic save
- **WHEN** periodic daemon save overlaps with `CHECKPOINT.RESTORE`
- **THEN** the persisted save tree SHALL end in either the complete pre-restore state or the complete post-restore state
- **AND** it SHALL NOT contain a mixed partial checkpoint restore
