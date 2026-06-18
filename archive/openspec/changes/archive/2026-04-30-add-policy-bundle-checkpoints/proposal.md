## Why

Flow Telemetry now covers normal observability records and Debug Stream explainability is already tracked as a separate diagnostic change. The remaining frontend-facing backend gap is safe rollback: the frontend can read and re-apply scattered policy state, but it cannot provide a strong checkpoint/restore guarantee without a backend atomic policy bundle primitive.

## What Changes

- Add fixed-slot policy bundle checkpoints for frontend undo/self-rescue workflows.
- Add vNext `CHECKPOINT.LIST`, `CHECKPOINT.SAVE`, `CHECKPOINT.RESTORE`, and `CHECKPOINT.CLEAR` commands.
- Store exactly three numeric slots (`0..2`) with no backend naming, notes, timeline, or product workflow metadata.
- Snapshot only verdict-affecting policy state: device/app verdict config, DomainRules, DomainPolicy, DomainLists metadata and list contents, and IPRULES rules including rule identity allocation state.
- Cap each slot at 64 MiB and report clear capacity errors.
- Make `CHECKPOINT.RESTORE` atomic-or-no-op: parse, validate, and stage the full bundle before committing any live state.
- On successful restore, clear verdict-affecting transient state and invalidate/clear runtime observability surfaces that cannot remain coherent across rollback.
- Keep Flow Telemetry records, Top-K, timeline/history, Geo/ASN enrichment, health snapshots, frontend metadata, and full import/export packages out of this change.

## Capabilities

### New Capabilities

- `policy-bundle-checkpoints`: Defines fixed-slot policy bundle snapshot, capacity, atomic restore, transient cleanup, and persistence semantics.
- `control-vnext-checkpoint-surface`: Defines the vNext `CHECKPOINT.*` command contract and strict response/error shapes.
- `dx-smoke-checkpoint-casebook`: Defines device coverage for save, mutate, restore, and verdict rollback behavior.

### Modified Capabilities

- `control-vnext-daemon-base`: Adds checkpoint commands to the vNext mutation/reset concurrency boundary so checkpoint save/restore cannot race ordinary policy mutations, periodic save, or datapath verdict publication.

## Impact

- Affected APIs: vNext control protocol gains `CHECKPOINT.LIST/SAVE/RESTORE/CLEAR`; `docs/INTERFACE_SPECIFICATION.md` must document the command shapes and slot semantics.
- Affected code: checkpoint bundle serializer/parser, staged policy model, control-vnext daemon command dispatch, Settings/App/Domain/IPRULES state extraction and atomic commit helpers, reset/transient cleanup hooks, and `sucre-snort-ctl`.
- Affected tests: host command tests, bundle parser/serializer tests, atomic no-op failure tests, control mutation concurrency tests, and device smoke save/mutate/restore cases.
- Dependencies: no new external libraries, no Flow Telemetry ABI change, no persistent migration for existing save tree.
