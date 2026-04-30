## Context

The frontend needs a reliable undo/self-rescue primitive for policy changes that can affect network verdicts. Today it can read `CONFIG`, DomainPolicy/Rules/Lists, and IPRULES state and then issue multiple apply commands to rebuild a baseline, but that workflow cannot guarantee atomic restore across modules, cannot safely preserve rule identity allocation, and cannot clean transient verdict state consistently.

The daemon already has the right concurrency foundation: `snortSave()` and `snortResetAll()` share a save/reset coordinator, vNext mutation commands share `mutexControlMutations`, and `RESETALL` quiesces packet/DNS publication through `mutexListeners` and the reset epoch. Checkpoint restore should reuse those boundaries. It should not reuse the startup-oriented per-module `restore()` functions as the restore transaction, because those functions are allowed to swallow read errors or clear one module on failure.

## Goals / Non-Goals

**Goals:**

- Provide a small backend primitive that lets the frontend save and restore policy checkpoints with strong rollback semantics.
- Expose exactly three fixed numeric slots and leave naming, history, notes, and workflow meaning to the frontend.
- Snapshot only verdict-affecting policy state needed for rollback.
- Guarantee `CHECKPOINT.RESTORE` is atomic-or-no-op.
- Clear transient verdict state and runtime observability surfaces after successful restore so old runtime facts do not affect the restored policy.
- Keep C++ implementation RAII-based, const-correct, and free of raw owning pointers or C-style casts.

**Non-Goals:**

- No frontend metadata, named checkpoint history, labels, colors, notes, profile model, or product timeline.
- No Flow Telemetry record replay, Top-K/timeline/history, Geo/ASN, health snapshot, Billing, or diagnostic export.
- No public import/export package format beyond the daemon's private checkpoint slot files.
- No best-effort or partial restore semantics.

## Decisions

1. **Use `CHECKPOINT.*` as the command family.**

   `CHECKPOINT.LIST/SAVE/RESTORE/CLEAR` matches the frontend and product language while keeping the backend scope intentionally small. `POLICYBUNDLE.*` was considered, but it exposes an implementation term to clients.

2. **Expose three numeric slots.**

   Slots `0..2` are enough for before-risky-change, last-known-good, and manual-save workflows without forcing those roles into the daemon. The daemon only stores the slot number and machine-readable metadata.

3. **Store private versioned policy bundles, capped at 64 MiB per slot.**

   The bundle format is daemon-private and starts with a format version, size metadata, and section table. Each slot is written using tmp-and-rename. The cap bounds storage and makes device failures testable while still allowing large local domain lists.

4. **Snapshot policy state only.**

   The bundle includes device/app verdict config, DomainRules, DomainPolicy, DomainLists metadata and contents, and IPRULES rule definitions plus rule identity allocation state. It excludes counters, stats, streams, telemetry rings, learned runtime associations, frontend metadata, and product history.

5. **Restore through staging, not module startup restore.**

   Restore first parses and validates the entire bundle into staging objects. Validation includes schema version, cross-reference checks, domain list limits, domain rule references, IPRULES canonicalization/preflight, and slot size. Live state changes only after staging is complete.

6. **Commit under the existing mutation/reset boundary.**

   `CHECKPOINT.SAVE`, `RESTORE`, and `CLEAR` are vNext mutation commands. `RESTORE` uses the save/reset coordinator, the control mutation coordinator, and a datapath quiesce window for the final commit and cleanup. Expensive parsing and validation should happen before the short datapath quiesce window when possible.

7. **Successful restore invalidates incoherent runtime state.**

   After commit, the daemon clears verdict-affecting transient state such as conntrack, learned domain/IP/host associations, and IPRULES caches. It also resets or invalidates stream/telemetry state and clears metrics that would otherwise describe the pre-restore policy epoch. The frontend must reopen stream/telemetry consumers after restore.

## Risks / Trade-offs

- [Risk] Bundle format duplicates existing save serialization. -> Mitigation: share small typed encode/decode helpers where safe, but keep checkpoint parsing strict and staging-oriented.
- [Risk] Large domain lists can make save/restore expensive. -> Mitigation: fixed 64 MiB slot cap, tmp-and-rename writes, and a short datapath quiesce window only for final commit.
- [Risk] Atomic commit touches multiple managers. -> Mitigation: introduce explicit snapshot/staging/commit helpers and host tests for failure before commit.
- [Risk] Runtime cleanup can surprise clients with closed streams or telemetry sessions. -> Mitigation: document restore as a policy epoch change requiring clients to reopen those surfaces.
- [Risk] Slot files become incompatible after future policy schema changes. -> Mitigation: version the bundle and reject unsupported versions with no live-state changes.

## Migration Plan

- Add the new command surface and documentation without changing existing save tree restore behavior.
- Existing devices start with all checkpoint slots empty.
- Rollback for the feature is removing the `CHECKPOINT.*` command handling and ignoring checkpoint slot files; existing policy save tree remains unchanged.
