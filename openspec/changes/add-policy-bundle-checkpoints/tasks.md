## 1. Interface Contract and Planning

- [x] 1.1 Update `docs/INTERFACE_SPECIFICATION.md` with `CHECKPOINT.LIST/SAVE/RESTORE/CLEAR`, fixed slot IDs, 64 MiB cap, error codes, and restore side effects
- [x] 1.2 Update `sucre-snort-ctl` help/command routing for `CHECKPOINT.*`
- [x] 1.3 Add host command tests for strict JSON parsing, unknown args rejection, slot validation, missing slot errors, and response metadata shapes
- [x] 1.4 Add host tests proving checkpoint slots are exactly `0..2` and `CHECKPOINT.LIST` returns sorted fixed slot metadata

## 2. Policy Bundle Model

- [x] 2.1 Add versioned policy bundle snapshot/staging types for verdict config, DomainRules, DomainPolicy, DomainLists, and IPRULES rules/nextRuleId
- [x] 2.2 Add RAII file helpers for checkpoint slot tmp-write, rename commit, clear, metadata stat, and bounded read with the 64 MiB per-slot cap
- [x] 2.3 Implement strict bundle encode/decode with explicit format version, section limits, and no raw owning `new/delete` or C-style casts
- [x] 2.4 Add host serializer/parser tests for valid bundles, unsupported versions, truncated files, over-cap files, duplicate sections, and corrupt section sizes

## 3. State Extraction and Staging Validation

- [x] 3.1 Add const snapshot extraction helpers for current policy state without including counters, stats, telemetry, stream replay, or frontend metadata
- [x] 3.2 Add staging validators for DomainPolicy references, DomainLists metadata/content consistency, domain string limits, and bundle cross-references
- [x] 3.3 Add IPRULES staging validation that preserves rule identity allocation state and reuses canonicalization/preflight checks before live commit
- [x] 3.4 Add host tests proving invalid staged domain references, invalid list data, and invalid IPRULES bundles fail before mutating live state

## 4. Atomic Restore and Runtime Epoch

- [x] 4.1 Add a checkpoint restore coordinator that parses and validates outside the datapath quiesce window, then commits live managers in one controlled restore transaction
- [x] 4.2 Serialize `CHECKPOINT.SAVE/RESTORE/CLEAR` with vNext policy mutations and periodic save using the existing control mutation and save/reset boundaries
- [x] 4.3 Ensure restore commit quiesces packet/DNS verdict publication only for final live-state swap and transient cleanup
- [x] 4.4 On successful restore, clear conntrack, learned domain/IP/host associations, IPRULES caches, metrics that describe the previous policy epoch, active stream state, and telemetry session state
- [x] 4.5 Add host no-op tests proving parse/validation/commit failures leave current policy state and previous slot contents unchanged
- [x] 4.6 Add host concurrency tests for restore versus `DOMAINLISTS.IMPORT`, `IPRULES.APPLY`, periodic save, and packet/DNS verdict publication

## 5. Command Handlers

- [x] 5.1 Implement `CHECKPOINT.LIST` with empty args and sorted slot metadata
- [x] 5.2 Implement `CHECKPOINT.SAVE` with atomic selected-slot replacement and capacity-preserving failure behavior
- [x] 5.3 Implement `CHECKPOINT.RESTORE` with `NOT_FOUND` for empty slots, strict staging validation errors, atomic commit, and restored slot metadata
- [x] 5.4 Implement `CHECKPOINT.CLEAR` as idempotent selected-slot removal
- [x] 5.5 Ensure all checkpoint responses follow vNext envelope limits and do not hold datapath locks while constructing JSON

## 6. Device Coverage

- [x] 6.1 Add device smoke coverage for DomainPolicy save/mutate/restore returning DNS verdicts to checkpoint behavior
- [x] 6.2 Add device smoke coverage for IPRULES save/mutate/restore returning Tier-1 packet verdicts to checkpoint behavior
- [x] 6.3 Add device smoke coverage proving restore invalidates active stream/telemetry consumers and tests reopen them before collecting post-restore evidence
- [x] 6.4 Add device smoke coverage proving stale conntrack or learned domain/IP/host associations do not affect post-restore verdicts

## 7. Verification

- [x] 7.1 Run `openspec validate add-policy-bundle-checkpoints --strict`
- [x] 7.2 Run `cmake --preset dev-debug`
- [x] 7.3 Run the host checkpoint/control/domain/iprules test gate
- [x] 7.4 Run ASAN and UBSAN host variants and fix all memory/UB issues before review
- [x] 7.5 Run TSAN for checkpoint restore concurrency tests if new shared-state commit helpers touch existing locks
- [ ] 7.6 Run device checkpoint smoke coverage
- [x] 7.7 Run `git diff --check` and verify no generated/tracked build artifacts are accidentally staged
- [x] 7.8 Run final verify/review pass before commit
