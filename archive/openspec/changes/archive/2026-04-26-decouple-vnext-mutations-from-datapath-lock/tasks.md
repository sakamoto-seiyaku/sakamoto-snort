## 1. Tests First

- [x] 1.1 Add a host regression test that holds `mutexListeners` exclusively, sends a vNext mutation such as `CONFIG.SET` or `METRICS.RESET`, and asserts the command responds before the lock is released.
- [x] 1.2 Add a host regression test for at least one representative large mutation path (`DOMAINLISTS.IMPORT` or `IPRULES.APPLY`) proving dispatch does not require the outer datapath lock.
- [x] 1.3 Add or update a reset concurrency test showing `RESETALL` waits for an in-flight control mutation boundary before clearing runtime state.

## 2. Runtime Locking

- [x] 2.1 Add a process-level control mutation mutex in the shared runtime globals near `mutexListeners`.
- [x] 2.2 Update `snortResetAll()` to acquire locks in the documented order: save/reset coordinator, control mutation mutex, then `mutexListeners` exclusive.
- [x] 2.3 Update vNext session dispatch so mutation commands acquire only the control mutation mutex and do not take `mutexListeners` around the whole handler.
- [x] 2.4 Keep `RESETALL` dispatch outside the normal mutation branch and let `snortResetAll()` own the full reset lock order.
- [x] 2.5 Keep read-only commands on their current safe path unless a specific test requires a narrower lock.

## 3. Manager Atomicity Audit

- [x] 3.1 Audit `DOMAINLISTS.IMPORT` after removing the outer lock; rely on `DomainList` local import/publish locks unless a concrete intermediate-state issue is found.
- [x] 3.2 Audit `IPRULES.APPLY` after removing the outer lock; rely on `IpRulesEngine` local lock and atomic hot snapshot publish for datapath safety.
- [x] 3.3 Audit `DOMAINRULES.APPLY`, `DOMAINPOLICY.APPLY`, and `DOMAINLISTS.APPLY` for multi-step intermediate-state exposure; add narrow manager-local batch APIs only if needed.
- [x] 3.4 Confirm `CONFIG.SET` and `METRICS.RESET` do not perform long work under `mutexListeners` and remain serialized with other vNext mutations.

## 4. Documentation

- [x] 4.1 Update `docs/reviews/CURRENT_HEAD_CPP_CONCURRENCY_REVIEW.md` to mark the vNext mutation lock finding as fixed and describe the actual lock split.
- [x] 4.2 Update `docs/decisions/RESETALL_RUNTIME_CONCURRENCY.md` to document control mutation serialization and the reset lock order.
- [x] 4.3 Update `docs/IMPLEMENTATION_ROADMAP.md` if this fix changes the current concurrency/stability status summary.

## 5. Verification

- [x] 5.1 Run `git diff --check`.
- [x] 5.2 Run `cmake --build --preset dev-debug --target snort-build`.
- [x] 5.3 Run `cmake --build --preset dev-debug --target snort-host-tests`.
- [x] 5.4 Run `cmake --build --preset dev-debug --target snort-host-tests-asan`.
- [x] 5.5 Record follow-up device verification guidance: concurrent large `DOMAINLISTS.IMPORT` / `IPRULES.APPLY` with datapath perf, checking `nfq_total_us` tail latency does not spike due to `mutexListeners`.
