## 1. Optional Runner Foundation

- [x] 1.1 Add an opt-in other casebook runner or IP/diagnostics case without wiring it into the default `dx-smoke` chain
- [x] 1.2 Ensure the new path uses vNext control APIs only and does not call legacy text protocol commands
- [x] 1.3 Add stable check ids for Case 1 and Case 2, using a readable prefix such as `VNXOTH-01*` and `VNXOTH-02*`
- [x] 1.4 Reuse existing ADB/root/vNext/Tier‑1 preflight helpers and preserve `BLOCKED(77)` / explicit `SKIP(10)` semantics
- [x] 1.5 Ensure cleanup restores mutated daemon/app/list/ruleset state without masking assertion failures

## 2. perfmetrics.enabled Case

- [x] 2.1 Save the original `perfmetrics.enabled` value before the case and restore it in cleanup
- [x] 2.2 Set `perfmetrics.enabled=0`, reset `METRICS.GET(name=perf)` aggregates, trigger Tier‑1 payload traffic, and assert `nfq_total_us.samples==0`
- [x] 2.3 Set `perfmetrics.enabled=1`, reset perf aggregates, trigger Tier‑1 payload traffic, and assert `nfq_total_us.samples>=1`
- [x] 2.4 Set `perfmetrics.enabled=1` again without reset and assert `nfq_total_us.samples` does not decrease
- [x] 2.5 Send `perfmetrics.enabled=2` and assert the vNext request is rejected without changing the current valid value
- [x] 2.6 Keep `dns_decision_us` assertions optional and gated on an active netd resolver hook plus explicit DNS traffic

## 3. Domain Import Limits Case

- [x] 3.1 Confirm vNext `HELLO` before the case and capture advertised request-size limits for diagnostics output
- [x] 3.2 Create a disabled test-only domain list so import checks do not affect real verdict behavior
- [x] 3.3 Import a bounded under-limit domain set and assert success plus expected `domainsCount`
- [x] 3.4 Send an over-limit `DOMAINLISTS.IMPORT` payload and assert `INVALID_ARGUMENT`
- [x] 3.5 Assert the over-limit error contains `limits.maxImportDomains`, `limits.maxImportBytes`, and a chunking or size-reduction hint
- [x] 3.6 Assert daemon recovery by running `HELLO` successfully after the rejected import

## 4. IPRULES Limits Case

- [x] 4.1 Reset daemon state and select a valid test app uid before mutating IPRULES
- [x] 4.2 Apply an under-hard-limit ruleset that exceeds the recommended `rulesTotal` threshold and assert `IPRULES.PREFLIGHT` reports a warning
- [x] 4.3 Attempt an over-hard-limit ruleset and assert `IPRULES.APPLY` fails with `INVALID_ARGUMENT`
- [x] 4.4 Assert the apply error includes structured `error.preflight.violations` with a `rulesTotal` violation
- [x] 4.5 Assert the failed apply is all-or-nothing by inspecting the resulting ruleset or preflight summary
- [x] 4.6 Assert daemon recovery by running `HELLO` and `IPRULES.PREFLIGHT` successfully after the rejected apply

## 5. Documentation Alignment

- [x] 5.1 Update `docs/testing/DEVICE_SMOKE_CASEBOOK.md` `## 其他` Case 1–2 with final optional check ids and remaining caveats
- [x] 5.2 Update `docs/testing/DEVICE_TEST_COVERAGE_MATRIX.md` to show optional other casebook coverage without changing default smoke/diagnostics boundaries
- [x] 5.3 Update `docs/IMPLEMENTATION_ROADMAP.md` so `complete-device-smoke-casebook-other` reflects the implemented state
- [x] 5.4 If validation exposes a Snort daemon/product behavior error, record it in `docs/testing/DEVICE_SMOKE_SNORT_BUGS.md`; do not record test-script implementation errors there

## 6. Validation

- [x] 6.1 Run shell syntax checks for all new or modified shell scripts
- [x] 6.2 Run `ctest -N -R 'dx-smoke|dx-diagnostics|casebook|other'` from a configured build tree and confirm no new `dx-smoke*` names were introduced
- [x] 6.3 Run the optional other casebook path on a rooted device with `--skip-deploy` and confirm Case 1–2 pass or report documented `BLOCKED/SKIP` preconditions
- [x] 6.4 Run `bash tests/integration/dx-smoke.sh --skip-deploy` or the equivalent CTest smoke wrapper to confirm the default smoke chain remains unchanged
- [x] 6.5 Run `openspec validate complete-device-smoke-casebook-other --strict`
