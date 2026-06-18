## 1. Test Helper Foundation

- [x] 1.1 Add or refactor vNext-only helpers for RPC JSON assertions, bucket delta assertions, and per-case cleanup in `tests/integration/vnext-baseline.sh` or `tests/integration/lib.sh`
- [x] 1.2 Add a reusable DNS stream capture helper that waits for `notice.started`, filters by uid/domain token, captures `type=dns` and `notice.suppressed`, and stops the stream cleanly
- [x] 1.3 Add a reusable `dx-netd-inject` wrapper that builds/stages the injector when needed and reports missing adb/root/injector prerequisites as `BLOCKED(77)`
- [x] 1.4 Add state snapshot/restore helpers for device config, app config, device/app DomainPolicy, DomainRules, and DomainLists touched by Domain casebook tests
- [x] 1.5 Ensure every new helper uses vNext control paths only and does not call legacy text protocol commands

## 2. Domain Case 1-2 Surface And DomainSources

- [x] 2.1 Extend existing Domain surface checks with `DOMAINLISTS.IMPORT` unknown-list rejection and assert structured error plus hint
- [x] 2.2 Extend existing Domain surface checks with “delete rule still referenced by policy” rejection and assert conflict/error details
- [x] 2.3 Keep existing domainSources reset/gating/growth checks and add bucket-level assertions instead of only total growth
- [x] 2.4 Prove APP, DEVICE_WIDE, and FALLBACK buckets are covered by later Domain cases and expose their check ids in the output

## 3. Domain Case 3-4 DNS Inject And Suppression

- [x] 3.1 Implement Case 3 app custom allow/block DNS inject using unique domains, `tracked=1`, `domain.custom.enabled=1`, and app scope policy
- [x] 3.2 Assert Case 3 dns stream fields: `uid`, `userId`, `app`, `domain`, `domMask`, `appMask`, `blocked`, `policySource`, `useCustomList`, `scope`, and `getips`
- [x] 3.3 Assert Case 3 per-app `traffic.dns.allow/block` and `domainSources` `CUSTOM_WHITELIST.allow` / `CUSTOM_BLACKLIST.block` growth
- [x] 3.4 Implement Case 4 with `tracked=0`, unique injected DNS traffic, no matching `type=dns` event for this trigger, and a `notice.suppressed` frame
- [x] 3.5 Assert Case 4 suppressed notice includes DNS traffic snapshot and tracked hint, while per-app `traffic.dns.*` and `domainSources` still grow

## 4. Domain Case 5-7 Policy And List Semantics

- [x] 4.1 Implement Case 5 `domain.custom.enabled=1` vs `0` using a unique domain and app scope block policy
- [x] 4.2 Assert Case 5 enabled path returns `CUSTOM_BLACKLIST` blocked verdict and disabled path falls back to `MASK_FALLBACK`
- [x] 4.3 Implement Case 6 APP vs DEVICE_WIDE priority with three unique domains covering app-allow-over-device-block, app-block-over-device-allow, and device-block-only
- [x] 4.4 Assert Case 6 dns stream source/scope fields and per-app `traffic.dns` / `domainSources` bucket growth
- [x] 4.5 Implement Case 7 DomainLists enabled block, disabled block, and allow-over-block using unique list IDs and domains
- [x] 4.6 Assert Case 7 `MASK_FALLBACK`, `domMask`, `appMask`, `useCustomList=false`, verdict transitions, and per-app traffic/domainSources growth

## 5. Domain Case 8-9 Resolver And RuleIds

- [x] 5.1 Add Case 8 preflight that detects netd resolv hook readiness and reports `BLOCKED(77)` with `dev/dev-netd-resolv.sh status|prepare` guidance when inactive
- [x] 5.2 Implement Case 8 true resolver DNS e2e when hook is active, using a unique blocked domain and shell uid or selected target uid
- [x] 5.3 Assert Case 8 dns stream event, `blocked=true`, `getips=false`, per-app `traffic.dns.block`, and corresponding `domainSources` growth
- [x] 5.4 Implement Case 9 exact-domain allow rule and regex block rule, attach them through app scope `DOMAINPOLICY(ruleIds)`, and inject matching domains
- [x] 5.5 Assert Case 9 `CUSTOM_RULE_WHITE` and `CUSTOM_RULE_BLACK` dns stream fields plus `traffic.dns` and `domainSources` bucket growth
- [x] 5.6 Restore DomainRules and policies after Case 9, including failure-path cleanup

## 6. Documentation Alignment

- [x] 6.1 Update `docs/testing/DEVICE_SMOKE_CASEBOOK.md` Domain Case 1-9 “现有覆盖/缺口” sections with the new check ids and remaining caveats
- [x] 6.2 Update `docs/testing/DEVICE_TEST_COVERAGE_MATRIX.md` to show Domain casebook coverage in `dx-smoke-control`
- [x] 6.3 Confirm `docs/IMPLEMENTATION_ROADMAP.md` still lists follow-up Domain casebook work accurately, or mark this change as the planned completion artifact

## 7. Validation

- [x] 7.1 Run `bash -n tests/integration/vnext-baseline.sh`
- [x] 7.2 Run `ctest -N -R dx-smoke-control` from the configured device-test build tree and confirm no new `dx-smoke*` names were introduced
- [x] 7.3 Run `bash tests/integration/dx-smoke-control.sh` on a rooted device and confirm Domain Case 1-9 pass or report the documented `BLOCKED` precondition for Case 8
- [x] 7.4 Run `openspec validate complete-device-smoke-casebook-domain --strict`
