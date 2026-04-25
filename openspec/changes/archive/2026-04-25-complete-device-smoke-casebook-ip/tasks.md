## 1. Helper And Surface Foundation

- [x] 1.1 Strengthen `tests/device/ip/cases/14_iprules_vnext_smoke.sh` so `VNX-05` also asserts `IPRULES.PRINT` `stats.hitPackets`, `stats.hitBytes`, `stats.wouldHitPackets`, and `stats.wouldHitBytes` exist and are numeric
- [x] 1.2 Add reusable helpers in `tests/device/ip/cases/16_iprules_vnext_datapath_smoke.sh` or `tests/device/ip/lib.sh` for TCP success/failure probes that preserve the real exit status instead of hiding it behind `|| true`
- [x] 1.3 Add reusable helpers for `METRICS.RESET/GET(name=traffic, app)`, `METRICS.RESET/GET(name=reasons)`, traffic bucket assertions, and reason bucket assertions
- [x] 1.4 Add reusable helpers for `IPRULES.PRINT` rule stats lookup and before/after comparisons by numeric `ruleId`
- [x] 1.5 Add or refactor a pkt stream capture helper that waits for `notice.started`, filters by uid, peer IP, direction, port, `reasonId`, `ruleId`/`wouldRuleId`, and returns `BLOCKED(77)` only for stream/control setup failure
- [x] 1.6 Ensure cleanup restores app `tracked`, app `block.ifaceKindMask`, device `block.enabled`, device `iprules.enabled`, and Tier‑1 topology state after failures

## 2. Existing Verdict Cases

- [x] 2.1 Update IP Case 2 allow flow to reset reasons/traffic, apply the allow rule, assert TCP connect succeeds, assert pkt stream `IP_RULE_ALLOW + ruleId`, assert `reasons.IP_RULE_ALLOW.packets>=1`, assert `traffic.txp.allow>=1`, and assert rule `hitPackets>=1`
- [x] 2.2 Update IP Case 3 block flow to reset reasons/traffic, apply the block rule, assert TCP connect fails, assert pkt stream `IP_RULE_BLOCK + ruleId`, assert `reasons.IP_RULE_BLOCK.packets>=1`, assert `traffic.txp.block>=1`, and assert rule `hitPackets>=1`
- [x] 2.3 Update IP Case 4 would-match flow to reset reasons/traffic, apply `action=block,enforce=0,log=1`, assert TCP connect succeeds, assert pkt stream `ALLOW_DEFAULT + wouldRuleId + wouldDrop`, assert `reasons.ALLOW_DEFAULT.packets>=1`, assert `traffic.txp.allow>=1`, and assert rule `wouldHitPackets>=1`
- [x] 2.4 Update IP Case 5 IFACE_BLOCK flow to reset reasons/traffic, configure the matching iface kind mask, assert TCP connect fails, assert pkt stream `IFACE_BLOCK` without `ruleId/wouldRuleId`, assert `reasons.IFACE_BLOCK.packets>=1`, assert `traffic.txp.block>=1`, and assert shadowed rule stats do not increase

## 3. Gate Correctness Cases

- [x] 3.1 Extend IP Case 6 `block.enabled=0` to reset reasons and per-app traffic before the trigger, assert reasons total stays zero, assert per-app traffic total stays zero, and assert no matching pkt stream verdict event is emitted
- [x] 3.2 Add IP Case 7 `iprules.enabled=0` by installing a matching block rule, recording its stats, setting `iprules.enabled=0`, resetting reasons/traffic, triggering Tier‑1 TCP, and asserting TCP connect succeeds
- [x] 3.3 Complete IP Case 7 assertions: pkt stream reports `ALLOW_DEFAULT` without `ruleId/wouldRuleId`, `reasons.ALLOW_DEFAULT.packets>=1`, `traffic.txp.allow>=1`, and the installed rule's `hitPackets/wouldHitPackets` do not increase
- [x] 3.4 Restore `iprules.enabled=1` after Case 7 and ensure subsequent smoke cases cannot inherit the disabled state

## 4. Payload Bytes Case

- [x] 4.1 Add IP Case 8 payload flow using the existing Tier‑1 TCP zero server and `iptest_tier1_tcp_count_bytes 443 65536 2000` or an equivalent helper
- [x] 4.2 Install paired allow rules for payload coverage: outbound client traffic to `dst=peer/32,dport=443` and inbound server traffic from `src=peer/32,sport=443`
- [x] 4.3 Reset reasons/traffic before the payload trigger and assert the client-observed byte count equals `65536`
- [x] 4.4 Assert payload metrics: `reasons.IP_RULE_ALLOW.packets>=1`, `reasons.IP_RULE_ALLOW.bytes>=65536`, `traffic.rxp.allow>=1`, `traffic.rxb.allow>=65536`, and `traffic.txp.allow>=1`
- [x] 4.5 Assert payload rule stats: inbound allow rule `hitPackets>=1` and `hitBytes>=65536`; outbound allow rule `hitPackets>=1`
- [x] 4.6 Optionally assert pkt stream sees both inbound and outbound `IP_RULE_ALLOW` events when this can be made deterministic without increasing flake

## 5. Documentation Alignment

- [x] 5.1 Update `docs/testing/DEVICE_SMOKE_CASEBOOK.md` `## IP` Case 1–8 “现有覆盖/缺口” sections with the final check ids and remove stale completed gaps
- [x] 5.2 Keep `docs/testing/DEVICE_SMOKE_CASEBOOK.md` `## IP - Conntrack` unchanged except for any cross-reference that clarifies it remains a separate follow-up
- [x] 5.3 Update `docs/testing/DEVICE_TEST_COVERAGE_MATRIX.md` so `dx-smoke-datapath` describes IP Case 1–8 coverage, including `iprules.enabled=0` and payload bytes coverage
- [x] 5.4 Confirm `docs/IMPLEMENTATION_ROADMAP.md` still represents the IP casebook follow-up accurately, or update only the relevant roadmap note

## 6. Validation

- [x] 6.1 Run `bash -n tests/device/ip/cases/14_iprules_vnext_smoke.sh tests/device/ip/cases/16_iprules_vnext_datapath_smoke.sh`
- [x] 6.2 Run `ctest -N -R dx-smoke-datapath` from a configured CMake build tree and confirm no new `dx-smoke*` names were introduced
- [x] 6.3 Run `bash tests/device/ip/run.sh --profile smoke --skip-deploy` on a rooted device and confirm IP Case 1–8 pass or report documented `BLOCKED/SKIP` preconditions
- [x] 6.4 Run `bash tests/integration/dx-smoke-datapath.sh --skip-deploy` on a rooted device to verify the wrapper path
- [x] 6.5 If validation or device testing exposes a Snort daemon/product behavior error, record it in `docs/testing/DEVICE_SMOKE_SNORT_BUGS.md` with command, environment, expected result, actual result, and key logs; do not record test-script implementation errors there
- [x] 6.6 Run `openspec validate complete-device-smoke-casebook-ip --strict`
