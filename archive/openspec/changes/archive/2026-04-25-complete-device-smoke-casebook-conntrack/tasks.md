## 1. Smoke Case Foundation

- [x] 1.1 Add stable conntrack smoke check ids to `tests/device/ip/cases/22_conntrack_ct.sh` for allow baseline, allow payload, allow stats, allow metrics, block verdict, block reasons, block stats, and block metrics
- [x] 1.2 Add or reuse helpers for `METRICS.GET(name=conntrack)` field assertions: `totalEntries`, `creates`, `expiredRetires`, and `overflowDrops` must be numeric
- [x] 1.3 Add or reuse helpers for `IPRULES.PRINT` rule stats lookup by numeric `ruleId`, including readable failure output with the full printed rules snapshot
- [x] 1.4 Ensure cleanup tears down Tier‑1 topology and restores daemon baseline after failures without masking assertion failures

## 2. Conntrack Allow Path

- [x] 2.1 Reset daemon state with `RESETALL` before the allow phase and assert initial conntrack metrics are `totalEntries==0` and `creates==0`
- [x] 2.2 Apply paired allow rules for `ct.state=new,ct.direction=orig,dir=out` and `ct.state=established,ct.direction=reply,dir=in`
- [x] 2.3 Assert `IPRULES.PREFLIGHT` or equivalent apply/print evidence shows conntrack consumers are active for the target uid
- [x] 2.4 Trigger Tier‑1 TCP payload read with `IPTEST_CT_BYTES` and assert the client reads exactly that byte count
- [x] 2.5 Assert both allow rules report `stats.hitPackets>=1`, and keep byte assertions best-effort unless they are deterministic enough for smoke
- [x] 2.6 Assert post-allow `METRICS.GET(name=conntrack)` reports `creates>=1` and `totalEntries>=1`

## 3. Conntrack Block Path

- [x] 3.1 Reset daemon state with `RESETALL` before the block phase and assert conntrack metrics return to `totalEntries==0` and `creates==0`
- [x] 3.2 Apply a matching enforce block rule for `ct.state=new,ct.direction=orig,dir=out`
- [x] 3.3 Trigger the same Tier‑1 TCP payload path and assert the client reads `0` bytes or observes the scripted expected connection failure
- [x] 3.4 Assert `METRICS.GET(name=reasons)` reports `IP_RULE_BLOCK.packets>=1`
- [x] 3.5 Assert the block rule reports `stats.hitPackets>=1`
- [x] 3.6 Assert post-block `METRICS.GET(name=conntrack)` still reports `creates==0` and `totalEntries==0`

## 4. Profile And Documentation Alignment

- [x] 4.1 Add the conntrack case to `tests/device/ip/run.sh --profile smoke` while keeping it available in `--profile matrix`
- [x] 4.2 Keep `dx-smoke-datapath` using the existing smoke profile path; do not add new `dx-smoke*` or profile names
- [x] 4.3 Update `docs/testing/DEVICE_SMOKE_CASEBOOK.md` `## IP - Conntrack` Case 1 with final smoke check ids and remove stale “not in smoke profile” gap notes
- [x] 4.4 Update `docs/testing/DEVICE_TEST_COVERAGE_MATRIX.md` to show minimal conntrack casebook coverage under `dx-smoke-datapath`
- [x] 4.5 Update `docs/IMPLEMENTATION_ROADMAP.md` so `complete-device-smoke-casebook-conntrack` reflects the current implementation state
- [x] 4.6 If validation exposes a Snort daemon/product behavior error, record it in `docs/testing/DEVICE_SMOKE_SNORT_BUGS.md`; do not record test-script implementation errors there

## 5. Validation

- [x] 5.1 Run `bash -n tests/device/ip/run.sh tests/device/ip/cases/22_conntrack_ct.sh`
- [x] 5.2 Run `ctest -N -R dx-smoke-datapath` from a configured CMake build tree and confirm no new `dx-smoke*` names were introduced
- [x] 5.3 Run `bash tests/device/ip/run.sh --profile smoke --skip-deploy` on a rooted device and confirm IP Case 1–8 plus conntrack Case 1 pass or report documented `BLOCKED/SKIP` preconditions
- [x] 5.4 Run `bash tests/integration/dx-smoke-datapath.sh --skip-deploy` on a rooted device to verify the wrapper path
- [x] 5.5 Run `openspec validate complete-device-smoke-casebook-conntrack --strict`
