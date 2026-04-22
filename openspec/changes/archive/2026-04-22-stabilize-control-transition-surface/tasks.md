## 1. Freeze legacy knobs in `Settings`

- [x] 1.1 Define frozen semantics for `BLOCKIPLEAKS/GETBLACKIPS/MAXAGEIP` (`0/0/14400`)
- [x] 1.2 Make `Settings::{blockIPLeaks,getBlackIPs,maxAgeIP}` setters enforce frozen values (ignore inputs)
- [x] 1.3 Make `Settings::save/restore` write and force frozen values (ignore persisted non-frozen values)
- [x] 1.4 Add a host-test save file override for `Settings` (so gtests can verify restore semantics)

## 2. Host P0 tests for frozen/no-op + restore

- [x] 2.1 Add gtest: legacy knobs remain fixed after setter calls (no-op semantics)
- [x] 2.2 Add gtest: restoring from a settings file with non-frozen values still results in frozen values

## 3. Legacy `HELP` + docs update

- [x] 3.1 Update legacy `HELP` output to mark `BLOCKIPLEAKS/GETBLACKIPS/MAXAGEIP` as frozen/no-op and point to vNext (`sucre-snort-ctl`, `sucre-snort-control-vnext`/`60607`)
- [x] 3.2 Update `docs/INTERFACE_SPECIFICATION.md` to document frozen/no-op semantics (remove “可调能力”表述)
- [x] 3.3 Update `docs/testing/ip/IP_TEST_MODULE.md` to reflect frozen semantics (and avoid treating ip-leak as a tunable)

## 4. Scripts/tests transition lanes (legacy vs vNext)

- [x] 4.1 Update `tests/integration/run.sh` to assert fixed/no-op semantics (replace roundtrip toggle checks)
- [x] 4.2 Update `tests/integration/full-smoke.sh` to assert fixed/no-op semantics for `GETBLACKIPS/BLOCKIPLEAKS/MAXAGEIP`
- [x] 4.3 Update `tests/integration/iprules.sh` to avoid relying on ip-leak functional behavior (convert to frozen assertions; keep IPRULES coverage)
- [x] 4.4 Update `tests/device-modules/ip/cases/30_ip_leak.sh` to validate frozen/no-op semantics (no longer require observing `IP_LEAK_BLOCK`)
