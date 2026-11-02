# S331 target-name query validation

Date: 2026-11-02. Fixed review baseline:
`5b7db81a845d0d35eac28cc1fcf29118ce27d502`.
Scope: [SAKAMOTO-331](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/312c118b-c1c8-40d6-a507-ab4c11228780),
under S329. Contract: [T28 target details](../interfaces/T28_DASHBOARD_QUERY.md#s331-target-name-details).
This is data/query qualification; formal Activity UI and S61 recognition order/counts remain separate.

The existing C producers now feed bounded SNI, latest-valid HTTP/SOCKS target,
current target eligibility, and separately refused target/rule facts through normal
observation, Rust, SQLite and the shared current/history query. Names are snapshots
of an observation boundary, not a request log or evidence of remote delivery.
Old records lack these facts explicitly; DNS association use remains deferred.
SDK ABI6, API CRC `b6d2a67c`, transport/Flow v12 and maximum record1512 are synchronized.
Retention counts, storage budgets and aggregate dimensions are unchanged.

All evidence paths below are relative to `build-output/s331-target-names-20261102/`.

| Layer | Actual result | Evidence |
| --- | --- | --- |
| Shared query/storage | New v12 decode → SQLite commit/close → saved query; latest valid target with unavailable current eligibility; distinct denial/rule; old wire/JSON missing fields; largest names; restart counts and exact 64-bit rule identity. Final query tests 7/7 and named-detail expiry test1/1 pass. | `rust-query-final.log`, `rust-names-retention.log`; tests in `observation.rs` and `observation_retention.rs` |
| Required suites | CTest133 cases:108 initially passed,25 failed on socket/artifact prerequisites or the changed HTTP test stub; all25 passed after correcting those causes. Required Rust default suite passed106 tests,7 explicitly ignored, including release panic profile. Subsequent production change only narrows the rule JSON projection; final focused query/storage tests cover it, other valid results are reused. | `c-build.log`, `c-tests.log`, `c-tests-r2.log`, `rust-profile-passed-summary.txt` |
| Native transport | Actual maximum-size1512-byte records fill the existing long ring at256, then report full; short-ring accounting, oversize rejection and descriptor settlement pass. | `transport-build.log`, `transport-test.log`, `tests/host/product_observation_transport_test.c` |
| Product builds | Stable Host/Android Product caches reused. Final Rust-only projection rebuild left the C producer/wire unchanged; final APK assembled with the shared native stage. | `host-build-final.log`, `android-native-final.log`, `apk-build-final.log`; `product-vpp-host/`, `android-stage/`, `apk/sakamoto-runtime-debug.apk` |
| Actual Root/VPN names | Pixel USB28201JEGR0XPAJ, ordinary Root3039 and VPN3040. HTTP one-write pipeline: latest=`later.http.test`, denied=`blocked.http.test`, actual refusing rule/version. SOCKS5 target/port distinct from outer proxy. TLS/QUIC/DTLS real fixture names have sources1/2/3. Current and independently consumed normal observation agree. Root3038's already successful valid→no-Host case is reused. | `device-original-qualified.json`, per-case `*-live.json`, `*-observed.json`, `*-result.json` |
| Real END/history | Existing TCP_CLOSED and bidirectional UDP30-second aging produced11 named ENDs. Root stop read retained names/rules; VPN restart retained the earlier generation; VPN stop read retained all exact identities. Database bytes remained unchanged by saved reads. Same tuple's later incarnation has no inherited name. | `root-stopped.json`, `vpn-restart-history.json`, `vpn-stopped.json`, `device-original-qualified.json` |
| Final Rust projection on device | Final APK Root3041/VPN3042 normal requests expose rule identities as decimal strings and omit irrelevant packet/App fields. Normal observation agrees; stopped reads reopen the real3039/3040 SQLite facts and preserve old names. | `device-final-result.json`, `root-final-projection-live.json`, `vpn-final-projection-live.json`, `final-seed-stopped.json`, `final-vpn-stopped.json` |
| Host shared query | Final Host reads all11 real named ENDs and exact rule identities from device SQLite. Reopening final3042 SQLite matches device recent/traffic/DNS/application/rule/protocol views and leaves database bytes unchanged. Real Host management/rule startup/restart also passed the required installed-artifact contract. Host packet capture remains unqualified without Adapter privileges. | `host-result.json`, `host-final-device-history.json`, `host-final-reopen.json`, `c-tests-r2.log` |
| Device restoration | Installed with `-r`, KernelSU grant checked; original rule directory and t27 test directory moved aside and restored. Original rules, main JSON and SQLite bytes unchanged. Selector/task files removed; generation3042 stopped, active service absent and cached diagnostic runtime process released. No generation rollback. | `device-final-result.json`, `device-operations.jsonl`; original recovery baseline remains in S330 output |

The normal UDP and TCP aging was actually observed; this does not qualify long
retention durations or performance. STOP still does not manufacture END, and the
existing observation loss/coverage semantics remain visible. Name fields leave
with their owning detail; there is no new permanent request history or domain aggregate.

## Failures and resolved premises

- API generation needed existing system `ply`: use
  `PYTHONPATH=/usr/lib/python3/dist-packages` (Android's
  `SAKAMOTO_VPP_PYTHONPATH`). No dependency was installed. Initial ABI consumer
  and HTTP test-stub synchronization misses were corrected. See
  `build-first-failures.txt` and initial suite logs.
- Initial Rust attempts used the wrong library directory, then ran the fixture
  lifecycle harness against real VAPI; those are not passing results. The normal
  default Rust suite passed through the required profile contract. Socket-restricted
  first runs remain in `rust-full*.log` / `rust-lifecycle-r3.log`.
- Device attempts1/2 stopped before traffic: lockscreen prevented the button;
  then optimistic revision conflict proved the editor needed its existing normal
  Query-all step. No rejected apply changed rules; original state was restored.
- Attempt3 already proved Root3038 names/current-ineligibility through normal
  query. Its15-second END wait was invalid: actual RST means TIME_WAIT and the
  pinned TCP_CLOSED timeout is30 seconds. Unified diagnosis checked tracker,
  expiry, normal observations and persistence before continuing; no product
  timeout or STOP behavior changed, and the successful request was not replayed.
- Attempt4 completed names, actual END and saved queries, then a tuple-only
  uniqueness assertion encountered a later incarnation on the same port. Full
  generation/owner/slot/incarnation checks over the saved evidence pass; the later
  record correctly has no old name. No device operation was replayed to correct
  that assertion. Original failure remains `device-fourth-failure-result.json`;
  corrected qualification is `device-original-qualified.json`.

No unresolved S331 product blocker remains. Independent review reports and the
exact reviewed candidate/final commits are referenced by the task handoff.
