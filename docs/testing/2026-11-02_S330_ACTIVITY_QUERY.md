# S330 activity query validation

Date: 2026-11-02. Review baseline: `f76c74149d2a5910316b652d9bb6f1abc5b716b6`.
Scope: [SAKAMOTO-330](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/fef2bdb0-9d1c-4a02-a8c2-da6aa49ba171),
under S329. Contract: [T28 shared query](../interfaces/T28_DASHBOARD_QUERY.md).

The normal Android observation action and its Query history / Query health
buttons can read committed history without a Product Core session. The shared
Rust saved branch is also available through the Host `saved-history` command and
an additive C/JNI entry. It opens SQLite read-only, does not migrate legacy JSON,
does not recover an interrupted session, and does not connect to or start VPP.
Running queries retain the existing in-memory, including-pending semantics.

The existing bounded recent Flow/Blocked and DNS views, aggregate windows,
coverage, storage and truncation fields retain their meanings. Current Flow
sampling remains separate. Target names, recognition order and actual recognition
payload counts are explicitly unavailable pending S331/S61. There is no new
policy, capture mode, UI product page or old-Activity retirement in this change.

## Actual validation

All output paths below are under `build-output/s330-activity-20261102/`.

| Layer | Actual result and qualification | Evidence |
| --- | --- | --- |
| Rust default test seam | Full `cargo test -p sakamoto-product-core --all-targets`: 104 passed, 7 explicitly ignored, no failures; rerun outside socket-restricting sandbox. Existing observation, pending/committed state, bounded retention, SQLite and lifecycle tests included. | `rust-current.log` |
| Shared saved-query seam | Final 4/4 tests pass: committed Flow/Blocked/DNS and statistics; generation/incarnation separation after restart; missing/empty/busy/corrupt history; legacy JSON without migration; interrupted coverage without recovery; repeated read leaves database bytes unchanged. | `rust-saved-final-r4.log`, `crates/product-core/src/observation.rs` |
| Product builds | Host and Android builders reused Product persistent caches. Android native stage and APK assembled from the changed Rust/JNI/Java. No VPP packet source changed. Subsequent changes only extend tests and documentation. | `host-build-current.log`, `android-native-current.log`, `apk-build-current.log` |
| Old device data | New APK installed with `-r`; while stopped, normal DebugControlActivity query returned old history and totals `[54313070,28002914]`, recent count 125, existing gaps 24864 and incomplete coverage. Original JSON and SQLite bytes remained unchanged. | `before-original-saved.json`, `device-recovery/` |
| Real Root | Pixel 6a, app KernelSU grant verified, normal `runtimeStart` / `runtimeStop`, NFQUEUE protection active. Generations 3032→3033. Real shell-UID UDP DNS query to 1.1.1.1 received a DNS answer; shared query exposed DNS stages 1/2, current UDP Flow identity/counters and statistics. Stopped reads retained DNS/statistics and pre-existing END history, did not change generation or database bytes. | `root-live-initial.json`, `root-1-live.json`, `root-1-stopped.json`, `device-result.json` |
| Real VPN | Same Pixel, ordinary VPN TUN/protect entry, generations 3034→3035. Each generation received a real DNS answer and exposed current UDP Flow and DNS stages 1/2. Restart retained old DNS generations and statistics; current identities remained generation-local. Both stopped reads preserved database bytes and protection stayed stopped. | `vpn-1-live.json`, `vpn-2-live.json`, `vpn-2-stopped.json`, `device-result.json` |
| Debug button | Real Query history button after stop rendered `saved_committed`, packets `[191,38]`, recent 2 and DNS 31. | `ui-history.xml`, `ui-history.txt`, `ui-history.png` |
| Shared Host read | Host Rust saved-history read the real device SQLite and matched device packets/bytes, recent Flow, DNS and application/protocol/rule windows. Original copied history also reopened unchanged. Real VPP management generations 33001/33002 returned current management identity; with no Adapter, current Flow/consumer were explicitly unavailable. Saved queries worked during management and after its stop without changing SQLite. | `host-result.json`, `host-device-history.json`, `host-33001-live.json`, `host-33002-stopped.json` |
| Device restoration | Original main JSON/SQLite bytes unchanged; prior t27 test directory restored; selector and task fixture removed; service process absent; final VPN generation 3035 stopped. Rules were not replaced. | `device-restoration.json`, `device-final-state.properties` |

Host packet capture and a live Host observation consumer are **not qualified** by
this run: this environment requires a sudo password, and VPP intentionally does
not allocate Adapter-owned Flow pools/observation endpoints without an Adapter.
Real Root/VPN packet-path coverage above is independent. No performance or
long-duration retention qualification is added.

## Failures and resolved premises

- Existing earlier `rust-tests.log` contains a sandbox UDS permission failure and
  is not a passing result. `rust-current.log` is the successful authorized rerun.
- An initial device assertion required every active UDP Flow to appear as an
  ended recent record immediately on STOP. The existing contract only records
  actual END there; shutdown does not manufacture END. SQLite confirmed the
  received baseline and totals persisted, while DNS, statistics and prior END
  history were readable. The existing shutdown coverage gap remained visible.
  Original failure is in `device-first-failure.log` and
  `device-first-failure-result.json`; successful Root operations were reused.
- Host startup premises were corrected together: the initial nested runtime path
  exceeded the Unix socket limit; after shortening it, waiting for an observation
  endpoint without an Adapter was invalid. Original logs are
  `host-current.log` / `host-current-r2.log`; `host-result.json` retains both
  causes and the final scoped result. No product startup behavior was changed.
- UI automation initially used the wrong existing content-description and tapped
  a partly clipped button. Correcting those selectors made the same button pass;
  no product change was needed. Device cleanup's `pidof` no-process exit code was
  likewise a runner premise, and already completed restore actions were not replayed.
- Added mixed-history test inputs initially omitted valid Blocked END metadata;
  later comparison incorrectly equated raw-store and annotated public-query
  interpretations. The validators and annotation contract were inspected together;
  only the fixture and assertions changed. Final saved-query tests preserve the
  factual identity/counters and require unavailable stopped rule conditions.

No unresolved S330 product blocker remains. Bounded history is not a complete
snapshot of every Flow active at STOP. The accepted loss/gap semantics and
existing retention/capacity limits are unchanged.
