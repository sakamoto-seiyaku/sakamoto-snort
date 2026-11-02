# S61 ordered recognition query validation

Date: 2026-11-02. Fixed review baseline:
`6d0c6fc84c57218c8f54abfc5ac20512c9f5d12b`.
Scope: [SAKAMOTO-61](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/c7e0c179-b64c-47d3-99b7-e0dd05bf2842),
under S329. The current contract is [T28 recognition](../interfaces/T28_DASHBOARD_QUERY.md#s61-ordered-recognition-facts).
Formal UI and the old Activity channel retirement belong to later work.

The existing owner-local LPI state now records first mapped publication order,
its submitted-payload ordinal and Flow direction, plus actual ORIG/REPLY submit
counts. The normal observation and typed current query carry those same facts
through Rust and SQLite. Protocol masks, detectors, policy timing and budgets
retain their existing behavior. SDK ABI7, API CRC `58b40081`, Flow/transport v13,
maximum record1688 and all required consumers are synchronized.

Evidence paths below are relative to `build-output/s61-recognition-20261102/`.

| Layer | Actual result | Evidence |
| --- | --- | --- |
| Shared query and compatibility | Normal v13 decode, live projection, SQLite commit/close and saved query preserve ordered IDs/counts/directions. Detecting, identified while running, terminal unidentified and missing schema are distinct. Old v12 names and JSON without recognition remain readable; mixed old/new saved rows retain old names with recognition=null. Final focused query tests8/8 pass. | `rust-query-final.log`; `observation.rs` |
| Largest detail and retention | The synthetic maximum ABI fixture combines20 result entries, three valid253-byte hostnames, IPv6, full attribution and64-bit identities. The ordinary writer originally rejected its Baseline wrapper at4096 bytes. Compact triplet storage now commits, closes and reopens with the entire recognition and names equal in the product query. The row/database limits are unchanged. Recognition leaves with its owning expired detail and does not recount a late END. | `max-detail-capacity-qualified.log` (original row-capacity failure), `rust-query-final.log`, `rust-recognition-retention.log` |
| C facts and transport | Actual DNS/QUIC payloads publish QUIC before DNS despite the opposite catalog-bit order; repeated results deduplicate. HTTP/TLS proves ORIG/REPLY submission counts and first direction. Existing zero-payload, invalid identity, budgets, stop and same-slot reuse checks pass. Native1688-byte records fill the existing256-slot long ring and report full without blocking; descriptor/capacity accounting passes. | `c-tests.log`, `transport-build.log`, `transport-test.log`; `product_flow_lpi_test.c`, `product_observation_transport_test.c` |
| Required suites | CTest133/133 passed. The Java manifest-gate regression was then tested red/green at its existing runtime seam. Rust default/profile suite passed107 tests,7 explicitly ignored; final8 query tests cover use of serde's existing object/triplet reader. The affected detail-retention test also passes. | `c-tests.log`, `android-abi-red.log`, `android-abi-green.log`, `rust-profile-final.log`, `rust-query-final.log` |
| Product builds | Existing Host/Android Product caches, pinned VPP stages and toolchains were reused; no dependencies were installed. Final storage change rebuilt Rust and republished the same C/transport inputs. | `host-build.log`, `host-build-storage-final.log`, `android-native-storage-final.log`, `apk-build-storage-final.log`; `product-vpp-host/`, `android-stage/`, `apk/` |
| Real normal Root/VPN | Pixel USB28201JEGR0XPAJ, Root3043/VPN3044. Actual DTLS→STUN results remain[1020,1016] at submitted ordinals1/3. Twelve bidirectional exchanges stop at20 submissions, counted[10,10], without duplicate IDs or later retries. An opaque request followed by a real STUN reply first identifies on REPLY at ordinal2. Opaque traffic is detecting while running, then unidentified on actual END. HTTP control packets exceed the two submitted payloads, while the count remains[1,1] and the real target name is retained. Current and normal consumer facts agree. | `device-result.json`, per-case `*-result.json`, representative `*-live.json`/`*-observed.json` |
| END, identity and stopped history | Eight selected controlled Flows produced actual END under the existing30-second TCP_CLOSED/bidirectional UDP aging. Each exact generation/owner/slot/incarnation is retained. Reusing the expired UDP tuple creates a new identity with empty sequence and fresh counts. STOP does not manufacture its END. Root history survives VPN restart; stopped queries preserve SQLite bytes. Incidental observed ENDs remain independently identified. | `device-result.json`, `root-stopped.json`, `vpn-stopped.json`, `vpn-restart-history.json` |
| Final storage on device | Final APK Root3045/VPN3046 each ran a representative real DTLS→STUN Flow through current/normal observation, actual END, stop and saved query. The already captured object-encoded history seed remains unchanged in query meaning alongside newly compact-encoded rows. No C/complete name/budget matrix was replayed for this storage-only change. | `device-storage-final-result.json`, `final-seed-stopped.json`, `root-final-stopped.json`, `vpn-final-stopped.json` |
| Final Host saved query | Final Host independently reads all21 retained seed records and33 final records, including incidental ENDs. Recent, packets/bytes, DNS, application/rule/protocol windows match the device query and database bytes stay unchanged. The installed Host management/rule startup contract already passed in CTest. Host live packet capture remains unqualified without Adapter privileges. | `host-saved-result.json`, `host-seed-saved.json`, `host-final-saved.json`, `c-tests.log` |
| Device restoration | APK installed with-r and KernelSU grant confirmed; no uninstall or clear-data. Original rule and t27 directories moved aside then restored; original main JSON/SQLite/rules bytes unchanged. Task selectors/files removed. Final generation3046 is VPN/stopped, mayBeActive=false; service absent and diagnostic process released, without generation rollback. The original recovery baseline remains in S330 output. | `device-result.json`, `device-storage-final-result.json`, `device-operations.jsonl` |

## Resolved failures and limits

- First device startup was rejected before traffic because Java's Product ABI
  constant remained6 while native/manifest had advanced to7. Its stopped error
  also prevented the runner's initial cleanup predicate from recognizing safe
  restoration. Actual stopped state was checked, preserved directories restored,
  the Java consumer synchronized, and the manifest/compiled-Java contract tested
  red/green before retrying the same entry. First failure and recovery remain in
  `device-first-failure-result.json` / `device-run-first-failure.log`.
- The row-capacity failure was reproduced by the real SQLite writer, not inferred
  from query JSON size. Earlier fixture attempts had a missing attribution time
  and a failed temporary store's generation; their nonpassing logs remain
  `max-detail-capacity*.log`. The fixture now uses a unique temporary directory.
  No sequence truncation, row-budget increase or parallel store was introduced.
- The standalone transport test first treated external VPP headers as ordinary
  headers under-Werror. Using system includes corrected the build premise;
  `transport-build-first.log` retains the failure. Product warnings remain errors.

No in-scope product blocker remains. Device packet qualification, Host shared
semantics and synthetic capacity/clock tests have separate meanings. No new
long-duration, performance, N>1/backpressure or handover qualification is claimed.
Existing detail/aggregate/storage budgets, gap reporting and actual-END semantics
remain; there is no shutdown snapshot or permanent recognition timeline.
