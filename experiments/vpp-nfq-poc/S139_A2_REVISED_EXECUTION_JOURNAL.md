# SAKAMOTO-139 A2 revised execution journal

Date: 2026-08-23 (Asia/Taipei)  
Updated: 2026-08-26 (S156-guarded A2-2 revalidation, S187/S191 A2-3 current refresh, S188 A2-4 overlay/runtime closure, S189 A2-5 admission closure, S190 A2-6 replay closure, and final S156 aggregate)
Plane: SAKAMOTO-139  
Design: [S139_A2_POC_DESIGN_REVISION.md](S139_A2_POC_DESIGN_REVISION.md)  
Device: Pixel 6a / arm64 / serial `28201JEGR0XPAJ`  
Aggregate: historical 2026-08-23 `PASS`; current S156-era aggregate `PASS`;
`architecture_interruption=false`

## Why the repeated UID verification was a POC problem

The repeated stop at "verify UID" was not one repeated UID resolver failure.
Earlier evidence already contained exact real-App tuples with the expected UID,
including asynchronous `uid=-1 -> uid=12629` resolution and a later cache hit.
Three POC concerns had instead been collapsed into one gate:

1. session provenance depended on an empty, volatile logcat capture even when
   durable package, allow-scope, and resolver evidence existed;
2. a legitimate asynchronous first miss (`uid=-1`) was classified as a wrong
   UID instead of waiting for its completion or same-tuple retry;
3. the runner did not prove that native VPP owner-resolver mode had started, so
   a missing plugin caused the VPN to disappear before a tuple could exist and
   surfaced downstream as "UID evidence missing."

The 2026-08-23 reproduction established the third failure precisely. Android
registered a VPN network with handle `4087919595533` and the expected UID
range, then removed `tun0` immediately after native start returned `rc=-3`.
There was no Java crash, fatal exception, or tombstone. The installed APK
contained `libvpnfdprobe.so` and the VPP runtime but omitted
`tun_poc_plugin.so`; owner-resolver mode requires that plugin. In native code,
`rc=-3` is the `write_vpp_files()` failure path. The observed active Wi-Fi
network and absent VPP tuple were consequences of failed native startup, not
evidence against Android UID attribution.

This is a POC fixture, provenance, and verdict-design defect. It does not
require blocking FlowOwner, adding UID to the canonical flow key, reviving
stale identity, or bypassing the protected transport boundary.

## Design and harness correction

The revised POC separates seven independently decidable cells (A2-0 through
A2-6) and uses `PASS`, `FAIL`, `INVALID`, and `INCONCLUSIVE` per cell.
`A2_INCOMPLETE` is only the aggregate state while any required cell is not
`PASS`.

For A2-0 specifically:

- allowed-package provenance is a six-way durable join: package snapshot,
  package-to-UID mapping, VpnService builder receipt, allowed UID scope,
  runtime UID plus VPN handle, and the exact VPN-source tuple in VPP;
- logcat is diagnostic only;
- owner-resolver native start is an instrumentation gate requiring
  `vppMode=5`, `rc=0`, artifact name, and artifact SHA-256;
- the installed APK hash must match the locally built APK, and the runtime
  extracted plugin hash must match the plugin embedded in that APK;
- missing plugin, failed native start, stale receipt, or APK/plugin mismatch is
  `INVALID`, not an inconclusive UID result;
- the runner repeats the same canonical UDP tuple so the normal asynchronous
  miss can complete and the repeat can observe the resolved UID.

The build takes the plugin explicitly through `VPP_TUN_POC_PLUGIN` and stages
it into the APK without changing the shared product stage. A durable
`vpp-start-provenance.json` receipt records the startup result and artifact.
The verifier independently recomputes configuration and artifact joins. Its
regression suite also asserts that initial `uid=-1` is a valid miss, while a
wrong nonnegative UID is a behavioral failure.

Clean implementation checkpoints:

- `95a0790` -- durable A2 session provenance;
- `f219eb9` -- native VPP start gate and explicit plugin packaging;
- `3a6faa7` -- same-tuple retry after asynchronous completion;
- `6d776a3` -- runtime plugin and installed-APK provenance binding.

## A2-0 execution result

Cell: `A2-0 session provenance`  
Verdict: `PASS`  
Raw bundle:
`results/s139-a2-0-session-provenance-20260823-fixed-1/`  
Machine verdict:
`results/s139-a2-0-session-provenance-20260823-fixed-1/result.json`

The device APK was built with an isolated copy of the pinned VPP source plus
only the repository `tun_poc` overlay. The pinned source snapshot and shared
product stage were not modified.

| Join or gate | Decisive evidence |
| --- | --- |
| Installed APK | Local and installed SHA-256 `d676b6e85cadb9aa2e100483256885475504a4734f737b3d3401262a9a9eb1f2` |
| Native start | `vppMode=5`, `rc=0`, artifact `libtun_poc_plugin.so` |
| Plugin binding | Embedded and runtime SHA-256 `fd3ceb866678f8eddd3517563ca921142d4caf45658d40d047cecd8de3539ad4` |
| Package identity | VpnLite UID 12628; allowed androidruntime UID 12629 |
| VPN builder | Durable successful allowed-package/configuration receipt and independently matched digest |
| Allowed scope | Durable `ALLOWED_UID_SCOPE uids=[12629]` |
| Runtime session | UID 12629, `bindResult=bound`, VPN handle `4096509530125`, `udp_datagram_sent` |
| Exact VPP tuple | IPv4 UDP `10.111.0.2:45630 -> 1.1.1.1:53` |
| UID resolver | Same tuple progressed `uid=-1 -> uid=12629` |
| Cleanup | No VPP/VpnLite process and no `tun0`; independent root check clean |

All registered A2-0 checks passed. No failure receipt was present, the Git
source provenance was clean at `6d776a3`, and the runner left no native or TUN
residue.

## A2-1 execution result

Cell: `A2-1 two-App dual-stack matrix`  
Final verdict: `PASS`  
Invalid fixture bundle:
`results/s139-a2-1-two-app-matrix-20260823-1/`  
Passing bundle:
`results/s139-a2-1-two-app-matrix-20260823-fixed-1/`  
Machine verdict:
`results/s139-a2-1-two-app-matrix-20260823-fixed-1/result.json`

The final matrix no longer uses Chrome or Maps as ambient traffic sources.
Two APKs built from one POC-only traffic-adapter implementation use distinct
application IDs and therefore distinct Android UIDs. Each adapter records its
package/process UID, exact fixed tuple, explicit VPN socket bind, VPN network
handle, actual local address, attempt outcome, repeat index, and monotonic
time. TCP connect and Internet reply are not acceptance criteria.

The first deterministic run was `INVALID`, not a UID behavioral failure.
AppA and AppB were installed as UIDs 12630 and 12631, but VpnLite's manifest
package-visibility queries did not name the two new packages. PackageManager
therefore raised `NameNotFoundException` before native start; the durable
session/start receipts, allowed UID scope, and VPP logs were empty, and every
adapter correctly recorded `bind_result=unavailable`, handle `-1`, and no
tuple attempt. Cleanup was clean. The POC correction added only these two
explicit package queries, rebuilt the same VpnLite fixture with the bound
`tun_poc` plugin, and retained the invalid raw bundle.

Clean implementation/correction checkpoints:

- `2ffd402` -- shared deterministic adapter packaged as two application IDs;
- `5373cd1` -- eight-tuple runner and A2-1 verifier profile;
- `b829438` -- explicit VpnLite visibility for the two POC packages.

The fixed run passed every registered check:

| App/family/protocol | Exact tuple | Resolver result |
| --- | --- | --- |
| AppA / IPv4 / TCP | `10.111.0.2:45641 -> 1.1.1.1:443` | `uid=-1 -> uid=12630` |
| AppA / IPv4 / UDP | `10.111.0.2:45642 -> 1.1.1.1:53` | `uid=-1 -> uid=12630` |
| AppA / IPv6 / TCP | `fd00:111:111::2:45643 -> 2606:4700:4700::1111:443` | `uid=-1 -> uid=12630` |
| AppA / IPv6 / UDP | `fd00:111:111::2:45644 -> 2606:4700:4700::1111:53` | `uid=-1 -> uid=12630` |
| AppB / IPv4 / TCP | `10.111.0.2:45651 -> 1.1.1.1:443` | `uid=-1 -> uid=12631` |
| AppB / IPv4 / UDP | `10.111.0.2:45652 -> 1.1.1.1:53` | `uid=-1 -> uid=12631` |
| AppB / IPv6 / TCP | `fd00:111:111::2:45653 -> 2606:4700:4700::1111:443` | `uid=-1 -> uid=12631` |
| AppB / IPv6 / UDP | `fd00:111:111::2:45654 -> 2606:4700:4700::1111:53` | `uid=-1 -> uid=12631` |

All 16 adapter operation records used VPN handle `4100804497421`. The VpnLite
builder/config receipt resolved and established both packages, the durable
scope was `[12630, 12631]`, and native start recorded `vppMode=5`, `rc=0`, and
plugin SHA-256
`fd3ceb866678f8eddd3517563ca921142d4caf45658d40d047cecd8de3539ad4`.
The local and installed VpnLite and traffic APK hashes matched. Post-run and
independent root checks found no VPP/VpnLite process and no `tun0`; Git was
clean at `b829438`.

This proves the complete deterministic A2-1 tuple/UID matrix at the VPN/VPP
owner-resolver boundary. It does not prove external TCP completion, UDP reply,
Internet reachability, concurrency/cache bounds, reverse traffic, lifecycle
invalidation, or downstream socket admission.

## A2-2 execution and fixture correction

Cell: `A2-2 async cache/concurrency/bounds`  
Current verdict: `PASS`  
Aggregate remains: `A2_INCOMPLETE`; `architecture_interruption=false`

The first A2-2 attempt retained raw evidence at
`results/s139-a2-2-cache-concurrency-20260823-1/` and was `INVALID`. It
submitted eight fresh keys against a native pending/cache capacity of `4/4`,
allowed normal eviction, and stopped before a durable `CLEANUP`. The original
verifier also paired different `(token, flow_id)` generations across eviction.
That was a cohort and settlement design defect, not a UID mismatch.

The corrected four-tuple cohort (AppA/AppB × IPv4/IPv6) added a bounded cleanup
wait and stable token/flow pairing. Its first device run,
`results/s139-a2-2-cache-concurrency-20260823-fixed-1/`, was valid but
`INCONCLUSIVE`: AppB completed both sequences while AppA lost one durable
runtime join and its other repeat returned `EPERM`.

The next run,
`results/s139-a2-2-cache-concurrency-20260823-fixed-2/`, reproduced the
fixture timing issue in the opposite App direction. All four first sends were
VPN-bound, native start/session/plugin/APK/source/allowed-scope checks passed,
`maxPending=2/4`, `maxCache=4/4`, and final cleanup settled to
`pending=0/cache=0/flow-ids=0`. AppA's two repeats succeeded, but AppB's second
IPv4 and IPv6 sends returned `EPERM` roughly 27 ms and 20 ms after their first
records, before another native resolver query. Fixed-1 had the corresponding
short-interval failure on AppA instead. This drift follows Android
`singleTop`/worker scheduling rather than a UID: the adapter's failed send path
returns before its success-path delay, so the result is not evidence of a
resolver or FlowOwner architecture fault.

The runner is therefore being revised to two evidence-gated waves. Each wave
uses four `repeat=1` launches. Wave 1 must show four correct-UID
`COMPLETION_ACCEPTED` events before wave 2 is submitted; wave 2 must show four
correct-UID `CACHE_HIT` events before pre-cleanup capture. The gates are
durable contract observations, not fixed sleeps. A timeout remains
`INCONCLUSIVE` with raw evidence retained; B1 remains blocked.

The first two-wave device run,
`results/s139-a2-2-cache-concurrency-20260823-fixed-3/`, reached all four
first-wave completion events and all four second-wave cache hits. Its pending
and cache bounds, UID joins, runtime pair gates, and native/session provenance
were valid. The runner nevertheless returned `INVALID` because the stop
control Activity did not produce a durable `CLEANUP` within the ten-second
settlement window; the emergency force-stop was marked in `cleanup-wait.json`.
The raw bundle is retained. This is a control-plane settlement defect, not a
UID/cache or FlowOwner architecture interruption. The next runner correction
uses a waited, clear-top stop delivery before considering the bounded fallback.

The clear-top cleanup correction was exercised by `fixed-4` and `fixed-5`.
Both runs observed durable `CLEANUP` before force-stop and retained valid
native/session provenance, UID joins, bounded state, and final settlement.
`fixed-5` also retained four durable runtime records per App (the complete
four-key, two-wave runtime set) and four correct-UID completion plus four
correct-UID cache-hit events. It nevertheless remained `INCONCLUSIVE` because
the runtime-pair polling window timed out while the final files were still
complete; the contract also exposed a `CACHE_EXPIRED` for the delayed IPv4
replay. This is a fixture sequencing defect: the adapter slept 1200 ms after
`send()` before appending runtime evidence, and the runner incorrectly used
that file poll as a pair barrier. It is not evidence of a UID or FlowOwner
failure.

The next fixture revision keeps the two-wave contract semantics but changes
the pair barrier to native family events. Wave 1 gates IPv4 and IPv6 pairs on
correct-UID `COMPLETION_ACCEPTED`; wave 2 gates each pair on a new
correct-UID `CACHE_HIT`, using a pre-wave hit-count baseline so an earlier
duplicate hit cannot satisfy the replay. A2-2 UDP launches retain the socket
with the positive `timeoutMillis=1200` observation delay so the asynchronous
Android owner API can resolve the tuple before the adapter closes it. Runtime
JSONL is captured as final evidence rather than a long-lived launch barrier.
The evidence schema is now `s139-a2-2-two-wave/v2` with explicit
`nativeGates`; the verifier treats the runtime snapshot as final evidence and
no longer turns a diagnostic runtime poll timeout into a wave-gate failure.

The `fixed-6` device run falsified the zero-delay variant: both Apps recorded
successful sends, but native owner resolution returned `uid=-1` with
`LOOKUP_UNAVAILABLE` because the UDP sockets closed before the asynchronous
Android owner query completed. This is a fixture socket-lifetime defect, not
a UID or FlowOwner defect. The runner therefore restores the positive 1200 ms
retention delay while keeping the native family barriers and final runtime
capture.

The `fixed-7` device run isolated one more delivery-only fixture race: when
AppA and AppB `am start` calls were launched completely concurrently, AppA's
IPv4 intent was lost (`runtime=0`, native contract `0`) while AppB completed
one lookup and cache hit. The native family gate correctly timed out at 1/2;
this is consistent with Android `singleTop`/ADB intent delivery drift, not a
UID or resolver failure. The runner now starts AppA and AppB with a
configurable 250 ms stagger. The stagger only protects intent delivery; the
1200 ms socket retention remains, so both family lookups can still overlap in
the native pending ledger.

The `fixed-9` run then completed the functional A2-2 evidence, but the verdict
was `INVALID` solely because the launch-window start marker
(`1787481955315537700`) exceeded its end marker
(`1787481935977718300`). The runner had obtained those values from wall-clock
`date +%s%N`; a host clock rollback made the monotonic-named fields reverse.
The fixture now obtains both markers from Python `time.monotonic_ns()` and
records the clock source in `launch-window.json`. This is evidence plumbing,
not a data-plane, UID, or FlowOwner failure.

The `fixed-10` rerun at clean HEAD `d9141ee` is the decisive A2-2 PASS. It
observed all four first-wave correct-UID completions and all four second-wave
correct-UID cache hits. Each App/family tuple has two successful VPN-bound
runtime records with the expected UID (`12630`/`12631`) and one stable
`MISS_SUBMITTED -> COMPLETION_ACCEPTED -> CACHE_HIT` identity. Native high-water
was `maxPending=2/4` and `maxCache=4/4`; the monotonic launch window covered all
eight launches with no failures. Durable cleanup was observed before any
force-stop fallback, and the final ledger settled to
`pending=0/cache=0/flow-ids=0` with no VPP process or `tun0` residue.

This closes the A2-2 fixture/contract hotspot. The prior failures were all
bounded evidence or Android intent/socket timing defects; none showed a wrong
UID, cross-App cache hit, stale identity, FlowOwner bypass, or architecture
interruption.

### 2026-08-26 S156-guarded A2-2 revalidation

After S156 closed `VPN-F061`, A2-2 was rerun from the new guardrail baseline
rather than relying on the 2026-08-23 public-endpoint-era bundle.  The runner
now rejects stale APK/native artifacts, uses the WSL2/LAN fixture endpoints,
records `uidContractCellId=A2-2`, requires resolver
`cell/stage/request` correlation, installs VpnLite as part of the run, and
keeps the source provenance clean before device execution.

The first guarded bundle,
`evidence/s186-a2-2-cache-concurrency-20260826-run1/`, was
`INCONCLUSIVE`, not failed.  It proved all four same-identity
`MISS_SUBMITTED -> COMPLETION_ACCEPTED -> CACHE_HIT` sequences and reached
`maxCacheObserved=4`, but `maxPendingObserved=1`.  The contract showed each
Android owner completion finished before the next App lookup was submitted.
That was a concurrency fixture timing issue caused by fast owner resolution
plus the per-stage ADB control round trip, not a UID attribution or cache
identity defect.

Commit `4b5182a` corrected the fixture by applying the existing bounded
`uidContractCompletionDelayMillis` control to A2-2 stage arms.  The second
guarded bundle,
`evidence/s186-a2-2-cache-concurrency-20260826-run2/`, is the decisive
S156-era A2-2 PASS:

- `status=PASS`;
- `registeredTuples=4`;
- `passedSequences=4`;
- `concurrent=true`;
- `maxPendingObserved=2` under declared pending capacity `4`;
- `maxCacheObserved=4` under declared cache capacity `4`;
- final cleanup settled to `pending=0/cache=0/flow-ids=0`;
- source provenance is `gitHead=4b5182a4069ba0142f65446f7a15e064fe1807c7`,
  `gitDirty=false`;
- fixture endpoints are `192.168.4.5:55553` and
  `fd76:d462:c4e3:0:542e:6667:7d53:b784:55553`;
- `uidCompletionDelayMillis=1000`.

This revalidation closes A2-2 under the S156 guardrails.  It does not broaden
A2-2 into production cache sizing, lifecycle invalidation, external
connectivity, or B1/B2 whole-device behavior.

The same guardrail standard now applies to the remaining A2 cells.  The
2026-08-23 A2-4, A2-5, and A2-6 PASS bundles remain retained functional
baselines, but they used the old public `1.1.1.1:53` destination/provenance
envelope and do not carry `uidContractCellId`, controlled fixture metadata, or
resolver `cell/stage/request` correlation.  They therefore cannot close the
current S156-era aggregate without S188/S189/S190 reruns.  This is an evidence
standard correction, not a behavioral contradiction of the earlier UID/drop
claims.

## A2-3 controlled reverse-return execution

Cell: `A2-3 controlled reverse traffic`

Current verdict: `PASS` for the controlled IPv4 and IPv6 return cells
Aggregate remains: `A2_INCOMPLETE`; `architecture_interruption=false`

The first three A2-3 attempts did not enter the data plane. They used the
mistyped historical serial `28201JEGR0XPA`; the connected Pixel serial is
`28201JEGR0XPAJ`. Those bundles are retained as `INVALID/NOT RUN` and contain
no native or App return evidence. `fixed-4` used the correct serial and
proved the complete IPv4 data path, but the runner's contract cleanup poll
looked only for `"event":"CLEANUP"` while the durable contract schema emits
`"outcome":"CLEANUP"`. Its final verifier result is therefore correctly
`INVALID`; commit `8768c2d` corrected the observation gate without weakening
the cleanup requirement.

The native and App evidence in `fixed-4` also exposed a real IPv6 fixture
defect. A valid IPv6 ingress was followed by unrelated 48-byte TUN frames;
`oi3_parse_tun_packet()` cleared the shared committed target before rejecting
one of those frames. The later owner-output packet consequently had IPv6
source `::` and UDP source port `0`, while the text ledger still reported the
right canonical key. AppA timed out (`fixed-6`, `INCONCLUSIVE`). This was a
native state-corruption bug, not a UID, FlowOwner, broker, or network
architecture failure. Commit `ffe87d7` preserves the committed target across
invalid TUN frames.

Clean-head arm64 evidence uses plugin SHA-256
`1176176517a95dd8ad7706a6713a2290997fb078e0970385e0112f834964c6cf`, VpnLite
UID `12628`, and AppA UID `12630`. The current VpnLite/APK source receipt is
`gitHead=ffe87d731414e20700bb3b606e0a922bf61a99b6`, `gitDirty=false`.

| Bundle | Family / tuple | Result | Decisive evidence |
| --- | --- | --- | --- |
| `results/s139-a2-3-controlled-return-20260823-fixed-7/` | IPv6 `fd00:200::2:45843 -> fd00:200::1:42083` | `PASS` | AppA same-socket receipt, native ingress/output, raw TUN tuple, broker, cleanup |
| `results/s139-a2-3-controlled-return-20260823-fixed-9/` | IPv4 `10.200.0.2:45845 -> 10.200.0.1:42085` | `PASS` | AppA same-socket receipt, native ingress/output, raw TUN tuple, broker, cleanup |

Both current bundles independently pass the verifier, including the raw
packet gate added after the IPv6 incident. The raw IPv6 output now has source
`fd00:200::1`, destination `fd00:200::2`, source port `42083`, destination
port `45843`, and the exact 26-byte marker. Both bundles join the same
direction-independent canonical key between AppA JSONL and OI3 ingress/
output; output owner-pthread matches durable owner identity; Android lookup
count is zero; transport re-entry is zero; broker request/completion is
`1/1`; native buffers have residue `0`; cleanup is observed before any
force-stop fallback; and post-run snapshots show no VPP/VpnLite process or
`tun0`.

The raw bundles `fixed-5` (pre-IPv6 fix), `fixed-6` (the falsifying IPv6
state-pollution run), and `fixed-8` (ADB vsock interruption after cleanup)
remain retained and are not substituted for the two current PASS bundles.
A2-3 proves controlled Flow Stack return/TUN delivery and UID/provenance
reuse only. It does not claim protected external Direct Egress, Internet
reachability, or an underlay reply.

### 2026-08-26 S187/S191 current-artifact A2-3 refresh

S187 initially reproduced the A2-3 controlled reverse path on the current
artifact but exposed a cleanup-control hotspot.  The first IPv4 bundle
`evidence/s187-a2-3-controlled-return-20260826-ip4/` had PASS evidence for
AppA same-socket return, OI3 ingress/output, raw TUN tuple/payload,
canonical UID/package/stage join, owner-pthread identity, zero Android UID
lookup, zero transport re-entry, and broker `1/1`; it was still `INVALID`
because native A2-3 `event=CLEANUP` was absent before force-stop fallback.

S191 classified that as a POC seam error.  Product stop via `--ez stop true`
terminates the native child and records signal/process settlement; it does not
drive the OI3 bounded cleanup emitter that the A2-3 verifier requires.
Commit `c9eb3c5` adds a `MainActivity` bridge for the test-only
`oi3Control=stop` intent and changes the runner to drive that control before
ordinary VPN stop.

Clean-head reruns close the current-artifact A2-3 refresh:

| Bundle | Family / tuple | Result | Decisive evidence |
| --- | --- | --- | --- |
| `evidence/s187-a2-3-controlled-return-20260826-clean-ip4/` | IPv4 `10.200.0.2:45853 -> 10.200.0.1:42093` | `PASS` | Same-socket App return, OI3 ingress/output, raw TUN tuple, UID/stage join, no lookup/re-entry, broker, bounded cleanup |
| `evidence/s187-a2-3-controlled-return-20260826-clean-ip6/` | IPv6 `fd00:200::2:45855 -> fd00:200::1:42095` | `PASS` | Same-socket App return, OI3 ingress/output, raw TUN tuple, UID/stage join, no lookup/re-entry, broker, bounded cleanup |

Both bundles record `gitHead=c9eb3c587bd8d46a277e69b733db48ef263d1ab7`,
`gitDirty=false`, VpnLite APK SHA-256
`0a4adfe379577289ee608a22d6ebd4f5fc4dd7577b53b59943871d4147d69ccf`, AppA APK
SHA-256 `29a4d0913cbf67fcdb33a6dd06381735fe657f16228f1088fff47917974b5a3c`,
and OI3 plugin SHA-256
`5012eeecb16828edca58f3dc98ddd52330a3b09b26394a3baa94b7c39604cc72`.  Their
cleanup receipts report `cleanupObservedBeforeForceStop=true`,
`nativeCleanupObserved=true`, `contractCleanupObserved=true`,
`forceStopFallback=false`, and `pollAttempts=2`.

## A2-4 S156-guarded lifecycle/native join refresh

Cell: `A2-4 lifecycle/native join`
Current verdict: `PASS`
Aggregate remains: `A2_INCOMPLETE`; `architecture_interruption=false`

S188 first exposed an artifact/runtime hotspot rather than a lifecycle or UID
failure.  The initial A2-4 run used a stale VpnLite APK that failed preflight
because it lacked the tun-poc plugin provenance asset and plugin members.  A
corrected package then carried a S156-correlated `tun_poc_plugin.so`, but that
plugin came from an older isolated VPP work tree and was ABI-mismatched with
the product runtime libraries in the APK.  VPP started but did not load
`tun_poc`: `show plugins` had no plugin row, `show tun-poc` and
`tun-poc stage` were `unknown input`, and the resolver aggregate recorded
`queries=0`.  That bundle was correctly `INVALID`; it did not test the A2-4
lifecycle claim.

Commit `138a2f4` fixes the Android VPP overlay so product runtime builds carry
the S156 native resolver correlation in `plugins/tun_poc/tun_poc.c`.  The
query now records `cell`, `stage`, and `request` at resolver request creation,
using `SAKAMOTO_A2_STAGE_CELL` for the cell and the current native stage for
the immutable request stage.  Static A2-4 tests now assert that the overlay
contains this correlation seam.

Clean-head rerun
`evidence/s188-a2-4-lifecycle-native-join-20260826-overlay-run1/` is the
current S156-era A2-4 PASS:

- `gitHead=138a2f4f4db5d5c73b199eb9bd37e101afa286e0`;
- `gitDirty=false`;
- fixture destination `192.168.4.5:55553`;
- `uidContractCellId=A2-4`;
- `resolverCorrelationSchema=a2-1-resolver-cell-stage-request/v1`;
- VpnLite APK SHA-256
  `5aef6c5e20c02e82f4e2acdf882f8f1686fd19774040ea972507bf66b6b1be39`;
- AppA APK SHA-256
  `7b082e62109addc465d91e5df82e0fca47cf206158db2d6a2f929dcbca9b4809`;
- runtime `libvpp_runtime.so` SHA-256
  `cc2dfaaee109f1c54f884010dfdf856e8c462a288f7594ee43513b7c3287c022`;
- runtime `libvlib.so` SHA-256
  `e6b6bf8f6864f77801a22bc60a8259744982af57aa9e933dc3c4f01361fde522`;
- `libtun_poc_plugin.so` and APK plugin-asset SHA-256
  `d919117842eb41b6924693f7b79a2d20ee6ce22f8ab371b7995039c38b46d9bc`.

All registered gates pass: baseline registration, session provenance,
native VPP start, local and installed APK hashes, plugin hash join, install
receipts, Java contract schema, native resolver ledger, stage boundaries,
VPN network-handle restart, all nine Java/native lifecycle stage joins,
refresh epochs, runtime generation refresh, cleanup settlement, contract
cleanup, and native cleanup ledger.  `native-stale-join` remains
`INCONCLUSIVE` only because `staleNativeJoinRequired=false` and
`staleNativeJoinGap=false`; it is the retained non-claim from the historical
A2-4 design, not a failure or invalidation reason.

This closes A2-4 under the S156 guardrails and records a new POC artifact seam:
future Android runtime/APK POCs must prove the selected tun plugin was built
from the same product runtime source/stage as `libvlib.so`, not only that an
APK member exists with the expected filename.

## A2-5 S156-guarded allow/drop admission refresh

Cell: `A2-5 known-UID allow/drop admission ledger`
Current verdict: `PASS`
Aggregate remains: `A2_INCOMPLETE`; `architecture_interruption=false`

S189 reran the A2-5 known-UID allow/drop ledger on the S156 guardrail baseline.
The run used the controlled WSL2/LAN fixture instead of a public resolver
destination, recorded `uidContractCellId=A2-5`, required resolver
`cell/stage/request` correlation, and joined local plus installed APK hashes.

Clean-head bundle
`evidence/s189-a2-5-admission-ledger-20260826-run1/` is the current S156-era
A2-5 PASS:

- `gitHead=9b7968662a3512e90a0a7b178ec75d5b79a39da6`;
- `gitDirty=false`;
- fixture destination `192.168.4.5:55553`;
- `uidContractCellId=A2-5`;
- `resolverCorrelationSchema=a2-1-resolver-cell-stage-request/v1`;
- VpnLite APK SHA-256
  `5aef6c5e20c02e82f4e2acdf882f8f1686fd19774040ea972507bf66b6b1be39`;
- AppA APK SHA-256
  `7b082e62109addc465d91e5df82e0fca47cf206158db2d6a2f929dcbca9b4809`;
- `libtun_poc_plugin.so` SHA-256
  `d919117842eb41b6924693f7b79a2d20ee6ce22f8ab371b7995039c38b46d9bc`.

The allow stage used AppA UID `12630` and canonical key
`ip4|udp|46001|192.168.4.5:55553`.  It recorded
`POLICY_DECISION=ALLOW`, one `TRANSPORT_ADMITTED`, and joined broker request,
broker completion, socket create, and socket settle evidence for the exact
key.  The drop stage used a fresh key
`ip4|udp|46002|192.168.4.5:55553`, recorded `POLICY_DECISION=DROP`, observed
the known-UID block at `tun_poc`, and produced zero downstream transport,
broker, or socket events.  Both stages observed durable native and contract
cleanup before any force-stop fallback, and final residue checks found no VPP
process or `tun0`.

This closes A2-5 under the S156 guardrails.  It proves the registered
known-UID allow/drop admission boundary only; it does not claim external
connectivity, Internet reachability, B2 transport failure semantics, or
production policy/catalog coverage.

## A2-6 S156-guarded replay and settlement refresh

Cell: `A2-6 replay and settlement aggregate`
Current verdict: `PASS`

S190 reran the A2-6 replay/settlement cell on the current S156 guardrail
baseline.  The run used the controlled WSL2/LAN fixture, recorded
`uidContractCellId=A2-6`, required resolver `cell/stage/request` correlation,
and joined local plus installed APK hashes.

Clean-head bundle
`evidence/s190-a2-6-replay-settlement-20260826-run1/` is the current S156-era
A2-6 PASS:

- `gitHead=ff69c0669f30bba838cccf853962a8d7e67d7ffc`;
- `gitDirty=false`;
- fixture destination `192.168.4.5:55553`;
- `uidContractCellId=A2-6`;
- `resolverCorrelationSchema=a2-1-resolver-cell-stage-request/v1`;
- VpnLite APK SHA-256
  `5aef6c5e20c02e82f4e2acdf882f8f1686fd19774040ea972507bf66b6b1be39`;
- AppA APK SHA-256
  `7b082e62109addc465d91e5df82e0fca47cf206158db2d6a2f929dcbca9b4809`;
- `libtun_poc_plugin.so` SHA-256
  `d919117842eb41b6924693f7b79a2d20ee6ce22f8ab371b7995039c38b46d9bc`.

All registered A2-6 gates pass: replay stage registration, replay falsifiers
for wrong owner, wrong UID, wrong generation, wrong scope, accepted, duplicate,
and stale cases, bounded contract settlement, orderly cleanup, process/TUN
settlement, real transport settlement, and native ledger bounds.  The live
transport stage observed a real AppA allow flow crossing policy into
broker/socket settlement.  The bounds were `max_pending=1`, `max_cache=2`,
and `max_flow_ids=2`, and all final values settled to zero.  Cleanup was
observed before force-stop fallback; no VPP/VpnLite process or `tun0` residue
remained.

This closes A2-6 under the S156 guardrails.  It does not claim production
capacity, external Internet reachability, B1/B2 whole-device behavior, long
lifecycle behavior, or underlay handover.

## Final S156-era A2 aggregate audit

Final aggregate bundle:
`evidence/s190-a2-aggregate-20260826-run1/a2-aggregate.json`

Current aggregate verdict: `PASS`; `architectureInterruption=false`.

The aggregate auditor binds these result files:

| Cell | Bound result |
| --- | --- |
| A2-0 | `results/s139-a2-0-session-provenance-20260823-fixed-1/result.json` |
| A2-1 | `evidence/s156-a2-1-correlation-20260825-run5/result.json` |
| A2-2 | `evidence/s186-a2-2-cache-concurrency-20260826-run2/result.json` |
| A2-3 | `evidence/s187-a2-3-controlled-return-20260826-clean-ip6/result.json` |
| A2-4 | `evidence/s188-a2-4-lifecycle-native-join-20260826-overlay-run1/result.json` |
| A2-5 | `evidence/s189-a2-5-admission-ledger-20260826-run1/result.json` |
| A2-6 | `evidence/s190-a2-6-replay-settlement-20260826-run1/result.json` |

The A2-3 current refresh is supported by both IPv4 and IPv6 raw bundles:
`evidence/s187-a2-3-controlled-return-20260826-clean-ip4/` and
`evidence/s187-a2-3-controlled-return-20260826-clean-ip6/`.  The aggregate
script accepts one `A2-3` result binding, so it references the IPv6 result
while this journal retains both address-family bundles as the A2-3 evidence
set.

The aggregate result contains no errors.  Every registered A2 cell is `PASS`,
every input retains cleanup or settlement checks, and A2-4's
`native-stale-join` remains the sole out-of-scope inconclusive check because
`staleNativeJoinRequired=false`.  The aggregate claims only the bounded A2
identity, lifecycle, allow/drop, replay, and cleanup scope.  It does not claim
B1/B2 external-connect behavior, Internet reachability, production capacity,
long-lifecycle capacity, or underlay handover.

## Claim boundary and next cells

A2-0, A2-1, and A2-2 now prove durable session provenance, the complete
deterministic two-App dual-stack tuple/UID matrix, and bounded asynchronous
cache/concurrency behavior. A2-3 now proves controlled Flow Stack reverse
delivery with same-socket App receipt, canonical owner/UID reuse, raw TUN
tuple integrity, no lookup/re-entry, and bounded cleanup. A2-4 now proves
stage-correlated lifecycle invalidation/recovery, Java/native resolver joins,
network-handle restart, generation refresh, and bounded cleanup on the current
artifact. A2-5 now proves the known-UID allow/drop admission boundary with
exact zero-downstream evidence for a fresh dropped key. These cells do not
prove B1/B2 external-connect behavior.

At the S156-era evidence standard, S187/S191 now closes the A2-3 current
artifact refresh, S188 closes A2-4 lifecycle native join, and S189 closes A2-5
allow/drop admission.  S190 closes A2-6 and the final current aggregate audit.
The historical final audit below records the 2026-08-23 aggregate only; the
current S156-era aggregate above is now the A2 closure evidence for Plane.

## Historical 2026-08-23 A2 closure audit

The seven registered cells were joined by the 2026-08-23 machine-readable
aggregate auditor:

`results/s139-a2-aggregate-20260823-1338/a2-aggregate.json`

Historical aggregate verdict: `PASS`; schema `s139-a2-aggregate/v1`; all
required cell results were `PASS`, every input retained a cleanup/settlement
check, and `architectureInterruption=false`. This remains an audit of the
registered bounded claims as they stood on 2026-08-23. It does not satisfy the
later S156 guardrail contract for A2-4/A2-5/A2-6, and it does not unblock
external-connect, production-capacity, long-lifecycle, or underlay-handover
claims.

### A2-4 lifecycle/native join

Passing bundle:
`results/s139-a2-4-lifecycle-native-join-20260823-201037/`

The lifecycle cell passes its registered baseline, cache-hit, refresh,
network-restart, provider-unavailable/restore, stale-generation, and cleanup
joins. Its one `native-stale-join` check remains `INCONCLUSIVE` by design: the
retained detail explicitly says native stale completion is outside the
registered claim; Java late-completion rejection is the registered assertion.
The aggregate auditor records this as an out-of-scope non-claim rather than
promoting it to a cell failure.

### A2-5 UID allow/drop admission ledger

Passing bundle:
`results/s139-a2-5-admission-ledger-20260823-133741/`

The default runner now uses a bounded `REPEAT=4` burst to allow the normal
asynchronous `uid=-1` miss to settle without sleep-based verdicts. On the
Pixel 6a, VpnLite UID `12628` and AppA UID `12630` produced an allow decision
for the fresh `46001` key, one native `TRANSPORT_ADMITTED`, broker request /
completion, and socket create / settle. A fresh `46002` key with the same
known UID was dropped at `tun_poc` and produced zero downstream admission,
broker, or socket events. Both stages observed orderly cleanup.

### A2-6 replay and settlement aggregate

Passing bundle:
`results/s139-a2-6-replay-settlement-20260823-133712/`

The live AppA transport tuple crossed `A2-6-transport` and settled the real
broker/socket seam. The replay stage joined all seven registered Java
contract cases: wrong owner, wrong UID, wrong generation, wrong scope,
accepted, duplicate, and stale-after-refresh, plus cross-App cache-hit and
flow-owner-key mutation rejection. Pending/cache/flow-id high-water remained
bounded and final cleanup reached zero residue; no VPP/VpnLite process or
`tun0` remained.

Two harness defects were corrected while retaining their raw bundles:

- the replay fixture used historical hard-coded UIDs and therefore rejected
  the installed AppA UID; `UidAttributionContract` now derives the accepted
  UID from the registered allow scope;
- stage admission evidence could be consumed by a startup packet or a shared
  tuple snapshot. Native stage changes now reset only the stage admission
  guard, and the logger parses the tuple from the packet at the write seam,
  consuming the guard only after a durable event is emitted.

Relevant clean checkpoints are `9dcfa30` (A2-6 cell and dynamic UID fixture),
`5c0187a` (AppA runner package binding), `bf6e371` (stage guard reset), and
`665623d` (packet-local admission logger). Host verifier coverage is 37 tests
passing.

## A2 disposition and next gate

A2 was complete at the registered 2026-08-23 POC scope and is now complete at
the S156-era guardrail scope.  The current aggregate audit is
`evidence/s190-a2-aggregate-20260826-run1/a2-aggregate.json` with `PASS` and
`architectureInterruption=false`.  This unblocks the A2 dependency for B1 in
Plane.  The aggregate still does not claim external Internet reachability,
production capacity, long lifecycle, or underlay handover.
