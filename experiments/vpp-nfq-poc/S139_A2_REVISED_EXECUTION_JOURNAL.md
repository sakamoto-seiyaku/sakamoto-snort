# SAKAMOTO-139 A2 revised execution journal

Date: 2026-08-23 (Asia/Taipei)  
Plane: SAKAMOTO-139  
Design: [S139_A2_POC_DESIGN_REVISION.md](S139_A2_POC_DESIGN_REVISION.md)  
Device: Pixel 6a / arm64 / serial `28201JEGR0XPAJ`  
Aggregate: `A2_INCOMPLETE`; `architecture_interruption=false`

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
Current verdict: `INCONCLUSIVE`  
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

## Claim boundary and next cells

A2-0 and A2-1 now prove durable session provenance plus the complete
deterministic two-App dual-stack tuple/UID matrix. They do not prove
concurrency bounds, controlled reverse traffic, lifecycle invalidation, or
downstream allow/drop admission.

The remaining order is A2-2 async cache/concurrency/bounds, A2-3 controlled
return, A2-4 lifecycle native join, A2-5 allow/drop admission ledger, and A2-6
replay/settlement aggregate. B1 remains blocked until every required A2 cell
passes and the final aggregate audit is recorded.
