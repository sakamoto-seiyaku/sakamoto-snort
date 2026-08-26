# S193 Android VPN Engineering Feasibility final audit

Date: 2026-08-26
Status: `ADJUSTMENT_REQUIRED_E2_PERFORMANCE`

## Decision

The current Android VPN POC campaign does not yet support importing the route
directly into the product/main stack as the selected implementation baseline.

The campaign evidence supports the owner-inline route for identity, bounded
full-device correctness, lifecycle/resource settlement, and matched device-state
operation on the selected Pixel 6a.  S221--S223 corrected the prior
seconds-level matched HTTP latency cliff, including screen-off and forced-Doze.
S225--S229 then exposed a new E2 budget blocker: OI3/VPP workers burn CPU while
idle, and the HEV/tun-poc matched baseline is not valid above the small
request-count envelope.  The campaign still does not prove the registered
ADR-0007 E2 performance gate because CPU budget is actively failing and
thermal/power/soak evidence plus the S223 forced-Doze tolerance decision remain
open.

This remains an `ADJUSTMENT_REQUIRED` result, not `SUPPORTS_BASELINE` and not
an architecture reopening by itself.  The owner-inline invariants still hold;
the next work is budget evidence and tolerance closure before formal main-stack
implementation planning.

Post-audit update: S199--S224 narrowed and corrected the main matched HTTP
latency issue.  The connector write-interest defect, owner handoff/post-send
read-wake tail, and TCP owner lifecycle/admission seam have focused
corrections.  S221 passed the matched foreground Direct/HEV/OI3 8-request
comparison with OI3 p95 `24ms`; S222 passed screen-off with OI3 p95 `27ms`;
S223 passed forced-Doze with OI3 p95 `78ms`; S224 passed five current-artifact
resource-trend cycles with stable fd/thread/RSS and `failureCount=0`.  The
next S225--S229 budget run did not close E2: S227/S228 OI3 remained correct
but high-CPU, S229 reproduced the worker CPU burn with no app traffic, and
HEV failed as a broad matched baseline around the 64-request boundary.  The
audit still remains `ADJUSTMENT_REQUIRED_E2_PERFORMANCE` because ADR-0007's
budget gate now has an active VPP/OI3 idle CPU blocker, plus unresolved
thermal/power/soak coverage and a pre-registered judgment on the S223
forced-Doze absolute/relative latency delta.

## Claim-family audit

| Required family | Current evidence | Audit verdict |
| --- | --- | --- |
| Minimum full-device dataplane | S178 carried IPv4/IPv6 UDP/TCP DNS through the current full-device path; S180 closed forced DNS fallback fixture design; S141 B2 final audit maps S178/S179/S181/S182/S183/S184/S185 to bounded positive/negative/outcome separation. | `PASS_FOR_BOUNDED_PIXEL_SCOPE` |
| Application identity | S139/S190 current S156-era A2 aggregate binds A2-0 through A2-6, including distinct-App matrix, async cache/concurrency, controlled reverse, lifecycle/native join, known-UID allow/drop, replay and settlement. | `PASS_FOR_BOUNDED_PIXEL_SCOPE` |
| Network and lifecycle | S151 closes real underlay epoch for the selected Pixel artifact; S153/S157 close real stop/fault/restart and same-session re-arm evidence; S153 full E1 residual sequence reruns normal stop/start, fault restart and Wi-Fi epoch restart with fresh traffic and zero residue. | `PASS_FOR_BOUNDED_PIXEL_SCOPE` |
| Ownership and failure | S158/S168 close final multi-owner topology/teardown corrections; S160/S161 close D3 overload/recovery for tested envelope; S176 closes four-owner UDP route-pinning; S141 B2 closes policy/transport/infrastructure separation. | `PASS_FOR_BOUNDED_PIXEL_SCOPE` |
| Engineering envelope | S153 closes the registered E1 resource/lifecycle sequence; S171/S172/S173/S174/S175/S176/S192 close bounded correctness/construction/device-state slices.  S221 closes the foreground matched HTTP latency regression with Direct `8/8` p95 `59ms`, HEV `8/8` p95 `11ms`, and OI3 `8/8` p95 `24ms`.  S222/S223 rerun the device-state shape under the corrected artifact: screen-off OI3 p95 `27ms`; forced-Doze OI3 p95 `78ms`; both with `failureCount=0` and cleanup `12/0`.  S224 adds five current-artifact four-flow UDP resource cycles with stable fd/thread/RSS, cleanup `16/0` per cycle, and `failureCount=0`.  S225--S229 show the remaining gap is not merely missing evidence: HEV fails as a broad baseline at 64+ requests, and OI3/VPP workers burn CPU while idle. | `ADJUSTMENT_REQUIRED_E2_PERFORMANCE` |

## E2 performance decision

ADR-0007 requires Direct median throughput at least 90% of baseline and p95/p99
latency and CPU per byte/transaction at most 110%, subject to a small absolute
latency tolerance registered before execution.  The older evidence did not
meet that comparative latency gate:

- S174 8-request matched foreground HTTP: OI3 p95 around 1.6s while Direct/HEV
  stayed in single- or double-digit milliseconds.
- S175 16-request matched foreground HTTP: OI3 p95 around 1.6--1.8s in matched
  repeats while Direct/HEV stayed below 100ms.
- S192 screen-off matched HTTP: OI3 p95/p99 `2604ms`; Direct `77ms`; HEV
  `23ms`.
- S192 forced-Doze matched HTTP: OI3 p95/p99 `2618ms`; Direct `81ms`; HEV
  `20ms`.
- S221 foreground matched HTTP with the F072 lifecycle candidate retained:
  Direct `8/8` p95 `59ms`, HEV `8/8` p95 `11ms`, OI3 `8/8` p95 `24ms`,
  cleanup `12/0`, `failureCount=0`.
- S222 screen-off matched HTTP with the same candidate retained:
  Direct `8/8` p95 `15ms`, HEV `8/8` p95 `10ms`, OI3 `8/8` p95 `27ms`,
  cleanup `12/0`, `failureCount=0`.
- S223 forced-Doze matched HTTP with the same candidate retained:
  Direct `8/8` p95 `18ms`, HEV `8/8` p95 `16ms`, OI3 `8/8` p95 `78ms`,
  cleanup `12/0`, `failureCount=0`.

The accepted S192 cells proved that this was not a device-state correctness
failure: every arm completed `8/8`, `stateValid=1`, OI3 cleanup was `12/0` or
`11/0`, and `failureCount=0`.  S222/S223 now prove the corrected artifact no
longer has that seconds-level device-state cliff.  The remaining issue is the
full comparative budget envelope.

S199--S223 then split and corrected the main matched HTTP cost envelope:

- S199 rejected a TCP payload timer-kick candidate: OI3 returned `0/4` and four
  app `SocketTimeoutException`s.
- S200/S201/S202 validated `connector_write_pending`: OI3 completed `4/4` and
  `8/8`, and the matched S202 run reduced OI3 to p95 `584ms` while Direct and
  HEV stayed at p95 `80ms` and `25ms`.
- S203/S204 showed the remaining p95 around `526--535ms` comes from native TUN
  dispatcher -> owner handoff delay; target-trigger wake did not solve it and
  was reverted.
- S205--S211 narrowed owner/completion handoff and added the guarded
  post-Direct-send read observer.
- S215--S218 isolated the final foreground tail to the TCP owner
  lifecycle/admission seam; generic timer kicks, stale-wake drains, and early
  response-complete rearm all had negative evidence.
- S219/S220 introduced the owner-local finish/rearm and deferred successor-SYN
  owner-fd candidate; S221 validated it in the matched foreground 8-request
  Direct/HEV/OI3 comparison.
- S222/S223 validated the same candidate under screen-off and forced-Doze,
  removing the prior S192 seconds-level device-state cliff.
- S224 validated the same candidate's repeated resource trend over five
  four-flow UDP cycles, with stable fd/thread/RSS and `failureCount=0`.
- S225--S228 attempted longer/count-bounded CPU-budget cells.  HEV became
  invalid around the 64-request boundary even after allowed-package scoping
  (`66/64` in S227, `64/63` in S228).  OI3 remained valid (`128/128` in S227,
  `64/64` in S228) but recorded aggregate VPP sched runtime around `32s`.
- S229 isolated the CPU issue without HTTP traffic: a valid 10-second OI3 idle
  run recorded `vppCpuTicksDelta=2235` and
  `vppSchedRuntimeNsDelta=22353121412`, dominated by the four `vpp_wk_*`
  worker threads.  A dirty exploratory 10ms `poll-sleep-usec` rerun was
  negative and was reverted.

Therefore the current result remains `ADJUSTMENT_REQUIRED_E2_PERFORMANCE`.
The immediate next engineering question is VPP/OI3 worker idle CPU reduction
and the HEV-baseline/narrowing decision, not F072 debugging or main-stack
import.

## Main-stack implication

Do not import the POC route directly into the product/main stack as completed
implementation work.

Allowed next work:

- quantify the S223 forced-Doze p95 delta against a pre-registered absolute
  tolerance rather than changing the threshold after seeing the data;
- fix or explicitly narrow the VPP/OI3 worker idle CPU hotspot found by S229;
- decide whether HEV/tun-poc remains required as a broad matched baseline, or
  narrow it to small control cells until its 64-request timeout is fixed;
- gather the remaining thermal/power/soak evidence for the corrected artifact;
- extend focused OI3 performance/cost diagnosis using the S172/S192 matched
  HTTP shape and the S171 L4 runner if budget outliers remain;
- identify whether the latency is caused by timer policy, owner scheduling,
  app probe pacing, TUN/HEV re-arm strategy, copy/materialization cost, Android
  state effects, or fixture/measurement overhead;
- implement a bounded local correction if the owner-inline invariants remain
  intact;
- rerun E2 and repeat this final audit.

Not allowed as a closure shortcut:

- lowering ADR-0007's E2 threshold after seeing the data;
- treating correctness-only POCs as performance feasibility;
- importing the throwaway POC runner or comparison APK as production code;
- replacing the product route with HEV/SOCKS, Direct fallback, unprotected
  retry, live owner migration, or a second datapath without an explicit
  architecture decision.

## Final audit result

`ADJUSTMENT_REQUIRED_E2_PERFORMANCE`.

The Pixel route remains viable enough to continue focused engineering, but the
campaign has not yet reached `SUPPORTS_BASELINE`.
