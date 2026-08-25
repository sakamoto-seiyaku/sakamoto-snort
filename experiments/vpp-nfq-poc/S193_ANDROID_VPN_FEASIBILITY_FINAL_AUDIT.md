# S193 Android VPN Engineering Feasibility final audit

Date: 2026-08-26
Status: `ADJUSTMENT_REQUIRED_E2_PERFORMANCE`

## Decision

The current Android VPN POC campaign does not yet support importing the route
directly into the product/main stack as the selected implementation baseline.

The campaign evidence supports the owner-inline route for identity, bounded
full-device correctness, lifecycle/resource settlement, and matched device-state
operation on the selected Pixel 6a.  It fails the registered ADR-0007 E2
comparative performance gate: OI3 remains materially slower than both Direct
and HEV matched controls in the HTTP staircase/device-state slices.

This is an `ADJUSTMENT_REQUIRED` result, not `SUPPORTS_BASELINE` and not an
architecture reopening by itself.  The owner-inline invariants still hold; the
next work is performance/cost diagnosis and correction before formal main-stack
implementation planning.

## Claim-family audit

| Required family | Current evidence | Audit verdict |
| --- | --- | --- |
| Minimum full-device dataplane | S178 carried IPv4/IPv6 UDP/TCP DNS through the current full-device path; S180 closed forced DNS fallback fixture design; S141 B2 final audit maps S178/S179/S181/S182/S183/S184/S185 to bounded positive/negative/outcome separation. | `PASS_FOR_BOUNDED_PIXEL_SCOPE` |
| Application identity | S139/S190 current S156-era A2 aggregate binds A2-0 through A2-6, including distinct-App matrix, async cache/concurrency, controlled reverse, lifecycle/native join, known-UID allow/drop, replay and settlement. | `PASS_FOR_BOUNDED_PIXEL_SCOPE` |
| Network and lifecycle | S151 closes real underlay epoch for the selected Pixel artifact; S153/S157 close real stop/fault/restart and same-session re-arm evidence; S153 full E1 residual sequence reruns normal stop/start, fault restart and Wi-Fi epoch restart with fresh traffic and zero residue. | `PASS_FOR_BOUNDED_PIXEL_SCOPE` |
| Ownership and failure | S158/S168 close final multi-owner topology/teardown corrections; S160/S161 close D3 overload/recovery for tested envelope; S176 closes four-owner UDP route-pinning; S141 B2 closes policy/transport/infrastructure separation. | `PASS_FOR_BOUNDED_PIXEL_SCOPE` |
| Engineering envelope | S153 closes the registered E1 resource/lifecycle sequence; S171/S172/S173/S174/S175/S176/S192 close bounded correctness/construction/device-state slices.  However, S174/S175/S192 preserve OI3 p95 around 1.3--2.6s versus Direct/HEV under 100ms in matched HTTP slices. | `ADJUSTMENT_REQUIRED_E2_PERFORMANCE` |

## E2 performance decision

ADR-0007 requires Direct median throughput at least 90% of baseline and p95/p99
latency and CPU per byte/transaction at most 110%, subject to a small absolute
latency tolerance registered before execution.  The current evidence does not
meet that comparative latency gate:

- S174 8-request matched foreground HTTP: OI3 p95 around 1.6s while Direct/HEV
  stayed in single- or double-digit milliseconds.
- S175 16-request matched foreground HTTP: OI3 p95 around 1.6--1.8s in matched
  repeats while Direct/HEV stayed below 100ms.
- S192 screen-off matched HTTP: OI3 p95/p99 `2604ms`; Direct `77ms`; HEV
  `23ms`.
- S192 forced-Doze matched HTTP: OI3 p95/p99 `2618ms`; Direct `81ms`; HEV
  `20ms`.

The accepted S192 cells prove that this is not a device-state correctness
failure: every arm completed `8/8`, `stateValid=1`, OI3 cleanup was `12/0` or
`11/0`, and `failureCount=0`.  The issue is the comparative cost/latency
envelope.

## Main-stack implication

Do not import the POC route directly into the product/main stack as completed
implementation work.

Allowed next work:

- design a focused OI3 performance/cost diagnosis using the S172/S192 matched
  HTTP shape and the S171 L4 runner;
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
