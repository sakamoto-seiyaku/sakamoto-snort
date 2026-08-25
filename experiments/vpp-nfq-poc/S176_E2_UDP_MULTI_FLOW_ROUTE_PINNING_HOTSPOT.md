# S176 E2 UDP multi-flow route-pinning hotspot

Date: 2026-08-25

Status: `CLOSED_FOR_BOUNDED_UDP_MULTI_FLOW_ROUTE_PINNING_SLICE`

Scope: Pixel `vpp-oi3-multi` IPv4 UDP/TCP L4 stress against the WSL2 LAN
fixture `192.168.4.5`, plus an OI3-only 16-request HTTP staircase regression.

S176 is a hotspot and correction record. It extends the post-S175 E2 work from
foreground HTTP/TCP staircase correctness into concurrent UDP flow admission.
It does not prove arbitrary UDP capacity, production throughput, CPU/thermal,
Doze, long-soak, IPv6/DNS, or final ADR-0007 performance readiness.

## Initial failure

Initial evidence directory:
[`evidence/s176-e2-l4-udp-tcp-final-apk-20260825/`](evidence/s176-e2-l4-udp-tcp-final-apk-20260825/)

- Run ID: `20260825-152536-302639`
- APK SHA-256:
  `441b0279e2685d0d89b6092ce00f64e49742a1fcfaaf691611c826a20fca97c4`
- OI3 plugin SHA-256:
  `9282f8c82c5223e2c7b144f85a2533100df646ec821ff0ef91737b9ef8a85186`
- HEV owner-context library SHA-256:
  `37481673d6547c5f2a178de04bf4c4b5f60ba6ce1bed7c7cba1cd22b606ac96d`

The bounded Direct-vs-OI3 runner used:

```text
CELLS="udp:1:64:1:closed udp:4:1400:1:closed tcp:1:1400:1:closed"
REPEATS=2 STEADY_SECONDS=10 WARMUP_SECONDS=1 DRAIN_SECONDS=2
```

Direct UDP/TCP cells passed, OI3 single-flow UDP passed, and OI3 TCP passed.
Only the concurrent OI3 UDP4 cell failed in both repeats:

| Cell | Sent | Received | Errors | cleanup | ownerBusy | multiRejectNonTail | valid |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `oi3-udp-f4-p1400-b1-closed-r1` | 1888 | 1878 | 10 | 3/0 | 11 | 11 | 0 |
| `oi3-udp-f4-p1400-b1-closed-r2` | 1897 | 1887 | 10 | 3/0 | 11 | 11 | 0 |

The app log showed one UDP source flow sending ten datagrams with zero replies.
VPP stdout showed three UDP hashes admitted to three owners, then the fourth
hash rejected because its deterministic primary owner was already active:
`reason=owner-busy`.

This is not the S173/F050 TCP successor-SYN defect. F050 preserved TCP
canonical ownership and deferred successor SYNs. S176 is a simultaneous UDP
flow collision: the selected four-owner topology had idle capacity, but
`hash % owner_count` mapped the fourth UDP flow to a busy owner.

## Root cause

High confidence:

1. The failing cell was valid. Direct passed, OI3 single-flow UDP passed, OI3
   TCP passed, cleanup was otherwise clean, and no fixture/ADB/APK residue
   explained the selective UDP4 loss.
2. OI3 multi-owner return rewrite is owner-local. Stuffing two different UDP
   5-tuples into the same active owner would corrupt return rewrite state.
3. TCP and UDP need different handling. TCP successor flows must stay on the
   canonical owner so SYN/tail/tombstone semantics remain deterministic. UDP
   datagram flows can be pinned to an idle owner when their canonical owner is
   busy, as long as later datagrams for the same flow use the same route.

The POC correction is therefore bounded UDP route pinning, not a second packet
path and not arbitrary owner spill.

## POC correction

Implemented in
[`owner_inline_oi3.c`](overlay/src/plugins/hev_external_driver_poc/owner_inline_oi3.c):

- `OI3_MULTI_FLOW_ROUTE_CAPACITY=16` stores bounded UDP flow-to-owner routes.
- `oi3_multi_flow_route_lookup()` runs before canonical owner modulo selection.
- `oi3_multi_udp_idle_owner()` chooses an idle owner only when the protocol is
  UDP, the primary owner is active for a different hash, and another owner is
  idle.
- `oi3_multi_flow_route_insert()` pins the selected UDP flow route after
  admission reservation succeeds; enqueue failure removes the inserted route.
- Telemetry records `oi4 multi-route result=REASSIGN ... reason=udp-idle-owner`
  and `oi4 multi-route result=PIN ... route-pinned=1`.
- Static regression
  `test_udp_multi_flow_uses_idle_owner_route_pinning` verifies the route lookup
  appears before `hash % oi3_multi.owner_count` and checks the route-pinning
  markers.

Build hygiene found two repeat pitfalls:

- The legacy `work/android-hev-stage` library lacks owner-context symbols.
  Packaging OI3 must use `work/android-hev-poc7-stage`.
- Building the plugin from `work/vpp-android-configure-probe` can capture the
  rejected P6 conditional-wake ABI (`vlib_frame_queue_wakeup_mode`). The
  accepted artifact below was rebuilt from the clean product Android VPP
  build/source and verified to have no `vlib_frame_queue_wakeup_mode`
  dependency.

## Accepted artifact

- APK SHA-256:
  `f4e350c6478ce9f495afa9b1b97f174c79915592a461aeb25d7e8cdd803e1541`
- OI3 plugin SHA-256:
  `5012eeecb16828edca58f3dc98ddd52330a3b09b26394a3baa94b7c39604cc72`
- HEV owner-context library SHA-256:
  `37481673d6547c5f2a178de04bf4c4b5f60ba6ce1bed7c7cba1cd22b606ac96d`

The APK was installed on Pixel 6a `28201JEGR0XPAJ`, Android 16, package
`com.sakamoto.snort.vpnlite`, UID `12628`.

## Accepted S176 evidence

Minimal UDP4 regression:
[`evidence/s176-e2-l4-udp4-f4-route-pinning-cleanabi-20260825/`](evidence/s176-e2-l4-udp4-f4-route-pinning-cleanabi-20260825/)

- Run ID: `20260825-155119-253253`
- CSV:
  [`cells-20260825-155119-253253.csv`](evidence/s176-e2-l4-udp4-f4-route-pinning-cleanabi-20260825/cells-20260825-155119-253253.csv)
- Manifest:
  [`run-20260825-155119-253253-manifest.json`](evidence/s176-e2-l4-udp4-f4-route-pinning-cleanabi-20260825/run-20260825-155119-253253-manifest.json)

| Cell | Sent | Received | Errors | cleanup | ownerBusy | multiRejectNonTail | valid |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `oi3-udp-f4-p1400-b1-closed-r1` | 2504 | 2504 | 0 | 8/0 | 0 | 0 | 1 |
| `oi3-udp-f4-p1400-b1-closed-r2` | 2483 | 2483 | 0 | 8/0 | 0 | 0 | 1 |

The route-pinning logs include:

```text
oi4 multi-route result=REASSIGN owner=0 primary=1 ... reason=udp-idle-owner route-pinned=0
oi4 multi-route result=PIN owner=0 ... protocol=17 route-pinned=1
```

Full IPv4 UDP/TCP S176 slice:
[`evidence/s176-e2-l4-udp-tcp-route-pinning-cleanabi-20260825/`](evidence/s176-e2-l4-udp-tcp-route-pinning-cleanabi-20260825/)

- Run ID: `20260825-155427-072214`
- CSV:
  [`cells-20260825-155427-072214.csv`](evidence/s176-e2-l4-udp-tcp-route-pinning-cleanabi-20260825/cells-20260825-155427-072214.csv)
- Manifest:
  [`run-20260825-155427-072214-manifest.json`](evidence/s176-e2-l4-udp-tcp-route-pinning-cleanabi-20260825/run-20260825-155427-072214-manifest.json)

All 12 Direct/OI3 cells were valid and the manifest records `failureCount=0`:

| Cell | Sent | Received | cleanup | ownerBusy | multiRejectNonTail |
| --- | ---: | ---: | ---: | ---: | ---: |
| `direct-udp-f1-p64-b1-closed-r1` | 2376 | 2376 | 0/0 | 0 | 0 |
| `oi3-udp-f1-p64-b1-closed-r1` | 706 | 706 | 3/0 | 0 | 0 |
| `direct-udp-f4-p1400-b1-closed-r1` | 9310 | 9310 | 0/0 | 0 | 0 |
| `oi3-udp-f4-p1400-b1-closed-r1` | 2537 | 2537 | 8/0 | 0 | 0 |
| `direct-tcp-f1-p1400-b1-closed-r1` | 2584 | 2584 | 0/0 | 0 | 0 |
| `oi3-tcp-f1-p1400-b1-closed-r1` | 584 | 584 | 4/0 | 0 | 0 |
| `direct-udp-f1-p64-b1-closed-r2` | 2226 | 2226 | 0/0 | 0 | 0 |
| `oi3-udp-f1-p64-b1-closed-r2` | 712 | 712 | 5/0 | 0 | 0 |
| `direct-udp-f4-p1400-b1-closed-r2` | 9641 | 9641 | 0/0 | 0 | 0 |
| `oi3-udp-f4-p1400-b1-closed-r2` | 2451 | 2451 | 8/0 | 0 | 0 |
| `direct-tcp-f1-p1400-b1-closed-r2` | 2475 | 2475 | 0/0 | 0 | 0 |
| `oi3-tcp-f1-p1400-b1-closed-r2` | 602 | 602 | 4/0 | 0 | 0 |

## HTTP staircase regression

HTTP regression evidence:
[`evidence/s176-s175-http16-oi3-route-pinning-cleanabi-20260825/`](evidence/s176-s175-http16-oi3-route-pinning-cleanabi-20260825/)

- Run ID: `20260825-160228-023067`
- Parameters: `arms=oi3`, `maxRequests=16`, `repeats=2`,
  `durationSeconds=30`, `requestIntervalMs=0`
- CSV:
  [`cells-20260825-160228-023067.csv`](evidence/s176-s175-http16-oi3-route-pinning-cleanabi-20260825/cells-20260825-160228-023067.csv)
- Manifest:
  [`run-20260825-160228-023067-manifest.json`](evidence/s176-s175-http16-oi3-route-pinning-cleanabi-20260825/run-20260825-160228-023067-manifest.json)

| Cell | Requests | Successes | Errors | Content-Length completions | p50 ms | p95 ms | Cleanup |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `oi3-r1` | 16 | 16 | 0 | 16 | 236 | 1289 | 20/0 |
| `oi3-r2` | 16 | 16 | 0 | 16 | 237 | 1308 | 20/0 |

The HTTP regression manifest records `failureCount=0`. This verifies the UDP
route-pinning change did not regress the S173/S175 TCP staircase path for the
bounded OI3-only 16-request sample.

## Interpretation

S176 closes the bounded UDP multi-flow collision for the selected four-owner
POC topology. UDP flows that collide on their canonical primary owner can now
use an idle owner through an explicit route table, and later datagrams for the
same UDP flow stay route-pinned.

The correction is intentionally protocol-scoped. TCP still uses canonical-owner
deferred admission from S173/F050 because TCP successor/tail/tombstone
semantics require a single deterministic owner.

## Non-claims

S176 does not prove arbitrary flow counts above the selected owner/route
capacity, UDP saturation throughput, IPv6 UDP/DNS, browser or multi-app
traffic, CPU/thermal/power budgets, Doze or screen-off behavior, long-soak
stability, or final ADR-0007/EG-17 performance readiness.
