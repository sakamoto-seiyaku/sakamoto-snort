# S204 E2 OI3 write-interest and owner-handoff hotspot

Date: 2026-08-26
Status: `PARTIAL_FIX_WITH_RESIDUAL_HANDOFF_HOTSPOT`

## Decision

Do not import the current Android VPN/OI3 POC route directly into the
product/main stack yet.

The S199--S204 diagnosis split the previous E2 latency gap into two concrete
parts:

1. A connector write-interest defect that caused seconds-level TCP payload
   stalls. This part is corrected by `connector_write_pending`.
2. A remaining multi-thread TUN dispatcher -> owner handoff delay. This part is
   still open and remains the E2 performance blocker.

This is not a UID-drop failure, not an HTTP fixture failure, and not a
correctness failure for the bounded matched HTTP cells.

## Evidence summary

| Slice | Evidence | Result |
| --- | --- | --- |
| S199 | `evidence/s199-e2-oi3-tcp-payload-kick-20260826/`, run `20260826-045947-713819` | Rejected. The TCP payload timer-kick candidate returned `0/4` OI3 successes and four `SocketTimeoutException`s. |
| S200 | `evidence/s200-e2-oi3-connector-write-interest-20260826/`, run `20260826-050600-460730` | OI3 `4/4`, p50/p95/p99 `351/514/514ms`, cleanup `8/0`. |
| S201 | `evidence/s201-e2-oi3-write-interest-8req-20260826/`, run `20260826-050729-932835` | OI3 `8/8`, p50/p95/p99 `525/539/539ms`, cleanup `12/0`. |
| S202 | `evidence/s202-e2-matched-write-interest-8req-20260826/`, run `20260826-050854-725207` | Direct `8/8` p95 `80ms`, HEV `8/8` p95 `25ms`, OI3 `8/8` p95 `584ms`. |
| S203 | `evidence/s203-e2-oi3-syn-admission-timing-20260826/`, run `20260826-051405-366520` | Added `multi-ingress` and `tun-queue enqueue` wall-time probes; OI3 `4/4` but p95 `526ms`. |
| S204 | `evidence/s204-e2-oi3-target-trigger-wake-20260826/`, run `20260826-051804-388905` | Target-trigger wake candidate did not remove the delay; OI3 `4/4`, p95 `535ms`. Candidate reverted. |

## Corrected root cause: connector write interest

The old seconds-level OI3 latency was caused by a missing protected-fd write
readiness subscription after Android TCP payload submission.

Observed behavior:

- Android submitted the HTTP request payload through TUN.
- HEV/lwIP needed protected socket write readiness.
- OI3 connector polling only subscribed to `POLLOUT` while
  `connector_connect_pending` was set.
- Once connect was already complete, payload write readiness could be missed
  until Android retransmission or the bounded connector deadline moved the
  owner again.

Correction:

- Track `connector_write_pending`.
- Set it after TCP payload submit when no Direct send has happened yet.
- Include `POLLOUT` in connector polling when either connect or write is
  pending.
- Clear it on Direct send and lifecycle/re-arm boundaries.
- Preserve the rejected timer-kick candidate as a non-solution.

The S200/S201/S202 cells prove this removed the prior 1.3--2.6s class of OI3
payload stall, but they do not close ADR-0007 comparative latency.

## Rejected candidate: TCP payload timer kick

The S199 timer-kick candidate was rejected because it changed transport
behavior instead of solving the actual wake condition. The app timed out on all
four OI3 requests even though the fixture received GETs. Native logs showed an
immediate ACK-only TUN output after payload submission and Direct send still
waited for the later connector deadline.

Do not reintroduce a generic lwIP timer-kick as the E2 latency fix.

## Remaining hotspot: dispatcher -> owner handoff

After the connector write-interest fix, OI3 still fails the comparative E2
latency gate. The remaining cost is concentrated before owner-local flow
processing, not in HTTP response receipt.

The S203/S204 wall-time probes show that TUN input reaches the multi dispatcher
quickly, but the same packet can take roughly 160--500ms before it is enqueued
on the selected owner:

- S203 examples:
  - `multi-ingress 1787692470671` -> `tun-queue enqueue 1787692470830`
    (~159ms)
  - `1787692472422` -> `1787692472867` (~445ms)
  - `1787692474405` -> `1787692474899` (~494ms)
- S204 examples after the target-trigger candidate:
  - `1787692709644` -> `1787692709885` (~241ms)
  - `1787692711458` -> `1787692711916` (~458ms)
  - `1787692713498` -> `1787692713946` (~448ms)

The target-trigger wake experiment did not materially change this distribution,
so the next POC should not keep rerunning matched E2 without changing the owner
handoff seam.

## Implementation state

Current kept changes:

- `experiments/vpp-nfq-poc/overlay/src/plugins/hev_external_driver_poc/owner_inline_oi3.c`
  keeps `connector_write_pending`, connector wake wall-time/revent logs, TCP
  payload length logging, and the multi-ingress/tun-queue timing probes.
- `experiments/vpp-nfq-poc/android/vpn-lite/src/main/java/com/sakamoto/snort/vpnlite/SnortVpnService.java`
  logs per-request connect/write/first-byte/done timing.
- `experiments/vpp-nfq-poc/scripts/tests/test_verify_s171_e2_oi3_direct_sample.py`
  guards the rejected timer-kick and the required connector write-interest
  shape.

Current build pitfall:

- The checked-in overlay is authoritative.
- The generated build-source copy under `build-output/android-vpp-runtime/source/...`
  can retain rejected candidate code between runs.
- Before any device rebuild, copy the overlay `owner_inline_oi3.c` into the
  build-source path; otherwise the next APK can accidentally include stale
  target-trigger code.

## Next POC direction

The next focused POC should target the dispatcher -> owner wake/handoff seam,
not UID drop, app HTTP logic, or generic connector polling.

A plausible next design is a per-owner OS wake/record handoff path for
latency-critical TUN packets, avoiding reliance on the current VPP frame queue
idle-wake behavior for the first SYN/payload admission path. The acceptance
gate remains matched Direct/HEV/OI3 E2 latency under the ADR-0007 comparative
threshold, plus unchanged cleanup/correctness validity.
