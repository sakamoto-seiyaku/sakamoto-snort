# S204--S214 E2 OI3 write-interest, owner-handoff, and first-payload hotspot

Date: 2026-08-26
Status: `PARTIAL_FIX_WITH_RESIDUAL_FIRST_PAYLOAD_WRITE_DRIVE_HOTSPOT`

## Decision

Do not import the current Android VPN/OI3 POC route directly into the
product/main stack yet.

The S199--S214 diagnosis split the previous E2 latency gap into three concrete
parts:

1. A connector write-interest defect that caused seconds-level TCP payload
   stalls. This part is corrected by `connector_write_pending`.
2. A multi-thread TUN dispatcher -> owner handoff and post-send Direct-read
   wake delay. This part is corrected/narrowed for the focused OI3 cell by the
   explicit owner/completion handoff path and the targeted post-Direct-send
   poll observer.
3. A remaining first-payload write-drive delay. In the current outliers, the
   first HTTP payload is submitted but Direct send does not happen until Android
   retransmits that payload roughly 200ms later. This part is still open and is
   the current E2 performance blocker.

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
| S205 | `evidence/s205-e2-oi3-owner-fd-handoff-20260826/`, run `20260826-053720-990568` | Explicit owner fd/TUN handoff candidate passed OI3 `4/4`, p95 `527ms`; p95 not closed. |
| S206 | `evidence/s206-e2-oi3-owner-event-handoff-20260826/`, run `20260826-054602-682259` | Completion handoff path passed OI3 `4/4`, p95 `522ms`; handoff/completion no longer explain the whole tail. |
| S207 | `evidence/s207-e2-direct-control-20260826/` | Direct control passed `4/4`, p95 `68ms`; fixture/device path healthy. |
| S208 | `evidence/s208-e2-hev-control-20260826/` | HEV control passed `4/4`, p95 `20ms`; fixture/device path healthy. |
| S209 | `evidence/s209-e2-oi3-tcp-nodelay-20260826/`, run `20260826-055233-228968` | `TCP_NODELAY` alone rejected as the latency fix; OI3 `4/4`, p95 `524ms`. |
| S211 | `evidence/s211-e2-oi3-post-send-direct-recv-guard-20260826/`, run `20260826-055822-728962` | Targeted post-Direct-send poll observer passed OI3 `4/4`, p50/p95/p99 `31/95/95ms`. |
| S212b | `evidence/s212b-e2-matched-after-post-send-read-observer-20260826/`, run `20260826-060037-266591` | Matched run passed Direct `8/8` p95 `86ms`, HEV `8/8` p95 `22ms`, OI3 `8/8` p95 `336ms`; residual remains. |
| S213 | `evidence/s213-e2-oi3-stale-wake-drain-20260826/`, run `20260826-060542-527708` | Stale-wake drain rejected; OI3 `8/8` but p95 worsened to `476ms`. Candidate reverted. |
| S214 | `evidence/s214-e2-oi3-post-send-revert-drain-20260826/`, run `20260826-060752-407437` | Reverted-drain baseline passed OI3 `8/8`, p50/p95/p99 `73/357/357ms`; residual stable. |

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

## Displaced hotspot: dispatcher -> owner handoff and post-send read wake

After the connector write-interest fix, OI3 still failed the comparative E2
latency gate. The S203/S204 evidence initially concentrated the cost before
owner-local flow processing.

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
so the next POC changed the owner handoff/completion seam instead of rerunning
matched E2 unchanged.

S205/S206 introduced explicit owner TUN and broker-completion handoff paths.
Those changes narrowed the ownership/completion question but did not close p95.
The later S211 observer then showed another delay class: after Direct send, OI3
needed a targeted Direct-read readiness observer. Guarding that observer with
`direct_recv_events` improved the focused OI3 cell to p50/p95/p99
`31/95/95ms`.

The current conclusion is that the broad "dispatcher -> owner handoff" label is
no longer precise enough for the remaining blocker. That earlier seam has been
processed into targeted owner/completion handoff and post-send read-wake fixes.

## Current remaining hotspot: first-payload write drive

Matched S212b and reverted S214 still fail the comparative OI3 latency gate.
The residual outliers have a different shape:

- The app connects and submits the first HTTP payload.
- Native receives/submits that payload.
- Direct send does not happen promptly.
- Android repeats the same payload roughly 200ms later.
- That duplicate payload triggers Direct send.
- After Direct send, the S211 observer drives Direct read promptly.

Therefore the next hotspot is not UID attribution, policy, HTTP fixture,
owner-handoff, broker completion, `TCP_NODELAY`, or post-send Direct read. It is
the connector/poll/owner re-entry path between first payload submit and first
Direct send.

Rejected candidates to avoid:

- Generic TCP payload timer kick: S199 produced `0/4` OI3 successes and app
  timeouts.
- `TCP_NODELAY` as sole fix: S209 still had p95 `524ms`.
- Stale connector wake drain: S213 worsened connect-tail behavior and was
  reverted before S214.

## Implementation state

Current kept changes:

- `experiments/vpp-nfq-poc/overlay/src/plugins/hev_external_driver_poc/owner_inline_oi3.c`
  keeps `connector_write_pending`, explicit owner TUN/completion handoff,
  connector wake wall-time/revent logs, TCP payload length logging, the
  multi-ingress/tun-queue timing probes, `TCP_NODELAY` socket hygiene, and the
  guarded post-Direct-send poll observer.
- `experiments/vpp-nfq-poc/android/vpn-lite/src/main/java/com/sakamoto/snort/vpnlite/SnortVpnService.java`
  logs per-request connect/write/first-byte/done timing.
- `experiments/vpp-nfq-poc/scripts/tests/test_verify_s171_e2_oi3_direct_sample.py`
  guards the rejected timer-kick, the required connector write-interest shape,
  the owner/completion handoff shape, `TCP_NODELAY`, and the guarded
  post-Direct-send observer.

Current build pitfall:

- The checked-in overlay is authoritative.
- The generated build-source copy under `build-output/android-vpp-runtime/source/...`
  can retain rejected candidate code between runs.
- Before any device rebuild, copy the overlay `owner_inline_oi3.c` into the
  build-source path; otherwise the next APK can accidentally include stale
  target-trigger code.

## Next POC direction

The next focused POC should target first-payload write drive, not UID drop, app
HTTP logic, generic connector polling, or the already rejected stale-wake drain.

A plausible next design is a targeted owner re-entry or write-readiness observer
when first payload is submitted while the connector still has pending write
work and no Direct send has occurred. The acceptance gate remains matched
Direct/HEV/OI3 E2 latency under the ADR-0007 comparative threshold, plus
unchanged cleanup/correctness validity.
