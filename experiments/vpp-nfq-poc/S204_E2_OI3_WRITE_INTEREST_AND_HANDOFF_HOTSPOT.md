# S204--S221 E2 OI3 write-interest, owner-handoff, and TCP lifecycle hotspot

Date: 2026-08-26
Status: `F072_MATCHED_DEVICE_STATE_CLOSED_E2_BUDGET_REMAINS`

## Decision

Do not import the current Android VPN/OI3 POC route directly into the
product/main stack yet as a completed product baseline.  The F072 lifecycle
hotspot is closed for the matched foreground/screen-off/forced-Doze HTTP
cells, but the broader ADR-0007 budget decision is still separate.

The S199--S214 diagnosis split the previous E2 latency gap into three concrete
parts:

1. A connector write-interest defect that caused seconds-level TCP payload
   stalls. This part is corrected by `connector_write_pending`.
2. A multi-thread TUN dispatcher -> owner handoff and post-send Direct-read
   wake delay. This part is corrected/narrowed for the focused OI3 cell by the
   explicit owner/completion handoff path and the targeted post-Direct-send
   poll observer.
3. A remaining TCP owner lifecycle/admission delay. In one outlier shape, the
   first HTTP payload is submitted but Direct send does not happen until Android
   retransmits that payload roughly 200ms later. In another shape, a successor
   SYN is deferred behind a completed TCP generation until stale tail /
   finish / rearm proceeds. S219/S220 introduced a focused candidate fix for
   this seam and passed narrow TCP correctness/reconnect cells. S221 reran the
   matched foreground Direct/HEV/OI3 8-request E2 comparison and closed this
   foreground F072 gate. S222/S223 then reran the screen-off and forced-Doze
   matched cells and closed the device-state F072 lifecycle gate.

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
| S215 | `evidence/s215-e2-oi3-f072-poll-instrument-20260826/`, run `20260826-061750-962864` | Instrumented OI3 `8/8`, p95 `566ms`; poll saw `write_pending`/`POLLOUT`, and slow requests showed successor SYN deferred behind completed-owner lifecycle. |
| S216 | `evidence/s216-e2-oi3-f072-finish-instrument-20260826/`, run `20260826-062214-952868` | Instrumented OI3 `8/8`, p95 `81ms`; useful as a green control only, not a fix. |
| S217 | `evidence/s217-e2-oi3-positive-reply-rearm-debug-20260826/`, run `20260826-062522-577059` | Early response-complete rearm candidate rejected: OI3 `6/8`, two `SocketTimeoutException`s, cleanup `9/2`, `owner-stopped` rejects. Candidate reverted. |
| S218 | `evidence/s218-e2-oi3-finish-after-buffer-debug-20260826/`, run `20260826-062746-118337` | Finish-after-buffer candidate preserved correctness (`8/8`, cleanup `12/0`) but did not fix latency; p95 `606ms`. Candidate reverted. |
| S219 | `evidence/s219-e2-oi3-deferred-owner-fd-debug-20260826/`, run `20260826-064414-513752` | Owner-local finish/rearm plus deferred successor-SYN owner-fd candidate passed focused long TCP: Direct `876/876`, OI3 `480/480`, OI3 cleanup `5/0`, `valid=1`. |
| S220 | `evidence/s220-e2-oi3-deferred-syn-reconnect-debug-20260826/`, run `20260826-064532-371054` | Same candidate passed focused reconnect TCP (`RECONNECT_EVERY=1`): Direct `623/623`, OI3 `337/337`, OI3 cleanup `6/0`, no app timeout/fatal/mismatch, `failures=0`. Logs show immediate owner-local finish/rearm avoided the observed deferred-SYN stall in this run; full matched E2 remains required. |
| S221 | `evidence/s221-e2-matched-f072-candidate-8req-foreground-20260826/`, run `20260826-065247-722050` | Matched foreground Direct/HEV/OI3 8-request comparison passed with `failureCount=0`: Direct `8/8` p95 `59ms`, HEV `8/8` p95 `11ms`, OI3 `8/8` p95 `24ms`, OI3 cleanup `12/0`. OI3 logs include `owner-busy-deferred`, `tcp-positive-fin-complete`, `tun-flow rearmed`, and `multi-deferred admit`; the previously hot lifecycle seam completed without timeout or cleanup failure. |
| S222 | `evidence/s222-e2-matched-f072-candidate-8req-screen-off-20260826/`, run `20260826-065949-263369` | Matched screen-off Direct/HEV/OI3 8-request comparison passed with `failureCount=0`: Direct `8/8` p95 `15ms`, HEV `8/8` p95 `10ms`, OI3 `8/8` p95 `27ms`, OI3 cleanup `12/0`. No timeout, owner-stopped reject, submit/queue reject, or cleanup failure. |
| S223 | `evidence/s223-e2-matched-f072-candidate-8req-forced-doze-20260826/`, run `20260826-070229-388301` | Matched forced-Doze Direct/HEV/OI3 8-request comparison passed with `failureCount=0`: Direct `8/8` p95 `18ms`, HEV `8/8` p95 `16ms`, OI3 `8/8` p95 `78ms`, OI3 cleanup `12/0`. This removes the prior S192 seconds-level Doze cliff, but leaves a separate ADR-0007 absolute/relative latency-budget decision. |

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

## Closed foreground hotspot: TCP owner lifecycle / admission

Matched S212b and reverted S214 still fail the comparative OI3 latency gate.
S215--S218 refine the shape: the residual is not a single missing socket wake.
It sits at the TCP owner lifecycle/admission boundary.

First observed shape:

- The app connects and submits the first HTTP payload.
- Native receives/submits that payload.
- Direct send does not happen promptly.
- Android repeats the same payload roughly 200ms later.
- That duplicate payload triggers Direct send.
- After Direct send, the S211 observer drives Direct read promptly.

Second observed shape:

- The previous request has completed its Direct response.
- The owner remains active for TCP tail/lifecycle settlement.
- A successor SYN for a new request reaches OI3 and is placed in
  `owner-busy-deferred`.
- The app's `connect()` latency includes the wait for stale tail / finish /
  rearm before broker request and SYN/ACK can proceed.

Therefore the next hotspot is not UID attribution, policy, HTTP fixture,
owner-handoff, broker completion, `TCP_NODELAY`, or post-send Direct read. It is
the TCP generation lifecycle design around completed response, stale tail,
successor SYN deferral, and first protected write drive.

Rejected candidates to avoid:

- Generic TCP payload timer kick: S199 produced `0/4` OI3 successes and app
  timeouts.
- `TCP_NODELAY` as sole fix: S209 still had p95 `524ms`.
- Stale connector wake drain: S213 worsened connect-tail behavior and was
  reverted before S214.
- Early response-complete rearm: S217 reduced latency for successful requests
  but broke correctness (`6/8`, `owner-stopped` rejects, cleanup `9/2`).
- Finish-after-buffer scheduling shortcut: S218 preserved correctness but left
  p95 at `606ms`.

S219/S220 changed the lifecycle seam instead of adding another generic wake:

- Deferred successor SYN packets now use the same owner-fd handoff mechanism as
  ordinary TUN packets, not the older VPP frame-queue path.
- Owner-local connector and TUN callbacks call an immediate finish/rearm helper
  once `finish_requested` is set and residue is zero, instead of waiting for a
  later token on the VPP side.
- Completed active TCP flow admission can force the active owner toward
  finish/rearm while preserving tail tombstoning.

The focused evidence was positive but still bounded after S220. S221 then kept
the candidate and reran the matched foreground Direct/HEV/OI3 8-request E2
matrix with comparison APK provenance:

- APK: `898906965d915b3540702ef3c5a838a5ba71dedeeb739b82f436debb6a8664e4`
- OI3 plugin: `ab5f1ab11b020f5e49e74ed95c97ec52cf795ed99ee545f2afb950d9f8e1ce15`
- HEV library: `420e67e71029888c3d6423b24a513bf6ed760fd159762903f22ee4235d016466`
- `tun_poc_plugin.so`: `d919117842eb41b6924693f7b79a2d20ee6ce22f8ab371b7995039c38b46d9bc`

S221 result:

- Direct: `8/8`, p50/p95/p99 `6/59/59ms`, `valid=1`.
- HEV: `8/8`, p50/p95/p99 `7/11/11ms`, `valid=1`.
- OI3: `8/8`, p50/p95/p99 `19/24/24ms`, cleanup `12/0`,
  `valid=1`.
- Manifest `failureCount=0`; installed APK/native artifact hashes matched the
  local comparison APK.
- OI3 logs include `owner-busy-deferred`, `tcp-positive-fin-complete`,
  `tun-flow rearmed`, and `multi-deferred admit`. Tail packets were rejected
  by tombstone as `reason=tcp-tail`; no `owner-stopped`, app timeout, submit
  reject, queue reject, or cleanup failure was observed.

This closed the foreground F072 lifecycle/admission gate. S222/S223 then reran
the older screen-off/forced-Doze E2 shapes with the same S221 comparison APK:

- S222 screen-off: Direct `8/8` p95 `15ms`, HEV `8/8` p95 `10ms`, OI3 `8/8`
  p95 `27ms`, OI3 cleanup `12/0`, `failureCount=0`.
- S223 forced-Doze: Direct `8/8` p95 `18ms`, HEV `8/8` p95 `16ms`, OI3 `8/8`
  p95 `78ms`, OI3 cleanup `12/0`, `failureCount=0`.
- Both OI3 runs showed owner-local finish/rearm and tail tombstoning markers
  without `owner-stopped`, app timeout, submit reject, queue reject, or cleanup
  failure.

Therefore F072 is closed for the matched foreground and device-state HTTP
cells. S223 still has a separate E2 budget question: OI3 forced-Doze p95 is
`78ms` versus HEV `16ms` and Direct `18ms`. ADR-0007 allows only a small
pre-registered absolute latency tolerance; this document does not reinterpret
that budget after seeing the data.

## Implementation state

Current kept changes:

- `experiments/vpp-nfq-poc/overlay/src/plugins/hev_external_driver_poc/owner_inline_oi3.c`
  keeps `connector_write_pending`, explicit owner TUN/completion handoff,
  connector wake wall-time/revent logs, TCP payload length logging, the
  multi-ingress/tun-queue timing probes, `TCP_NODELAY` socket hygiene, and the
  guarded post-Direct-send poll observer.  It also keeps the S219/S220 F072
  candidate: deferred successor-SYN owner-fd handoff plus owner-local
  finish-if-ready after direct owner callbacks.
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

The next focused POC should move from F072 debugging to the remaining E2
budget decision: quantify whether the S223 forced-Doze p95 delta is acceptable
under the pre-registered absolute tolerance, and gather the missing CPU/
thermal/power/soak evidence required by ADR-0007. Do not return to UID drop,
app HTTP logic, generic connector polling, or the already rejected wake patches
unless new evidence points there.

The lifecycle contract for the POC is now explicit: a completed response must
not hold successor SYN admission hostage, but old tail packets must still be
tombstoned without killing the owner. The acceptance gate remains matched
Direct/HEV/OI3 E2 latency under the ADR-0007 comparative threshold, plus
unchanged cleanup/correctness validity.
