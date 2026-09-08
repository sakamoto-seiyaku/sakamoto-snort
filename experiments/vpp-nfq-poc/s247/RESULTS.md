# S247 Pixel resource-boundary results

Executed 2026-09-07 23:37–23:51 Asia/Taipei. **18 PASS runs across 13 registered cells; one retained HOLD followed by a source correction and fresh-artifact regression.** PASS means the registered resource/settlement invariant, not universal packet delivery.

## Evidence and identity

Real Pixel 6a (`bluejay`, serial `28201JEGR0XPAJ`), Android 16, kernel 6.1.134; one actual VPP worker (thread index 1), owner generation 1 per run, real pinned HEV/lwIP and protected Android Direct UDP socket. Each evidence directory records device/kernel, installed-native SHA256, package identity, source manifest hash, app/broker/VPP traces and stop/process residue. `evidence-summary.json` contains the full resource counts, copy bytes/calls, allocation peaks and verifier hash for every run.

Immutable build snapshots live under `../work/s247/artifacts/<APK SHA256>/`: source/dirty manifest, VPP/HEV revisions, fresh plugin/HEV/APK binaries, source snapshots and base recipes. `archive-files.sha256.json` seals the complete archive including the recipes. Sources remain isolated from product code. The final corrected APK is `53c612ec6e65a0d0b0519e2f4fa9e4d60f607ef32c60d0812506173e7bce662b`.

## Observed boundaries

The allocator guard limits combined live PBUF (pool 4) and PBUF_POOL (pool 5) objects at the actual allocation point. Existing input-pbuf credits are independently limited. No new credit model or capacity default is introduced.

- Single/250 ms delayed real replies: input storage is released before normal output allocation; joint peak 2, input/output overlap 0. At pbuf=1, input is accepted and delivered to the endpoint, but the output header cannot be allocated. All replies time out; subsequent inputs remain admissible at the same limit. This is a no-delivery boundary, not successful transport.
- Controlled synchronous `udp_sendto_ctx`: pbuf=1 rejects the controlled payload allocation; pbuf=2 retains input plus payload but rejects the output header; pbuf=4 produces actual callback output at joint peak 3. This is explicitly controlled real lwIP output, not a claim about ordinary Direct timing.
- Three real app datagrams queued before the first HEV task step: pbuf=4 with credit=1/2/4 admits 1/2/3 initial packets, rejects only excess packets, and accepts a fourth recovery packet in the same session/generation. Joint peaks are 2/3/4. Paired pbuf/credit=1/1 remains a no-delivery boundary; 2/2 can lose an earlier reply to header pressure, then deliver the next/recovery reply after storage drains.
- Overlap stop is requested while one input and two output/protocol pbufs are actually live. It exits callback/input first, lets the native return frame drain, and closes the session without sending the queued second input. Final corrected run has no pool, credit, UDP-frame, native buffer or VPP-process residue.

## Retained contradiction and correction

`234620-stop-p4-c4` is **HOLD (F247-01)**. During stop, HEV's external-task drain allowed the UDP splice to send the queued input and allocate another native output frame after the stop barrier checked residue. The cleanup line reported buffers 8/7 and residue 1; that late frame ran after TUN closure. Eventual process exit does not turn this into PASS.

The isolated fixture now checks the existing owner's `started` state before each UDP forwarding iteration. Stop already clears this state before driving teardown, so the queued datagram is released by session destruction without new forwarding. No topology, storage ownership or acceptance threshold changed. Fresh APK `53c612…` passed overlap-stop, single-packet limits 1/2/4, synchronous output and burst/recovery regression. The original HOLD remains in the summary.

## Run matrix

| Evidence suffix | Pattern | pbuf / credit | Joint / overlap peak | Accepted input | App results | Result |
| --- | --- | --- | --- | --- | --- | --- |
| 233710-single-p4-c4 | single | 4 / 4 | 2 / 0 | [1, 2, 3] | 1:EXACT,2:EXACT,3:EXACT | PASS |
| 233915-single-p1-c4 | single | 1 / 4 | 1 / 0 | [1, 2, 3] | 1:TIMEOUT,2:TIMEOUT,3:TIMEOUT | PASS |
| 234158-single-p2-c4 | single | 2 / 4 | 2 / 0 | [1, 2, 3] | 1:EXACT,2:EXACT,3:EXACT | PASS |
| 234306-sync-p1-c4 | sync | 1 / 4 | 1 / 0 | [1, 2, 3] | 1:TIMEOUT,2:TIMEOUT,3:TIMEOUT | PASS |
| 234328-sync-p2-c4 | sync | 2 / 4 | 2 / 2 | [1, 2, 3] | 1:EXACT,2:EXACT,3:EXACT | PASS |
| 234339-sync-p4-c4 | sync | 4 / 4 | 3 / 3 | [1, 2, 3] | 1:EXACT,2:EXACT,3:EXACT | PASS |
| 234419-burst-p4-c1 | burst | 4 / 1 | 2 / 0 | [1, 4] | 1:EXACT,2:TIMEOUT,3:TIMEOUT,4:EXACT | PASS |
| 234433-burst-p4-c2 | burst | 4 / 2 | 3 / 3 | [1, 2, 4] | 1:EXACT,2:EXACT,3:TIMEOUT,4:EXACT | PASS |
| 234446-burst-p4-c4 | burst | 4 / 4 | 4 / 4 | [1, 2, 3, 4] | 1:EXACT,2:EXACT,3:EXACT,4:EXACT | PASS |
| 234537-burst-p1-c1 | burst | 1 / 1 | 1 / 0 | [1, 4] | 1:TIMEOUT,2:TIMEOUT,3:TIMEOUT,4:TIMEOUT | PASS |
| 234555-burst-p2-c2 | burst | 2 / 2 | 2 / 2 | [1, 2, 4] | 1:TIMEOUT,2:EXACT,3:TIMEOUT,4:EXACT | PASS |
| 234608-delay-p4-c4 | delay | 4 / 4 | 2 / 0 | [1, 2, 3] | 1:EXACT,2:EXACT,3:EXACT | PASS |
| 234620-stop-p4-c4 | stop | 4 / 4 | 3 / 3 | [1, 2] | 1:EXACT,2:TIMEOUT | HOLD |
| 234925-stop-p4-c4 | stop | 4 / 4 | 3 / 3 | [1, 2] | 1:EXACT,2:TIMEOUT | PASS |
| 234958-single-p1-c4 | single | 1 / 4 | 1 / 0 | [1, 2, 3] | 1:TIMEOUT,2:TIMEOUT,3:TIMEOUT | PASS |
| 235042-single-p2-c4 | single | 2 / 4 | 2 / 0 | [1, 2, 3] | 1:EXACT,2:EXACT,3:EXACT | PASS |
| 235053-single-p4-c4 | single | 4 / 4 | 2 / 0 | [1, 2, 3] | 1:EXACT,2:EXACT,3:EXACT | PASS |
| 235104-sync-p4-c4 | sync | 4 / 4 | 3 / 3 | [1, 2, 3] | 1:EXACT,2:EXACT,3:EXACT | PASS |
| 235115-burst-p4-c2 | burst | 4 / 2 | 3 / 3 | [1, 2, 4] | 1:EXACT,2:EXACT,3:TIMEOUT,4:EXACT | PASS |

## Scope and replay

`prepare.py` creates the separate experimental source tree, `build.py` builds and seals it, `run.py PATTERN --pbuf N --credit N [--install]` uses only repo `./dev/adb` on the identified Pixel, and `verify.py EVIDENCE...` checks actual lifetimes and conservation. See preregistration in `README.md`. Normal and controlled paths are labelled in every trace. The narrow app VPN route and loopback destination projection, extra staging copies and single-owner UDP4 limits of S245/S246 still apply.

This proves local resource boundaries and stop settlement only. It does not prove product readiness, production capacity, throughput, TCP retransmission, IPv6, W2 or full underlay migration/crash recovery. Other devices were untouched. The experiment service was stopped and no VPP process remained.
