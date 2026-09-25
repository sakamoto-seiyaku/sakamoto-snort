# T07: CT conditions in the real unified rule path

Date: 2026-09-25. Scope: [SAKAMOTO-258](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/35ffb21f-3650-405a-93c7-911e9931eb9f).
Result: **PASS for T07 representative acceptance**. The
[interface contract](../interfaces/T07_CT_EXPRESSIONS.md) specifies the two CT
expression leaves, availability, conservative placement and ownership.

## Source and evidence

Evidence root: `build-output/t07-20260925/`. Accepted Linux and Android `build-c`
manifests bind Product source closure
`6f129ee294adae922746ebbbe5cad78b19a3cfde49dbcf48a314aae519382930`.
They retain source snapshots, dirty diff, build logs and artifact hashes. The
Android run independently checks the installed APK and every native library.
`acceptance-index.json` and `raw-manifest.json` index the evidence; original
Plane task, parent, comments and dependency readbacks remain local alongside it.

## Original acceptance mapping

| T07 criterion | Implementation and evidence |
| --- | --- |
| Existing owner-local CT state and flow direction; distinct device direction/current endpoints | The matcher receives the current `FlowRuntime` tracker result after observation. NEW, ESTABLISHED and INVALID have independent availability from ORIG/REPLY; an invalid new TCP candidate can expose INVALID without an entry or direction. Current packet endpoints never swap. Host covers both IP families, TCP/UDP and input-first/output-first flows. Linux's bidirectional loopback OUTPUT packets also demonstrate that device OUTPUT does not mean ORIG. |
| Static and dynamic rules compete in one effective application view under the same Rank | Compilation marks the complete UID view post-flow if any expression requires CT or flow direction. All competitors retain priority/order/stable identity ordering, including observe mode. Static-only views retain their existing early behavior. Both real platforms exercise higher-ranked dynamic DROP and higher-ranked static ALLOW. |
| Complete protected snapshot includes expressions, source and dependency data; failed publication retains the old view | Existing complete source API and SKRULE04 persistence carry the new leaves without a new wire structure. Compiled expressions, Rank and per-UID dependency data live in the same immutable bank. A packet holds one reader claim through observation and matching. Host rejects invalid operands, over-depth compilation and a publication callback failure without losing the old dynamic plan or its dependency metadata. Linux holds an old reader while a preconnected real API session saves/publishes a successor: the held packet uses the old DROP and the next packet uses the new observe result. |
| Preserve Flow/CT lifecycle; policy updates do not clear facts or terminate connections; post-flow DROP does not undo observation | Real traces join the same incarnation, monotonically increasing packet/side counters, CT facts and changed policy identities across drop/recovery. Observation occurs exactly once, before the post-flow decision. TCP sockets continue through retransmission and complete their original payload after rule recovery. Capacity bypass and infrastructure terminal outcomes retain their existing behavior. |
| Compare CT changes, both directions, mixed priorities and observe against a test-only reference | The independent recursive logical evaluator performs 1,385 complete-winner comparisons, with hand-calibrated CT availability and Rank cases followed by generated Boolean combinations. The separate wire verifier reconstructs saved logical source, fresh normal TCP/UDP facts and ordered winners; it does not load Product compiler/tracker tables. Query winner/action/counters must match a real packet-accounting prefix. |
| Representative verification with retained evidence and explicit platform limits | Final Host suite is 43/43. Linux independently verifies 67 real NFQUEUE packets: 64 logical hits, 14 actual drops and three unavailable-UID packets. Pixel independently verifies 71 Root TCP packets with 20 drops, and 65 VPN TCP packets with 14 drops. Twenty altered witness categories are rejected per platform. These counts describe this run, not a performance gate. |

## Verification details

Linux uses ordinary kernel TCP and UDP sockets in an isolated network namespace.
Both socket endpoints use the same controlled application UID. Seven sessions
cover state/direction changes, observe/enforce/recovery, static precedence and a
held-reader publication. Every selected packet is joined through raw admission,
owner-local CT observation, logical decision, the acquired snapshot identity,
actual NFQUEUE verdict and buffer release. Source/query snapshots retain the
complete rule/group/binding graph.

Pixel uses six real application TCP sessions, three per profile, against an
independent LAN echo endpoint. The CT-state and REPLY cases each transfer a
payload, change rules while retaining the socket, experience actual data drops,
then recover and finish all three 256-byte payloads and normal EOF. Static high
Rank ALLOW completes without a timeout despite a matching lower-ranked dynamic
DROP. VPN packets enter through TUN, traverse the normal owner-local transport
path and return through the shared graph. The probe does not construct packets,
protect sockets, select owners or forward data for Product. Screenshots/XML and
operation logs supplement the raw packet and endpoint evidence.

`linux-c-verified.json` and `pixel-c-verified.json` record independent results.
The corresponding `*-negative-witnesses.json` records rejection of altered
winner, Rank, mode/action, CT facts/direction, placement, observation counts,
Flow identity, source expression, query counters, runtime/artifact binding,
endpoint payload, completion and cleanup evidence. Root/VPN stop evidence
confirms zero native debt, closed owner resources, absent processes and no
Product hook/queue residue. The Pixel finishes stopped at generation 1523.

Focused CT/complete-source C tests also pass ASan/UBSan/LSan in the established
non-PIE Host setup (`sanitizer-summary.json`). This does not reclassify T05's
unexplained sanitizer anomaly or claim to fix T06's retained PIE initialization
failure. Java boundary checks, the real APK build and Rust profile tests are
included in the applicable build/Host verification.

The two independent review axes found no hard standards violations or spec
omissions. Two nonblocking duplication suggestions were resolved by sharing
operand widths and decision/failure recording. Both follow-up reviews found no
remaining actionable issue; final `build-c` repeats Host/Linux/Pixel acceptance
after those fixes. See local `review-results.md`.

## Retained failed attempts and limits

`linux-a` does not establish the held-reader race: creating its VAPI client at
publication time serialized the new-client path past the held worker. The
accepted `linux-c` uses a preconnected real Product API handle. Its successor
publication completes before the old reader releases, while the packet retains
its old complete snapshot. No alternative source writer or diagnostic policy
publisher supplies this result.

`pixel-a` does not pass the full matrix. In its VPN REPLY case, rule recovery was
already active and Flow identity remained intact, but the diagnostic socket
closed at its fixed 20-second read deadline before the next data retransmission.
The same scenario in `pixel-b` uses a bounded 45-second diagnostic deadline;
the next natural reply retransmission arrives about 20.7 seconds after the first
blocked reply and all three payloads complete on the same socket. The default
probe deadline stays 20 seconds; Product transport timers and policy semantics
are unchanged. `diagnosis-summary.json` joins both timelines. Final `pixel-c` repeats the same scenarios on the reviewed source. Neither failed
attempt is silently relabelled PASS, and these timings are not latency claims.

Device coverage is representative IPv4 TCP; Linux adds bidirectional IPv4 UDP.
Dual-stack, INVALID and detailed availability combinations are Host evidence.
This slice does not qualify broader protocol/state combinations on devices,
physical network handover, long-term expiry, loss-duration resilience, optimized
placement/caches, LPI/SNI, CPU/power or release readiness. Controlled VPN still
reports `protectionRunning=false`. Broader combined qualification remains T29.

```sh
rtk proxy python3 tests/host/product_static_reference_test.py
rtk proxy python3 tests/evidence/verify_t07_ct.py build-output/t07-20260925/linux-c
rtk proxy python3 tests/evidence/verify_t07_ct.py build-output/t07-20260925/pixel-c
```
