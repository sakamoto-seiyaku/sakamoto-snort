# S247 — simultaneous packet-storage and credit bounds

Registered 2026-09-07, before device execution. This is an isolated extension
of the S245/S246 experimental boundary, not product code. Pixel 6a serial
`28201JEGR0XPAJ`, one VPP worker, real HEV/lwIP, IPv4 UDP. Preserve the S246
correction that rejects only the current output datagram on ERR_MEM/ERR_IF.

## Questions and matrix

Measure the **actual** overlap among input PBUF_POOL objects, protocol/output
PBUF objects, independent VPP buffers and existing input pbuf credits. The
existing input pbuf credit does not account for all protocol/output allocations;
the experiment reports those as separate resources, without redesigning credits.

- Normal single-datagram progression and a 250 ms delayed real endpoint reply.
- Controlled synchronous real `udp_sendto_ctx` output while an input pbuf is
  still owned by lwIP. Label it independently from real Direct replies.
- A bounded burst of three packets submitted before the first HEV task step,
  followed by a recovery datagram after the burst has drained. The batching
  gate returns to VPP and waits for subsequent real ingress; it never blocks
  the worker or fabricates transport output.
- Independently vary the total live pbuf-object ceiling and the existing input
  pbuf-credit limit through 1, 2 and 4. A fixed, experimental allocator guard
  enforces the total PBUF + PBUF_POOL ceiling at the real allocation point.
  The other resource uses 4 for the independent comparisons; paired 1/1,
  2/2 and 4/4 cells expose combined bounds. These are not product defaults.
- A controlled stop requested from the synchronous output overlap window,
  then bounded drain of native frames and HEV-owned objects. No full network
  transition, crash/restart or W2 campaign is included.

The minimum viable pbuf ceiling is an **observed result**, not a predeclared
pass condition. At a ceiling incapable of forming a UDP reply, truthful
allocation rejection with reusable input capacity is a valid boundary finding;
it must not be labelled successful delivery. At a viable ceiling, a later
recovery datagram must succeed after temporary burst pressure drains, without
replacing the existing session. Limits stay fixed within a cell.

## Acceptance and stop rules

Each cell gets a freshly identified installed experiment artifact, at most
four actual app datagrams, 4 s receive timeout and a 30 s observation ceiling;
cleanup is bounded to 10 s. The overlap-stop cell intentionally interrupts
delivery and must show the overlap at request time and zero resources after
stop. A batching cell missing its registered packets fails validity rather
than silently running a smaller batch.

Require exact accepted payloads; source/dirty snapshots and artifact hashes;
owner/generation identity; per-allocation interval, copy and free evidence;
pool/credit/native peaks at or below each registered limit; precise rejection
location; no credit underflow, double free, leak or 32 consecutive zero-quanta
owner turns; and no VPP process after service stop. Classify raw app, real
Direct endpoint, synchronous lwIP injection and graph evidence separately.

Unexpected packet retention, loss of future receive progress, premature
destruction or unbounded wake activity is HOLD. Preserve the raw failure and
review a narrow correction against the existing contract before a new build
and rerun. Host-only checks and previous S245/S246 logs do not close S247.
