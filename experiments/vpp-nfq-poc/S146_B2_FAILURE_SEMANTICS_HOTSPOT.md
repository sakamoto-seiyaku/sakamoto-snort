# S146 B2 Failure-Semantics Hotspot

Date: 2026-08-24
Status: **CLOSED_FOR_POC — correction and full B2 matrix passed**
Device: Pixel 6a (`28201JEGR0XPA`), Android 16
Artifact: VpnLite APK `cff40c3a838def2f6417c8bb04012839aba01efa1ea497aed5ec1fae76d72419`
OI3 plugin: `648b33c8d5d9429e5e0bb39de29a6c4af5d9b0655aaea0b3775457a77eedbfbf`

## Why the remaining POC run is paused

The B2 controlled IPv4 TCP refusal cell is the first negative full-TUN cell
after the corrected B1 positive path. It produced the expected transport
failure internally, but the durable cleanup verdict reported `FAIL`:

```text
cell=refused result=OK sent=22 received=0 destination=10.200.0.1:42080
oi3_cleanup result=FAIL outcome=EXPECTED_TRANSPORT_REFUSAL
  output=1 handshake=1 direct=0 rewritten=1 endpoint=0/0 accepted=0
  broker=1/1 transport-failures=1 infrastructure-failures=0
  buffers=5/5 residue=0 error=
```

The native classifier's refusal invariant is actually satisfied: the broker
was admitted and protected once, no endpoint reply was observed, no direct
reply was emitted, and a transport failure was recorded. The app-side line is
also ambiguous (`result=OK` with zero bytes received), so the artifact does
not provide one unambiguous `PASS`/expected-failure contract.

This is deterministic POC design behavior, not an intermittent underlay or
the S142/S143 short-TCP ACK hotspot. The same `oi3_finish()` path is shared by
the `refused`, `no-reply`, and `policy-drop` cells, so continuing the matrix
would create more misleading `FAIL` evidence rather than close B2.

## Root cause

`oi3_classify_result()` contains a cell-specific negative-outcome classifier,
but it is skipped for TUN mode. `oi3_finish()` then applies a positive-path
assertion to every TUN cell:

```c
if (tm->tun_mode &&
    (tm->tun_output_errors != 0 || tm->output_packets == 0 ||
     tm->output_direct == 0 || tm->return_rewritten == 0))
  cleanup_result = "FAIL";
```

`output_direct == 0` is required for a refused or no-reply result, and all
transport output is required to be zero for policy drop. Therefore an expected
negative outcome is forced to `FAIL` even when its cell invariant is met. The
app fixture compounds this by treating a connected-but-no-reply socket as
`OK` instead of recording a distinct transport outcome.

## Required design correction before resuming

1. Make cleanup verdict cell-aware. `PASS` for a negative cell must mean its
   expected invariant is satisfied; the positive `output_direct` and
   `return_rewritten` requirements must apply only to positive cells.
2. Run `oi3_classify_result()` (or an equivalent shared classifier) for TUN
   mode and emit one durable outcome field: `PASS_EXPECTED_FAILURE` or
   equivalent, never `FAIL` for an expected refusal/timeout/drop.
3. Make the app probe distinguish `CONNECT_REFUSED`, `NO_REPLY_TIMEOUT`, and
   `POLICY_DROP_NO_TRANSPORT`; do not emit `result=OK` for zero-byte failure
   outcomes.
4. Add a verifier that joins app/native cell, stage, and canonical tuple and
   checks the negative invariant plus zero residue. Only then rerun the
   complete B2 matrix and unblock C/D/E.

Until this correction is implemented and regression-tested, B2 and all
dependent POCs remain **not closed**. B1 positive IPv4/IPv6 TCP/UDP/DNS
evidence remains valid and is not withdrawn.

## Correction and closure

The native cleanup path was corrected to classify the three negative cells
before applying positive-path TUN assertions. It now emits
`PASS_EXPECTED_FAILURE` only when the cell-specific invariant is met:

- refusal: broker/protect `1/1`, endpoint `0/0`, direct `0`, transport failure
  present;
- no-reply: broker `1/1`, endpoint `1/0`, direct `0`, TUN deadline reached;
- policy-drop: output/direct/broker/transport/infrastructure all zero.

The App probe now emits `EXPECTED_TRANSPORT_FAILURE`,
`EXPECTED_NO_REPLY_TIMEOUT`, and `EXPECTED_POLICY_DROP_NO_TRANSPORT` instead
of ambiguous `OK`/zero-byte results.  The final APK
(`cb921108bf88b8a9ae77818378547bd11b3fa77fb7e0680191465e501820963e`) was
installed on the same Pixel and the complete B2 matrix passed; details are in
[`S147_B2_FAILURE_SEMANTICS_EXECUTION_JOURNAL.md`](S147_B2_FAILURE_SEMANTICS_EXECUTION_JOURNAL.md).

The original S146 pause was therefore a closed local POC design correction,
not an architecture interruption.  B2 is unblocked for the dependent C/D/E
POCs; the broader B1 whole-device claim remains bounded by the Evidence Gap
Map.
