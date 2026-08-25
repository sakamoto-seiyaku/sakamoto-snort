# S152 C2 real-stop classification hotspot

Date: 2026-08-24
Device: Pixel 6a (`28201JEGR0XPAJ`), Android 16
VpnLite APK: `272f860012307d021f5a97800f73727e486e13150dc6d5fbd5f58081d1393b2e`
OI3 plugin: `fbfeabfb29f650fd237ac6839148091c233b6ca107cf656219b681c4449dfdf1`
HEV arm64: `88cc920e6aca9bf1b999372d40fc895077208ea545d918ac2b22471eeabffc04`

Status: **RESOLVED_FOR_POC by S153; historical hotspot record**

The correction and real Pixel rerun are recorded in
[S153_C2_REAL_STOP_CORRECTION_EXECUTION_JOURNAL.md](S153_C2_REAL_STOP_CORRECTION_EXECUTION_JOURNAL.md).

## Finding

The first real AppA C2 stop cell reached the final OI3 path and proved that
the stop request aborts the in-flight socket, but the terminal classifier has
no normal-stop result contract.  The owner records a clean resource drain as
`FAIL outcome=EXPECTED_DIRECT_REPLY` because the positive-flow classifier still
requires a reply after an explicit stop.

This is a POC lifecycle-design defect, not an ADB or LAN-fixture failure.  The
cell is not promoted to C2 evidence, and fault/restart cells are paused until
the terminal contract is corrected and re-run.

## Reproduction

1. Start `vpp-oi3` with `allowedPackage=com.sakamoto.snort.poc.appa` and IPv4/6
   enabled.
2. From the real AppA UID, start B1 TCP DNS traffic to the WSL2 host fixture
   `192.168.4.5:42086`, whose accepted connection deliberately waits without a
   reply.  Stage: `C2-real-normal-tcp-active`, source port `46421`.
3. While the flow is active, issue the bounded JNI control `sakamoto-oi3 stop`.

The AppA record (in `files/debug/b1-runtime.jsonl`) shows a bound VPN socket,
an attempted tuple, and the expected stop-side abort:

```text
stage_id=C2-real-normal-tcp-active
bind_result=bound tuple_attempted=true
vpn_network_handle=733550137357
send_connect_outcome=tcp_connect_failed
error=Software caused connection abort
```

The native log shows the flow entered the owner, completed broker admission,
performed the handshake/direct-send path, then stopped with no resource leak:

```text
oi3 broker-request ... token=1 ... fd=25
oi3 broker-completion result=SUCCESS token=1 generation=1 owner=1
oi3 direct-send length=1
oi3_cleanup result=FAIL outcome=EXPECTED_DIRECT_REPLY generation=1 epoch=1
  fault-injected=0 output=1 handshake=1 direct=0 rewritten=1
  endpoint=0/0 broker=1/1 buffers=5/5 residue=0 error=
```

The durable native log hash is
`b8197cf1073dfb9603a7e1dc782013a9248ef625a57fe32a60bd3027b1bb7869` and the
CLI log hash is
`40aaf91ddc9c422db9a93893f2f78c5982bd258cad3aeb2cc33ee675c4e7640a`.

## Root cause

`sakamoto-oi3 stop` sets `phase=OI3_STOPPING` and `finish_requested=1`, then
queues the owner stop token.  `oi3_finish()` does not classify
`finish_requested` as a terminal reason.  For a real positive TUN flow it
therefore runs the ordinary direct-reply classifier, where `output_direct==0`
and `endpoint_replied==0` are treated as an unexpected failure.  Resource
settlement is correct in this run; the observable result contract is not.

The existing `PASS_EXPECTED_FAULT` and
`PASS_EXPECTED_UNDERLAY_INVALIDATION` branches do not cover an explicit normal
stop.  Reusing either branch would lose the distinction between a requested
stop, injected fault, and transport failure.

## Required correction before resuming C2

- Add an explicit stop reason/state (for example `normal_stop_requested`) that
  is set before the stop token is enqueued and is immutable for the generation.
- Emit a distinct terminal outcome such as `EXPECTED_STOP` and
  `PASS_EXPECTED_STOP` when the request was explicit, the owner drained once,
  and all per-flow resources settled (`buffers allocated == freed`, residue
  zero, no duplicate close, no stale-generation revival).
- Keep fault, underlay-invalidation, transport refusal/timeout, and positive
  direct-reply classifiers separate.
- Add a static regression test and re-run this exact real AppA stop cell before
  attempting C2 fault and bounded-restart cells.

Before S153, C2 remained **PARTIAL**; S149 controlled lifecycle evidence and
S151 C1 evidence were valid but did not substitute for this real-traffic gate.
S153 closes the normal-stop contract only.  Real fault/restart evidence is
still required for complete C2 closure.
