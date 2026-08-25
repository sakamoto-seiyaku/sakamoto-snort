# S160 D3 overload/recovery execution journal

Date: 2026-08-24
Status: `HISTORICAL_SUPERSEDED_BY_S161`
Scope: Pixel `vpp-oi3-multi`, HEV submit backpressure, owner-local overload,
post-overload recovery

## What was fixed before this run

The staged HEV arm64 disassembly identifies `flow_stack_owner_submit()` return
`-5` as category-1 inflight-pbuf credit exhaustion: category 0 reserve failure
returns `-4`; category 1 reserve failure returns `-5`, releases category 0,
and does not corrupt the owner context.  The OI3 adapter now settles that
pending copy exactly once, records `owner-submit`, and classifies a bounded
multi-owner UDP outcome as `EXPECTED_PACKET_OVERLOAD`.

The earlier pre-fix log also exposed a second local seam: a 16-entry
owner-local pending queue was upgraded to `finish_requested` and
`OI3 TUN pending queue full`.  That violated ADR 0007's rule that exhausted
packet-handoff/buffer credit discards only the current packet without implicit
flow termination.  The adapter now records `queue-rejects` and keeps a
multi-owner UDP owner alive; TCP and non-multi paths retain the infrastructure
failure behavior.

## Matched artifact

- Device: `28201JEGR0XPAJ`
- VPP core: `b7917ff34897ca731ba2a800b7c04762ec27feb3a0f9bf6688572a1a53acc132`
- staged OI3 plugin: `0e259d99b99dd8f2047520155fa0c0614d82a04cf14cc3282cd1029ae7df163e`
- HEV arm64 library: `88cc920e6aca9bf1b999372d40fc895077208ea545d918ac2b22471eeabffc04`
- APK: `f8c2562c06e87aa8581313ef7d2b8457ef1d306af4cd59f911543c5447509a2e`
- Plugin load was confirmed by `show plugins` before the run.

## Effective D3 pressure result

Four AppA `EMIT` intents offered the same IPv4/UDP tuple
(`10.111.0.2:47004 -> 1.1.1.1:53`), each with `repeat=16` (64 Android sends,
all `bound`/`udp_datagram_sent`).  Ambient Android traffic also arrived; its
owner is recorded separately below.

The AppA owner that received the D3 tuple completed three bounded generations:

| generation | HEV submit rejects | queue rejects | cleanup | buffers | rearm |
| --- | ---: | ---: | --- | --- | --- |
| 1 | 17 | 0 | `PASS_EXPECTED_OVERLOAD` | `42/42`, residue `0` | yes |
| 2 | 7 | 0 | `PASS_EXPECTED_OVERLOAD` | `62/62`, residue `0` | yes |
| 3 | 4 | 0 | `PASS_EXPECTED_OVERLOAD` | `85/85`, residue `0` | yes |

Each generation had `broker=1/1`, no transport/infrastructure failure, and
`c1 used=8 high=8` with releases settling after cleanup.  The pre-queue-fix
failure (`OI3 TUN pending queue full`) is retained as
[`vpp-prequeuefix.log`](evidence/s160-d3-overload-recovery/vpp-prequeuefix.log)
 (SHA-256 `674110bf6b59b32f10a17bbbca1f1af01bbd425c47884ce3fe82edaba38a0c49`)
and is not present in the corrected run.

## Recovery gate and reproducible blocker

The post-pressure B1 DNS probe reached owner 1 (`broker=1/1`, submit result
`0`, connector connect and direct-send succeeded), but the device received no
DNS reply.  The owner ended with `tun-flow-timeout-no-reply`; its ledger was
already `c0 used=0`, `c1 used=0`, and VPP buffers were `90/90`, residue `0`.

This could not be attributed to D3 alone.  A fresh multi-owner VPN with no D3
pressure was started and the same B1 probe was sent immediately.  Android first
delivered an ambient TCP flow to port `5228`; it repeatedly reached
`output=1`, `direct=0`, then ended as
`tun-flow-output-not-a-direct-return`.  The owner entered `owner-stopped`, and
the B1 probe was consequently unable to obtain a valid reply.  The same
ambient-flow failure was reproduced in more than one fresh multi-owner run;
it is independent of HEV credit exhaustion and leaves no buffer residue.

Evidence:

- D3 VPP log: [`vpp-stdout.log`](evidence/s160-d3-overload-recovery/vpp-stdout.log)
  (SHA-256 `658605bd0cc8169ae19992e838f80e83db79b88de186388d20de6962eb944eb4`)
- AppA pressure log: [`appa-a2-runtime.jsonl`](evidence/s160-d3-overload-recovery/appa-a2-runtime.jsonl)
  (SHA-256 `1caaac4e39aa6ccf89094a99ccd900c29e047738c1310db741f2198f2c925c0c`)
- Post-pressure B1: [`appa-b1-runtime.jsonl`](evidence/s160-d3-overload-recovery/appa-b1-runtime.jsonl)
  (SHA-256 `8e3d3cdc4988c7556ef630a4f8d983e75a6a29499f11d05cfe65b0264adf34db`)
- Fresh ambient baseline VPP log: [`vpp-baseline-ambient.log`](evidence/s160-ambient-full-route-hotspot/vpp-baseline-ambient.log)
  (SHA-256 `85afe5abfe43bad52ebe594d4b13a1e89a74ba0b30f13ad87962ef7d67fa3723`)
- Fresh ambient baseline B1: [`appa-b1-baseline.jsonl`](evidence/s160-ambient-full-route-hotspot/appa-b1-baseline.jsonl)
  (SHA-256 `82cac9ee5d7f63b23b14bbae36b81a161a5e0a85a19bae4aec030b699ee099a6`)

## Decision

This S160 interruption is historical. S161 added the missing pressure
completion barrier and closed the D3-to-recovery gate; see
[`S161_D3_TIMED_RECOVERY_EXECUTION_JOURNAL.md`](S161_D3_TIMED_RECOVERY_EXECUTION_JOURNAL.md).

Stop the D3-to-recovery gate and keep E1/E2 paused.  The HEV category-1
backpressure and owner-local queue semantics are corrected for the tested UDP
overload generations, but the required normal-flow recovery is not proven
because full-route multi mode has a reproducible ambient TCP/5228 owner-stop
hotspot.  The next change must isolate or explicitly classify ambient Android
flows (or use a controlled no-ambient route) before another D3 pressure attempt.
Do not count the ambient runs as UID/ADB/HEV-credit failures, and do not report
D3 as fully closed until a clean recovery probe returns a valid DNS response.
