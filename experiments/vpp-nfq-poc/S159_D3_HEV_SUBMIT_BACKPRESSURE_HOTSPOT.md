# S159 D3 HEV submit backpressure hotspot

Date: 2026-08-24
Status: `HISTORICAL_SUPERSEDED_BY_S160`
Scope: Pixel `vpp-oi3-multi`, D3 bounded packet/credit/buffer overload

> Historical interruption record. S160 maps `-5` to category-1 inflight-pbuf
> credit exhaustion and adds explicit overload/drop accounting; see
> [`S160_D3_OVERLOAD_RECOVERY_EXECUTION_JOURNAL.md`](S160_D3_OVERLOAD_RECOVERY_EXECUTION_JOURNAL.md)
> for the current status. D3 remains paused there because a separate,
> reproducible full-route ambient TCP/5228 owner-stop hotspot prevents a clean
> post-pressure recovery assertion.

## Result

The first D3 pressure run against the two-owner artifact made a negative HEV
`submit()` return fatal and stopped the session.  That local ownership bug was
changed so a negative return is classified as an owner-local `owner-submit`
rejection, the pending copy is retired exactly once, and the VPP buffer is
still freed.  A single identical bounded rerun was then executed after
rebuilding and reinstalling the artifact.

The rerun did not pass D3:

- Four concurrent AppA `EMIT` intents offered the same IPv4/UDP tuple
  (`10.111.0.2:47004 -> 1.1.1.1:53`), each with `repeat=16` (64 attempted
  datagrams).  AppA recorded all 64 sends as `bound`/`udp_datagram_sent` on
  VPN handle `815154515981`; no AppA bind/UID/ADB failure occurred.
- The owner accepted 15 `submit()` calls (`result=0`), then returned `-5` for
  49 calls.  All 49 were explicitly logged as
  `oi4 multi-admission ... reason=owner-submit`.
- The owner did not produce a reply: `output=0`, `direct=0`,
  `endpoint=0/0`.  The bounded flow ended with
  `oi3_cleanup result=FAIL ... error=tun-flow-timeout-no-reply`.
- Settlement itself remained exact: `broker=1/1`, `buffers=74/74`,
  `residue=0`, and no owner-stop or cross-owner mutation was observed.

This is therefore not an Android permission, ADB transport, UID lookup, LAN,
or broker-completion hotspot.  It is a runtime contract gap at the
`FlowStackOwner` submit boundary: the selected HEV credit/backpressure result
(`-5`, whose symbolic meaning is not exposed by the current dlsym seam) is
treated as a permanent packet drop, while the accepted portion of the burst
still does not make progress to a direct reply before the bounded timeout.
The accounting correction removed the fatal owner teardown but did not define
retry, credit release, or a conservative admission envelope for this result.
S160 supplies the bounded owner-local drop/credit ledger semantics; the
remaining recovery gate is documented separately because full-route ambient
traffic can stop an owner before the recovery probe.

## Evidence

- Plugin SHA-256: `21cdf660981a087ee625ffd835f17491a208c76f0dadb3eba7896298c02de177`
- APK SHA-256: `4a02b3fffd66082f522c6a807bba213827098b5fb4572b51e6d91eac02aabba5`
- Device serial: `28201JEGR0XPAJ`
- Native stdout: [`evidence/s159-d3-fixed/vpp-stdout.log`](evidence/s159-d3-fixed/vpp-stdout.log)
  (SHA-256 `daac2511cd08eee7dab0f387855f13f96b1d9270af90a3b15cb80adec47eb884`)
- AppA runtime: [`evidence/s159-d3-fixed/app-runtime.jsonl`](evidence/s159-d3-fixed/app-runtime.jsonl)
  (SHA-256 `c1339f33b261ff53912f4b67f53aaa10e5959537d14789edba5851fca64b12ce`)

The startup log confirms the intended seam:
`oi4 multi enabled owners=2 target-a=1 target-b=2 fd=3`.
The same log contains expected pre-admission rejects for Android IPv6
Hop-by-Hop/ICMP control frames (`reason=invalid-tuple`); those are outside the
registered plain TCP/UDP D3 envelope and are unrelated to this failure.

## Decision and required follow-up

Stop D3 pressure attempts here.  Do not report D3 as `PASS`, and do not start
E1/E2 pressure/soak work on this artifact.  The next engineering change must
be made at the HEV adapter seam and then validated with one fresh bounded
rerun:

1. Recover the pinned HEV `flow_stack_owner_submit` contract and map `-5` to a
   named condition (transient credit/backpressure versus permanent reject).
2. Implement a bounded per-owner policy: retry only when the contract permits,
   or reject before HEV with explicit credit/queue accounting; never silently
   turn accepted work into a no-reply timeout.
3. Add a recovery assertion proving a subsequent normal UDP flow receives a
   valid DNS reply after the bounded pressure outcome.

Until that seam is corrected, D3 is `BLOCKED_BY_RUNTIME_BACKPRESSURE` and the
dependent E batch remains paused.  D1 isolation and D2 owner-busy evidence are
still valid within their tested envelope; this finding does not reopen the
already-closed C1/C2 lifecycle corrections.
