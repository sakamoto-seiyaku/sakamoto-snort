# S149 C2 Real-traffic Lifecycle Execution Journal

Date: 2026-08-24
Device: Pixel 6a (`28201JEGR0XPAJ`), Android 16
VpnLite APK: `720a844bef4049a5e0e564655be4ffa82dd8db32d9f2fd8ce283018b62d83099`
OI3 plugin: `8adefc0c9e7a32e00f50ac3b10405a41d1b734873734ec3c45649e7f7dbeb671`
HEV arm64: `88cc920e6aca9bf1b999372d40fc895077208ea545d918ac2b22471eeabffc04`

## Runner correction recorded before the final run

The first current-APK attempt exposed a runner-only timing defect.  The
synthetic `no-reply` cell can reach a valid `DONE` state in roughly 30 ms;
the runner's fixed 5 ms sleep therefore sometimes issued `stop` before broker
admission and reported `unexpected-no-reply broker=0/0`.  The same attempt
also showed that the existing cleanup mapping treated an explicitly injected
bounded fault as an ordinary failure, despite the S130 lifecycle contract.

The correction is deliberately narrow:

* normal-stop waits for `active + broker=1/1 + endpoint=1/0`, and accepts a
  clean naturally completed `DONE` cell as the equivalent bounded result;
* fault-stop issues `fault` immediately after the synchronous `run` command,
  avoiding a race with the short synthetic no-reply loop;
* native cleanup emits `PASS_EXPECTED_FAULT` for a fault-injected, error-free
  lifecycle termination.  B2's non-fault refusal/timeout/drop cells retain
  `PASS_EXPECTED_FAILURE` and their strict cell-specific classifiers.

The host Python suite (41 tests) and `git diff --check` passed before the
rebuild.  The VPP overlay was reapplied to the actual Android build source,
the arm64 plugin build passed with `CCACHE_DISABLE=1`, the APK build passed,
and streamed installation on the full Pixel serial succeeded.

## Final Pixel sequence

The app ran `vpp-oi5-controlled` with the controlled `10.200.0.0/24` route,
loopback test underlay, one owner on target thread 1, and no AppA injection.
The complete runner log is the app-private file
`files/vpp/logs/vpp-oi5-android.log` (SHA-256
`dea4d1fd3bb00296b8b90a9b51d46caaf98a9bdd8c9693730aa458b7682196bb`).
Native VPP stdout is `files/vpp/logs/vpp-stdout.log` (SHA-256
`8382c376403462b018e183bcd5715a16b5ec6caac73204f9dcc280dfc596eace`).

| Cell | Generation/epoch | Native terminal evidence | Verdict |
| --- | ---: | --- | --- |
| normal stop / no-reply | `1/1` | `PASS_EXPECTED_FAILURE`, `EXPECTED_TIMEOUT`, `endpoint=1/0`, `broker=1/1`, `output=0`, buffers `514/514`, residue `0`; runner recorded `natural-complete` | PASS |
| injected fault / no-reply | `2/2` | `PASS_EXPECTED_FAULT`, `EXPECTED_TIMEOUT`, `fault-injected=1`, `endpoint=0/0`, `broker=0/0`, buffers `516/516`, residue `0` | PASS |
| restart TCP4 | `3/3` | `PASS`, `EXPECTED_DIRECT_REPLY`, `output=2`, `handshake=1`, `direct=2`, `rewritten=2`, `endpoint=1/1`, `broker=1/1`, stale `1`, buffers `523/523`, residue `0` | PASS |
| underlay old UDP4 | `4/4` | `PASS`, `EXPECTED_DIRECT_REPLY`, `output=1`, `direct=1`, `rewritten=1`, `endpoint=1/1`, `broker=1/1`, buffers `532/532`, residue `0` | PASS |
| underlay new TCP4 | `5/5` | `PASS`, `EXPECTED_DIRECT_REPLY`, `output=2`, `handshake=1`, `direct=2`, `rewritten=2`, `endpoint=1/1`, `broker=1/1`, buffers `538/538`, residue `0` | PASS |

The native ledger recorded the four required transitions:

```text
old-generation=1 old-epoch=1 -> new-generation=2 new-epoch=2 old-tcp-reconnect=0 old-udp-reuse=0
old-generation=2 old-epoch=2 -> new-generation=3 new-epoch=3 old-tcp-reconnect=0 old-udp-reuse=0
old-generation=3 old-epoch=3 -> new-generation=4 new-epoch=4 old-tcp-reconnect=0 old-udp-reuse=0
old-generation=4 old-epoch=4 -> new-generation=5 new-epoch=5 old-tcp-reconnect=0 old-udp-reuse=0
```

The runner ended with `result=PASS command-failures=0 residue=0`.  No
late-generation mutation, duplicate broker close, transport/infrastructure
failure, or VPP buffer residue was recorded.

## C2 conclusion and boundary

C2 is **SUPPORTED for the controlled Pixel OI5 lifecycle cell**: bounded
normal completion, explicit fault termination, generation/epoch invalidation,
fresh TCP restart, and old-UDP/new-TCP sequencing all settle cleanly.  The
normal cell's natural completion is now an explicit runner contract rather
than an ambiguous stop race.

This does not yet prove a real Wi-Fi↔cellular Network-handle transition while
an external AppA flow is active (C1), multi-owner distribution, overload
limits, or repeated/long-soak resource trends.
