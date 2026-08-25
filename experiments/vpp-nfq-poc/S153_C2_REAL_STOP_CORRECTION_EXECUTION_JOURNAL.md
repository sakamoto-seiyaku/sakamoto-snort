# S153 C2 real-stop correction execution journal

Date: 2026-08-24
Device: Pixel 6a (`28201JEGR0XPAJ`), Android 16
VpnLite APK: `2155cce9d56a9d5d6ca7735be48ecf6e9ac1e151655d97b03cb98c3845d61b6a`
OI3 plugin: `aa6ca47df6dd953a06fdd50cf8cedfe39af65c3e42ecf8474659b18cd70ee004`
HEV arm64: `88cc920e6aca9bf1b999372d40fc895077208ea545d918ac2b22471eeabffc04`

## Correction

The S152 hotspot was corrected in the owner-inline plugin.  An explicit CLI
`sakamoto-oi3 stop` now records an immutable `normal_stop_requested` reason,
uses the distinct `EXPECTED_STOP` outcome, and emits
`PASS_EXPECTED_STOP` only after owner-token reclamation and resource checks.
The positive direct-reply gate no longer overrides an explicit stop.  Fault,
underlay invalidation, negative transport cells, and direct reply retain their
separate classifiers.

The correction has a static regression suite (`49 tests OK`) and the packaged
plugin contains `EXPECTED_STOP`, `PASS_EXPECTED_STOP`, and
`normal-stop-requested` strings.

## Real Pixel rerun

The VPN was started with `vpp-oi3`, `allowedPackage=com.sakamoto.snort.poc.appa`,
and IPv6 enabled.  A real AppA B1 TCP DNS flow was sent to the WSL2 LAN
fixture `192.168.4.5:42086`, whose accepted socket waits without a reply.  The
stage was `S152-real-normal-stop-fixed`, source port `46422`, VPN Network
handle `737845104653`.  In the same device command the OI3 `stop` control was
issued one second after the flow started.

AppA reached the real VPN path and recorded the stop-side abort:

```text
bind_result=bound tuple_attempted=true
send_connect_outcome=tcp_connect_failed
error=Software caused connection abort
```

Native terminal evidence:

```text
oi3_cleanup result=PASS_EXPECTED_STOP outcome=EXPECTED_STOP generation=1 epoch=1
  fault-injected=0 normal-stop-requested=1 output=3 handshake=1 direct=2 rewritten=3
  endpoint=0/0 broker=1/1 duplicate-close=0 underlay-invalidated=0
  transport-failures=0 infrastructure-failures=0 buffers=10/10 residue=0 error=
```

Java/Native control evidence reports `sakamoto-oi3 stop rc=0`.  The durable
log hashes are:

- `vpp-stdout.log`: `f0e4a7f116a9f4ba62b9b527e120a1d8dbba145268135a68eb7c6391c7e65a15`
- `vpp-cli.log`: `1c8684caa915cc6fb9c0d4855bfa247e7f4ea4d4d1917bc9fa445ae2112ddd87`

## Result and boundary

S152's normal-stop classification hotspot is **CLOSED_FOR_POC**.  This closes
only the normal-stop contract correction.  C2 remains open until the same
real-B1 setup proves injected fault, one bounded restart, fresh traffic after
restart, and no stale revival.  The device VPN process and LAN fixture were
stopped after the run.
