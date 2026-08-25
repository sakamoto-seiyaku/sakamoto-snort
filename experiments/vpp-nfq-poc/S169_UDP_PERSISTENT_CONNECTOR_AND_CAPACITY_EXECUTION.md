# S169 UDP persistent connector correction and 4-owner capacity closure

Date: 2026-08-25

Scope: Pixel `vpp-oi3-multi`, same-package preflighted WSL2 LAN UDP echo
fixture `192.168.4.5:42185`, repo-local `./dev/adb`, rebuilt OI3 plugin,
rebuilt HEV owner-context library, rebuilt four-owner OI3 plugin, and rebuilt
VPN Lite APK.

## Result

The active UDP closed-echo hotspot changed category twice and is now closed for
the tested four-owner UDP envelope.

- VPN-F045 is closed for the current two-owner UDP closed-echo envelope. The
  UDP lifecycle blocker was the combination of OI3 per-datagram state and HEV's
  UDP connector returning terminal status after one protected response. OI3 now
  has an explicit per-datagram inflight latch, and the HEV owner-context patch
  keeps the UDP connector session persistent across datagrams.
- VPN-F046 was a real POC design/capacity mismatch, not an ADB, endpoint, heap,
  or UDP lifecycle failure. The registered 4-flow closed echo cell exceeded the
  previous final-topology POC because OI4 multi started two owners, and each
  owner admitted one active UDP canonical hash. Extra concurrent flow hashes
  routed to a busy owner were deliberately rejected as `owner-busy`.
- VPN-F046 is now closed for the selected bounded design: four owner contexts,
  still one active UDP canonical hash per owner. The 4-flow Pixel/WSL2 run
  `127931250090287` passed with four active owners, zero app errors, zero
  `owner-busy`/multi-admission rejects, and four clean owner teardowns.

## Build provenance

### F045 two-owner UDP lifecycle closure

- APK: `c15604413b3cb234a958b42d5c23892228fb4cd2f761af8ce2790e3ce1e48a61`
- HEV owner-context library:
  `37481673d6547c5f2a178de04bf4c4b5f60ba6ce1bed7c7cba1cd22b606ac96d`
- OI3 plugin:
  `60243ba744dee0201e99b1d350cde7cfea807dad7933e76f180bffcbac7423ff`

### F046 four-owner capacity closure

- APK: `96726fa8e56d74e731105c71568735af338f74fcb06cc067eff00b7525b07179`
- HEV owner-context library:
  `37481673d6547c5f2a178de04bf4c4b5f60ba6ce1bed7c7cba1cd22b606ac96d`
- OI3 plugin:
  `b97c57a853a31e0bd7451dd4216519553091954ba45412b3b3def0825dda5951`

## Evidence

### 1-flow UDP closed echo

Run `86632836943396`, `flows=1`, `sourcePortBase=43000`,
`udpClosedTimeoutMs=1000`.

- App: `sent=834 received=834 errors=0 late=0`.
- Host fixture: `udp_total` increased from `3` to `1253`.
- VPP: repeated `tun-udp-window submit-next`, `direct-send`,
  `tun-output result=OK`, and `tun-udp-window complete`; no recurrence of the
  earlier `tasks=0` one-shot stall.

This proves the UDP lifecycle/connector fix works for one canonical flow.

### 2-flow UDP closed echo

Run `139608275148756`, `flows=2`, `sourcePortBase=43000`,
`udpClosedTimeoutMs=1000`.

- App flow 0 / port `43000`: `sent=852 received=852 errors=0`.
- App flow 1 / port `43001`: `sent=850 received=850 errors=0`.
- App summary: `sent=1702 received=1702 errors=0 late=0`.
- Host fixture: `udp_total` increased from `3890` to `6455`.
- VPP: both owners produced `tun-output result=OK`,
  `tun-udp-window complete`, `oi3_cleanup result=PASS`, and zero residue.

This proves the current two-owner envelope can carry one active UDP flow per
owner after the persistent connector correction.

### Historical 2-owner 4-flow UDP closed echo

Run `83202807976373`, `flows=4`, `sourcePortBase=43100`,
`udpClosedTimeoutMs=1000`.

- App flow `43100`: `sent=883 received=883 errors=0`.
- App flow `43101`: `sent=10 received=0 errors=10`.
- App flow `43102`: `sent=10 received=0 errors=10`.
- App flow `43103`: `sent=880 received=880 errors=0`.
- App summary: `sent=1783 received=1763 errors=20`.
- Host fixture: `udp_total` increased from `1253` to `3890`.
- VPP: exactly 20 matching
  `oi4 multi-admission result=REJECT ... reason=owner-busy` records. The
  rejected hashes were routed to owners already holding active hashes for
  `43100` and `43103`. The two admitted flows continued to complete normally.

This is not the old UDP lifecycle bug and not a heap recurrence. It is the
current topology's admission contract doing what the code says: two owners, one
active UDP flow hash per owner.

### Four-owner 4-flow UDP closed echo

Run `127931250090287`, `flows=4`, `sourcePortBase=43000`,
`udpClosedTimeoutMs=1000`.

- App flow 0 / port `43000`: `sent=920 received=920 errors=0`.
- App flow 1 / port `43001`: `sent=919 received=919 errors=0`.
- App flow 2 / port `43002`: `sent=919 received=919 errors=0`.
- App flow 3 / port `43003`: `sent=940 received=940 errors=0`.
- App summary: `sent=3698 received=3698 errors=0 mismatches=0 unexpected=0
  late=0 reordered=0 fatalFlows=0 executorTimeout=false`.
- Host fixture stayed healthy and reached `udp_total=5499
  udp_bytes=351936`.
- VPP startup proved the selected topology:
  `oi4 multi enabled owners=4 target-a=1 target-b=2 target-c=3
  target-d=4`.
- VPP ingress covered all four owners: owner 0 received `1366` packets, owner 1
  received `1366`, owner 2 received `1372`, and owner 3 received `1395`.
- VPP F046-specific rejects were absent: zero `owner-busy`, zero
  `multi-admission result=REJECT`, and zero `reason=owner-busy`. The only
  generic `result=REJECT` records were `invalid-tuple` ambient IPv6/unsupported
  packets outside the registered UDP echo cell.
- All four owners emitted `oi3_cleanup result=PASS` with `submit-rejects=0`,
  `queue-rejects=0`, and `residue=0`.

This closes VPN-F046 for the bounded four-owner UDP closed-echo envelope.

## Design disposition

Do not use the historical two-owner 4-flow closed echo result as a correctness
failure of the persistent UDP connector fix. It was a POC registration/design
mismatch.

The selected design is four owner contexts, preserving the existing
one-active-UDP-hash-per-owner safety model. OI4 now has a bounded owner
capacity of four, and Android `vpp-oi3-multi` starts four workers with:

```text
target-thread-a 1 target-thread-b 2 target-thread-c 3 target-thread-d 4
```

The closure is deliberately bounded. It supports the registered four-flow UDP
closed echo envelope and unblocks the dependent D/E functional progression. It
does not claim production capacity constants, arbitrary flow count, soak,
performance, thermal behavior, or long lifecycle trend.
