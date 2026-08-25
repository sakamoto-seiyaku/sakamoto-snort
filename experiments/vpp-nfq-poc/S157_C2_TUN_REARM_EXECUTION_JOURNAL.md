# S157 C2 TUN re-arm correction execution journal

Date: 2026-08-24
Device: Pixel 6a (`28201JEGR0XPAJ`), Android 16
VPN package: `com.sakamoto.snort.vpnlite`
App package: `com.sakamoto.snort.poc.appa`

## Correction

S156 showed that the ordinary positive OI3 terminal path closed the detached
Android TUN fd after the first real flow.  The canonical and generated
`owner_inline_oi3.c` sources now separate per-flow settlement from VPN-session
teardown:

- successful positive TUN flows destroy only the HEV context, connector and
  per-flow broker watcher, then retain the TUN fd, TUN watcher and connector
  wake pipe;
- the next packet is admitted as a fresh `generation`/broker token and starts
  a new FlowStackOwner context;
- idle TUN readiness is limited to one packet and is blocked during a pending
  terminal drain;
- explicit stop, fault, underlay invalidation, negative cells and failed
  positive flows still close the TUN session;
- an idle re-armed fault is classified as `PASS_EXPECTED_FAULT` rather than
  falling through the positive-output gate.

The generated Android source was kept byte-identical to the canonical source.
The static suite ran 54 tests with `OK`; `git diff --check` passed.

## Same-session real dual-stack result

The final APK/plugin were installed through the repository-local `./dev/adb`.
The VPN was started once with full IPv4/IPv6 routes and AppA as the only
allowed package.  Two B1 DNS operations then ran without a VPN stop/start:

| Stage | Family/protocol | Source port | VPN handle | App result |
| --- | --- | ---: | ---: | --- |
| `S157-same-session-ip4` | IPv4/UDP DNS to `1.1.1.1:53` | 46430 | 767909875725 | `bound`, `udp_datagram_sent`, valid 61-byte DNS response |
| `S157-same-session-ip6` | IPv6/UDP DNS to `2606:4700:4700::1111:53` | 46431 | 767909875725 | `bound`, `udp_datagram_sent`, valid 61-byte DNS response |

The native log contains both terminal records and re-arm markers:

```text
oi3_cleanup result=PASS outcome=EXPECTED_DIRECT_REPLY generation=1 ... buffers=4/4 residue=0
oi3 tun-flow rearmed flow-count=1 next-generation=2 tun-fd=3 watcher=7
oi3_cleanup result=PASS outcome=EXPECTED_DIRECT_REPLY generation=2 ... buffers=8/8 residue=0
oi3 tun-flow rearmed flow-count=2 next-generation=3 tun-fd=3 watcher=7
```

Both records used the same Android `TRANSPORT_VPN` handle, proving the
previous S153/S155 `vpn_unavailable` second-flow boundary is corrected for this
registered IPv4→IPv6 cell.  The VPN was then explicitly stopped.

## Fault regression

With the corrected APK, a real AppA TCP flow to the bounded LAN fixture
`192.168.4.5:42086` was active while the supported MainActivity legacy bridge
issued the OI3 fault control.  AppA observed the expected stop-side abort, and
native cleanup settled the active flow as:

```text
oi3 fault-injected generation=1 epoch=1 action=bounded-stop-restart
oi3_cleanup result=PASS_EXPECTED_FAULT outcome=EXPECTED_DIRECT_REPLY generation=1
  fault-injected=1 output=3 handshake=1 direct=2 rewritten=3
  broker=1/1 buffers=9/9 residue=0 error=
```

An additional idle re-arm fault check emitted `PASS_EXPECTED_FAULT` with
`output=0 buffers=0/0 residue=0`, confirming the newly reachable idle branch is
also bounded.  The outcome string remains the existing direct-reply outcome
vocabulary; the decisive lifecycle classification is `PASS_EXPECTED_FAULT`.

## Artifact and evidence hashes

- plugin: `c7d0b00627202d0a3a1e39a4cf6603f7daa8cd3a91daeb6720b18bf06ab31ed1`
- APK: `c5001cfabbb9011df111780d87e1bab41f04aa04f733406a552e498ed8fda71f`
- AppA `files/debug/b1-runtime.jsonl` (post-run):
  `379f409309f2858cc3a2086051c778af4af27b6bdc1890e55a835dd570936d4b`
- native `vpp-stdout.log`:
  `18b0898dd7cba117d10bdf531a7c64942696cad01932a9e4ec1c73a35f736786`
- native `vpp-cli.log`:
  `1c769de2b1c039c7ec03fcae377d8e8f229487c1bd7c9d34b0caa4762ea0a42e`
- native `vpp-oi3-broker.log`:
  `259700be4192500c651b278e6a1339c05baf324dc9467ab998f7bf77bca2caf7`

## Decision

S156 `VPN-F035` is closed for the registered POC contract.  The corrected
claim is persistent same-session re-arm for successful positive real flows,
with explicit stop/fault/underlay teardown and fresh generation per flow.  It
does not claim arbitrary concurrent multi-owner capacity, seamless Android
underlay migration, or production service policy.
