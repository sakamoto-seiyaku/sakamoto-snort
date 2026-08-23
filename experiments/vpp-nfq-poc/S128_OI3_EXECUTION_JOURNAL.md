# SAKAMOTO-128 OI-3 execution journal

Date: 2026-08-23 (host Linux, x86_64; Pixel 6a arm64 runtime)

This is the bounded Direct Egress gate after OI-1 owner scheduling and OI-2
asynchronous bind/protect.  The question is whether a packet submitted to the
owner enters the shared `FlowStackOwner` graph, uses a protected original-
destination socket, and returns through the owner output/TUN path without a
second SOCKS/packet-port path.

## Artifact identity

```text
OI3 source (overlay)       7b7429acb410cb6cfa89e6f245218cc737a9f1bf5f721ed0b3a1d3147da728bf
OI3 source (work copy)     7b7429acb410cb6cfa89e6f245218cc737a9f1bf5f721ed0b3a1d3147da728bf
HEV/lwIP host library      bdebc1f33833d151df1ea719d52faa5d4d67881bb11208f874f61df5415d6685
host VPP                   5c4d1f707d2e7072a2da5974b76e3f7c43b13ecd823f2d76fbb91d5aa644908d
host OI3 plugin            f0af33506160b454d2192b4eddfca3eaff30ac91724012952b455c33754906b4
Android OI3 plugin         7a92ed0c3c9d9e9ad77f972219b48ce143f109fcae1b6b1c538493d4b2efd9eb
Android APK (debug)        cb5e6ffd80a66934206c9d62205c3a65f5db37c3f397bbd10997fb47c24545a9
matrix stdout              da751a9faa95a401d1727a62cc31448c27c4b00f084e37851c9f1404f883a729
matrix console             fc6853842a7a3ffe77092ea87837ec363a253d4095829fea85c8197a812876dc
real-TUN console           8831fb0e949204431bdefd00ce76e2edd95e17140f860b9389fabc07da1df2a5
real-TUN stdout            432b063329844918f6f32f60a2411eac7e14725004beeed1fa5ec7bed5cb1464
Android native probe       f18cf84ac39356063fcf9e990faa806ea9d1eeb79566a37e1fc44cf476ef9579
Android service            102f67cc35347d3434d7c6e486bf46132e8ca9e359658332d5a3dc8cead91457
```

The host plugin and arm64 plugin were rebuilt after the connector and TUN
canonicalization fixes.  The APK is `snort-vpn-lite-debug.apk` (the staged
runtime APK has the same digest).

## Host synthetic original-destination matrix

Command output is retained in `/tmp/s128-oi3-matrix-stdout-final-v2.txt` (SHA-256
`da751a9faa95a401d1727a62cc31448c27c4b00f084e37851c9f1404f883a729`); the VPP
control log is `/tmp/sakamoto-vpp-nfq-poc/s128-oi3-matrix-console.log` (SHA-256
`fc6853842a7a3ffe77092ea87837ec363a253d4095829fea85c8197a812876dc`).  Each cell
ran on worker 1 in a two-worker VPP and reached `active=0`, `state=DONE`, with
buffer accounting `allocated/freed` equal and `residue=0`.

| Cell | Result | Transport / path evidence |
| --- | --- | --- |
| UDP4 | `generation=1`, `packets=1`, `output=1`, `direct=1`, `rewritten=1`, endpoint `1/1`, broker bind/protect `1/1` | direct reply |
| TCP4 | `generation=2`, `packets=4`, `output=2`, `handshake=1`, `direct=2`, `rewritten=2`, endpoint `1/1`, accepted `1` | SYN/ACK, payload, FIN bounded exchange |
| UDP6 | `generation=3`, `packets=1`, `output=1`, `direct=1`, `rewritten=1`, endpoint `1/1`, broker `1/1` | direct reply |
| TCP6 | `generation=4`, `packets=4`, `output=2`, `handshake=1`, `direct=2`, `rewritten=2`, endpoint `1/1`, accepted `1` | direct reply |
| refused | `generation=5`, endpoint `0/0`, `direct=0`, transport failures `1` | expected `ECONNREFUSED`; no policy fallback |
| no-reply | `generation=6`, `steps=513`, endpoint `1/0`, accepted `0`, output `0`, direct `0` | expected UDP timeout; no policy fallback |
| policy-drop | `generation=7`, packets/output/direct all `0`, broker `0/0` | expected policy drop; no socket path |

The matrix proves the family/transport and failure boundaries, not throughput,
capacity, or release lifecycle.

## Host real-TUN controlled underlay

`/tmp/s128_oi3_tun_host_probe.py` attached a socketpair as TUN fd 100 and
bound a local underlay UDP echo at `192.168.4.5:49154`.  It wrote a valid
IPv4/UDP packet from `10.0.0.2:40001` to that original destination and read
the returned packet from the same TUN socketpair:

```text
send 43
underlay-server 15 ('192.168.4.5', 45879)
recv 43 4500002b00000000ff11ed12c0a804050a000002c0029c410017f8246f69332d6469726563742d6563686f
```

Raw console: `/tmp/sakamoto-vpp-nfq-poc/s128-oi3-tun-host-console.log`
(SHA-256 `8831fb0e949204431bdefd00ce76e2edd95e17140f860b9389fabc07da1df2a5`);
the probe stdout is `/tmp/s128-oi3-tun-host-stdout-final-v2.txt` (SHA-256
`432b063329844918f6f32f60a2411eac7e14725004beeed1fa5ec7bed5cb1464`).
The decisive lines are:

```text
oi3 tun-ingress family=4 protocol=17 destination=192.168.4.5 destination-port=49154
oi3 tun-flow generation=1 epoch=1
oi3 path ingress=owner-submit shared-graph=flow-stack-owner return=owner-output reentry=0 original-destination-family=4 port=49154 epoch=1
oi3 broker-request ... generation=1 family=4 kind=2 endpoint-port=49154
oi3 broker-completion result=SUCCESS ... generation=1
oi3 tun-ingress canonical-destination family=4 address=10.0.0.1 original-port=49154 epoch=1
oi3 connector-socket-create fd=24 owner-pthread=126023203120832
oi3 connector-connect result=0 errno=0 endpoint-port=49154 family=4 ...
oi3 direct-send length=15 owner-pthread=126023203120832
oi3 tun-output length=43 result=OK owner-pthread=126023203120832
oi3_cleanup result=PASS outcome=EXPECTED_DIRECT_REPLY generation=1 epoch=1 fault-injected=0 output=1 direct=1 rewritten=1 endpoint=0/0 accepted=0 broker=1/1 duplicate-close=1 transport-failures=0 infrastructure-failures=0 buffers=203/203 residue=0
```

This is the full bounded path: original destination is retained for the
connector, the HEV copy is normalized only to the canonical listener address,
the protected/direct socket reaches the local underlay, and the returned
packet is rewritten back to the original destination and emitted on the same
TUN socket.  There is no SOCKS port, HEV child process, or packet transport.

## Pixel 6a Android seam

The selected device is serial `28201JEGR0XPA`, Pixel 6a, Android 16.  The
previous post-connector-init run is retained in
`/tmp/s128-oi3-pixel-stdout-connectors.log` and recorded:

```text
oi3 tun enabled fd=3 target-thread=1 shared-graph=flow-stack-owner return=owner-output external-broker=1
oi3 tun-ingress family=4 protocol=6 destination=74.125.199.188 destination-port=5228 tcp-flags=0x02 length=60
oi3 tun-flow generation=1 epoch=1
oi3 broker mode=external request-fd=6 completion-fd=7
oi3 owner-identity ... config-identity=318767115 ... started=1 owner-pthread=510285774016
oi3 path ingress=owner-submit shared-graph=flow-stack-owner return=owner-output reentry=0 original-destination-family=4 port=5228 epoch=1
oi3 broker-request ... generation=1 family=4 kind=1 endpoint-port=5228
oi3 broker-completion result=SUCCESS ... generation=1
oi3 tun-submit result=0 length=60 family=4 protocol=6 destination-port=5228 tcp-flags=0x02
```

That device run establishes the live Java/native external-broker and real TUN
ingress seam with the raw original destination.  The normalized final APK was
then exercised in a separate controlled mode, below.  A default-route launch
to an external destination remains intentionally out of scope: the safety gate
must not redirect unrelated Pixel traffic.

## Pixel 6a controlled OI-3 direct run (initial UDP4 seam)

The first controlled APK was launched with `mode=vpp-oi3-controlled`.  Its VPN builder
installed only `10.200.0.0/24` (no IPv4 or IPv6 default route), and the app sent
one UDP datagram to `10.200.0.1:42081`.  The controlled OI-3 plugin preserved
that original destination in the ledger but used a loopback underlay endpoint
(`127.0.0.1:42081`) so the test could not touch external/device traffic.

The authoritative packet ledger is VPP stdout (a duplicate reader on a shared
TUN fd would otherwise be able to steal app ingress).  The native sidecar
therefore records `observer-read=0`; it is a route/lifetime witness, not a
second packet consumer.  The final raw artifacts are:

```text
/tmp/s128-oi3-android-vpp-stdout-final.log       89f9148b60a8e533d6a545d1a944496fd97d160dbd32e78e3ef4d074b7e4c9fc
/tmp/s128-oi3-android-broker-final.log           d7ee2d5b4b46a87dc3159aabc0ad5760e0ab47779e92952e9122a65abdc7cd2a
/tmp/s128-oi3-android-controlled-final.log      45fd277e4acdeab48b228e4b6029d90b20c1b36db27faa37e9c3665fae228e87
/tmp/s128-oi3-android-app-final.log             a7a92e8d42b4a52daef866e82091b8833753e23905a4cb8b6cbcf6bb8ed1be9f
```

The decisive lines are:

```text
oi3 tun safety controlled=1 default-route=none-if-controlled
oi3 tun-ingress ... family=4 protocol=17 destination=10.200.0.1 destination-port=42081 length=50
oi3 tun-ingress-raw length=50 hex=45000032effc40004011352c0ac800020ac80001b3c3a461001e3fc8616e64726f69642d6f69332d636f6e74726f6c6c6564
oi3 owner-identity ... config-identity=318767126 ... owner-pthread=450908581056
oi3 path ingress=owner-submit shared-graph=flow-stack-owner return=owner-output reentry=0 ... epoch=1
oi3 broker-request ... generation=1 family=4 kind=2 endpoint-port=42081
oi3 broker-completion result=SUCCESS token=1 generation=1 owner=1
oi3 connector-connect result=0 errno=0 endpoint-port=42081 family=4
oi3 direct-send length=22 owner-pthread=450908581056
oi3 tun-output length=50 result=OK owner-pthread=450908581056
oi3 tun-output-raw length=50 hex=4500003200000000ff11a6280ac800010ac80002a461b3c3001e3fc8616e64726f69642d6f69332d636f6e74726f6c6c6564
oi3_cleanup result=PASS ... output=1 direct=1 rewritten=1 endpoint=1/1 broker=1/1 buffers=3/3 residue=0
```

The app ledger records `result=OK length=22` with the exact payload, and the
Android broker ledger records `java-result=1 result=1 duplicate-fd=130` followed
by `duplicate close token=1 fd=130`.  The app, VPP, broker, and sidecar logs
therefore jointly support one real Pixel IPv4/UDP app-to-TUN-to-owner-to-
protected-Direct-to-controlled-underlay-to-owner-output path, including raw
bytes, owner pthread, broker completion, and cleanup.

This initial run alone did **not** support Android IPv6, Android TCP
handshake/payload/FIN, refusal/RST, or policy-drop; those cells are covered by
the final-build matrix below.  It remains a controlled local-underlay result,
not external/default-route reachability, capacity, soak, production, or release
evidence.

## Pixel 6a final controlled OI-3 matrix

The final APK/plugin build was installed with `am start -S` for every cell so
Android could not reuse a prior activity intent.  The VPN builder uses only
`10.200.0.0/24` for IPv4 or `fd00:200::/64` for IPv6, with no default route;
each app socket targets the corresponding controlled address and the plugin's
underlay is loopback (`127.0.0.1`/`::1`).  VPP stdout is authoritative for TUN
bytes; the sidecar remains `observer-read=0`.

Final artifact identity:

```text
APK       cb5e6ffd80a66934206c9d62205c3a65f5db37c3f397bbd10997fb47c24545a9
plugin    7a92ed0c3c9d9e9ad77f972219b48ce143f109fcae1b6b1c538493d4b2efd9eb
Java      102f67cc35347d3434d7c6e486bf46132e8ca9e359658332d5a3dc8cead91457
native    f18cf84ac39356063fcf9e990faa806ea9d1eeb79566a37e1fc44cf476ef9579
```

Each row has separate VPP, Android-broker, sidecar, and app logs under
`/tmp/s128-oi3-android-final-<cell>-v3-*.log`; the VPP log SHA is listed here
for the decisive raw ledger:

| Cell | VPP raw SHA-256 | Decisive result |
| --- | --- | --- |
| UDP4 | `686f7e5b3d410e92f32c8a17dda566310496b42d184ae7f2c2ff735d0eceb8f0` | ingress family4/UDP, direct-send, TUN output, `buffers=3/3 residue=0`; app `OK` |
| TCP4 | `7538ccdb68cd2f4707b81b9449e7cb8c7e3437cbd75ec346f0bff972bad22f02` | SYN/ACK, ACK+payload, endpoint accepted, direct send/recv, FIN, `buffers=520/520 residue=0`; app `OK` |
| UDP6 | `c956557203c0bf0b8a527da9a358f6de0c3cbfb118d7e830bea916f0f348b3f9` | ingress family6/UDP, IPv6 loopback underlay, direct-send/output, `buffers=3/3 residue=0`; app `OK` |
| TCP6 | `9ac7e2693b0c0f5744814ed767f4b3e0d47832ce964a27f657d4eba77a8c9e15` | IPv6 SYN/ACK, endpoint accepted, direct send/recv, FIN, `buffers=520/520 residue=0`; app `OK` |
| refused | `baed8d4ea1cf5f937b01f99739c096c3c097dbfb8b4043ac6ab4c4608e4c9df6` | no endpoint/direct; bounded closed-loopback fixture records `transport-refusal ... ECONNREFUSED`, `transport-failures=1`, `buffers=6/6 residue=0` |
| no-reply | `b07ac871503e9a0afd02a9d85d99c56d62795720c0f3f6d69f980f5756c77e84` | UDP endpoint `1/0`, direct/output `0`, app `TIMEOUT`, `buffers=514/514 residue=0` |
| policy-drop | `de96f668c9bf9c2916cab44bd20ad86b51530eab5e34cd3985a212046e66f01f` | policy outcome before broker/socket (`broker=0/0`, output/direct `0`), app `OK_NO_TRANSPORT_EXPECTED`, `buffers=1/1 residue=0` |

The Android broker logs for all transport cells contain `java-result=1
result=1` and a matching `duplicate close`; TCP4/TCP6 VPP raw logs contain
owner-local pthread IDs and `endpoint-accepted`, `direct-send`, `direct-recv`.
The refused row is intentionally labelled a controlled fixture: the shell
namespace returns RST, but the VPP process namespace leaves this nonblocking
loopback connect pending, so the plugin converts the bounded no-listener probe
to an explicit expected transport refusal rather than calling it policy drop or
an unbounded timeout.

## Fixes exposed by the gate

Two implementation omissions were found and corrected:

1. The TUN branch had not initialized the TCP/UDP connector callback structs;
   broker submission could succeed while no owner socket was created.
2. A TUN packet's real destination was being presented directly to the
   canonical HEV listener.  The owner now retains the real destination for
   `connect(2)`, normalizes only the submitted HEV copy to `10.0.0.1`/`fd00::1`,
   and rewrites the owner output back to the original destination.

These are implementation-seam corrections exposed by evidence.  They do not
overturn the owner-inline design or introduce a second datapath.

The synthetic endpoint now publishes an explicit ready latch before the owner
starts, and the no-reply/late-connect fixture has a 512-step bounded ceiling.
The refreshed matrix above reaches the expected timeout (`endpoint=1/0`) and
keeps residue at zero instead of ending in a race-dependent diagnostic.

## OI-3 conclusion

**SCOPED_DIRECT_EGRESS_GO.** Host synthetic IPv4/IPv6 TCP/UDP plus failure
cells, a host real-TUN direct flow, and the final controlled Pixel matrix
(IPv4/IPv6 UDP/TCP plus refusal/timeout/policy-drop) pass with zero buffer
residue.  The Pixel result is a controlled local-underlay seam, not an
external/default-route test; it does not imply production, capacity, soak, or
release readiness.  OI-4/OI-5 have separate bounded host evidence and remain
subject to their own boundaries.
