# SAKAMOTO-235 — Linux network events and packet policy facts

## Scope and implementation

Linux Root now owns a same-network-namespace kernel collector. It feeds the
existing 280-byte, at-most-32-known-interface snapshot on VPP main, using the
existing worker barrier for publication. Packet workers perform only a bounded
snapshot lookup. No manager RPC, FlowRuntime lock, second owner hash, interface
key component, packet pre-steering, generic metadata service, or new dependency
is introduced. Android retains its separate ConnectivityManager collector.

The conservative classifier uses explicit kernel evidence on an UP/RUNNING,
non-loopback interface:

| Category | Accepted evidence | Missing/unsupported evidence |
| --- | --- | --- |
| Wi-Fi | Wireless ioctl reports the IEEE 802.11 protocol | Unknown, including drivers without this available interface |
| Mobile | Kernel WWAN-core `wwan` link kind | Other modem/legacy interfaces stay Unknown |
| VPN | Kernel WireGuard `wireguard` link kind | Generic TUN/TAP, IP tunnels, bridge, veth are not VPN evidence |
| Wired | No virtual link kind; Ethernet hardware type plus successful ethtool link settings reporting a physical connector **and** the corresponding supported medium | Ethernet type, interface name, speed or a default zero port alone do not qualify |

Wi-Fi probing precedes wired probing. A successfully reported non-802.11 wireless
protocol does not fall through to Wired. Driver queries use a socket in the
runtime's own namespace and validate the interface identity before/after probing;
there is no host-manager/foreign-netns ifindex join. Generic unconfirmed VPNs are
not inferred from routing, TUN presence, or the system default network.

Sources are the installed Linux UAPI and primary kernel definitions:
[ethtool link settings](https://docs.kernel.org/networking/ethtool-netlink.html),
[cfg80211 protocol reporting](https://github.com/torvalds/linux/blob/master/net/wireless/wext-compat.c),
[WWAN link ownership](https://github.com/torvalds/linux/blob/master/drivers/net/wwan/wwan_core.c),
and [WireGuard device ownership](https://github.com/torvalds/linux/blob/master/drivers/net/wireguard/device.c).
These are classification evidence, not imported packet-domain implementations.

RTNL link and IPv4/IPv6 address events invalidate the previous known map and
request a complete new dump. Notifications during a dump invalidate that
candidate. Delete/reuse, malformed/interrupted/truncated dumps and receive loss
cannot republish its stale entries. More than 32 known interfaces publishes an
explicit `map_overflow_unknown`, not a truncated purportedly complete map. The
retry/watchdog timer is one-shot and disarmed after a complete dump; it is not an
idle polling timer. Each read callback has a bounded datagram budget.

Root lifecycle starts the collector only after its packet resources are ready.
Final stop removes both main-thread file listeners and closes route/query/timer
FDs after graph drain. A failed subscription stays explicitly Unknown and cleans
its partial FDs. Kernel metadata collection is read-only. Ordinary missing
metadata does not block packets or turn all policy evaluation off.

The default Linux snapshot writer is the kernel collector. A simultaneous VAPI
writer is rejected. Tests or an explicitly selected external platform publisher
can opt into `SAKAMOTO_LINUX_NETWORK_SOURCE=external` at startup; that generation
has no kernel subscriptions and its projection evidence is labelled separately.
The public snapshot ABI and Android writer behavior are unchanged.

## Actual acceptance — source B

Product source closure:
`ab278ba6c69555a0772277f17d9350bc73ced8312d061a663d52fe3b06b05b96`.
The immutable Linux/Pixel builds use the existing pinned six-patch VPP stages
from S220. The installed Pixel APK SHA-256 is
`e964f9d9a83ece13bbc5ac02465931ee97091c2681f39168d487b0f8eb71994f`.
Full source files, pre-commit dirty diff, compiler/helpers and native/VPP/APK
hashes are retained under `build-output/s235-20260913/`.

| Evidence | Independently verified result |
| --- | --- |
| `linux-network-d/kernel` | 44 real dual-stack endpoint cases; 74 captures, 74 unique native verdict operations and matching buffer returns |
| `linux-network-d/controlled` | 38 separately labelled projection cases; 58 captures/verdict operations; all four categories plus missing facts |
| `pixel-smoke-b` | RuntimeService Root generation 1379; 16 cases, 52 captures/verdict operations; all four lanes and local/remote owners; JNI stop and Android subscription shutdown |

The Linux test creates two disposable rootless network namespaces with a real
WireGuard encrypted path and a separate veth underlay path. It does not alter
host networking or use an injected packet graph. Independent UDP endpoints
prove delivery, DROP and recovery for both IP families. Original NFQUEUE TLVs
are decoded independently; LOCAL_OUT uses actual OUTDEV and LOCAL_IN actual
INDEV. The actual snapshot revision/context, policy publication, Gate/L4
matcher, canonical owner and native origin syscall are joined by generation and
packet identity. Some loopback INPUT packets lack UID; that absence is preserved,
not rewritten to the test UID or confused with Unknown network context.

Real checks include VPN Gate/L4 OUTPUT/L4 INPUT DROP, unrelated-network no-match,
unclassified veth no-match, independent UID/ifindex/L4 conditions still dropping,
and both default-route choices without overriding per-packet interface facts.
Address add/delete, down/up, interface delete, same-ifindex dummy reuse, and
recreation of the real tunnel all refresh snapshots. Thirty-three actual UP
WireGuard interfaces exercise overflow and subsequent recovery.

For notification loss, only the test-owned runtime is temporarily stopped while
800 MTU changes fill its route socket. The kernel records **714 dropped
notifications**. Deletion and reuse occur while queued; after resume, EPOLLERR
reaches the collector, old facts become Unknown, and a complete resync reflects
the reused unclassified interface. The collector remains subscribed until normal
drain/close; packet verdicts, buffers, obligations and FD cleanup reconcile.

This machine provides no qualified physical Wired, Wi-Fi or Mobile endpoint for
this matrix. Those three hardware paths are explicitly **UNVERIFIED**, as allowed
by S235's hardware-availability boundary. Their controlled projections and
classifier syscall tests are not real-platform PASS claims. VPN classification
here proves WireGuard, not ownership discovery for arbitrary VPN software.
No UI, release, performance or wider protocol-readiness claim follows.

## Failures found and resolved

Candidate A assumed multicast events had `nlmsg_seq == 0`. A real WireGuard IPv4
address notification retained the ip command's nonzero sequence and pid. The
corrected collector uses the kernel sockaddr's multicast group, and the host
regression includes this exact nonzero-sequence case. It also supplies an error
callback because VPP otherwise closes an fd on EPOLLERR; actual ENOBUFS recovery
above validates the corrected behavior. Candidate A is not completion evidence.

Source B's first two integration attempts exposed disposable test setup errors:
this kernel removes explicit routes, then IPv6 addresses, when a link goes down.
The final runner restores both before claiming tunnel recovery and records a
kernel route lookup for every packet case. Product B was unchanged. Earlier runs
remain HOLD; their owned processes/endpoints/namespaces were cleaned.

The classifier/parser host test passes, including the nonzero-sequence event,
virtual non-inference, missing metadata, disconnect, reuse, stale/interrupted and
malformed dumps, and 32-entry overflow. ASan/UBSan passed outside the restrictive
sandbox with a five-second bound; one sandbox invocation's sanitizer signal
handler loop was stopped, not mistaken for a Product runtime failure or a pass.

Sixteen rehashed semantic-negative checks (10 Linux, 6 Pixel) reject wrong raw
NFQUEUE interface/context, virtual-as-VPN claims, altered injected category,
missing receive-loss evidence, duplicate verdicts, wrong owner, and resource or
subscription residue. They overlay file reads in memory; originals are untouched.

Full current Host CTest is **35/40**. The remaining five VPP/S176/S189/S190/S191
static-contract failures are the pre-existing failures recorded by S220, with
unchanged test scripts. The additional sandbox-only Rust UDS failure passes when
run with actual socket access. No whole-repository green claim is made.

Verified report hashes:

- Linux: `57bf731ccc13abf47c367a04913e8c3b99ca1d3c1c87859dfdbfcc9d1363d8c4`.
- Pixel: `965dfc9d098a36973be92467d5ef4b4b71bd567175c4ce1f1acb1bdff2567f39`.
- Unsandboxed Host JUnit: `25677b611c7de5f0cf4903733a37ab2c93cdad71b3c6e022d3190b0b7adee5f4`.

## Reproduce

```sh
rtk proxy python tests/device/verify-s235-network.py build-output/s235-20260913/linux-network-d
rtk proxy python tests/device/verify-s235-network.py build-output/s235-20260913/pixel-smoke-b
rtk proxy ctest --test-dir build-output/s236-20260913/host-tests -R linux-network --output-on-failure
```

Build entry points are `build_s230_linux.py`, `product_chain.py build`,
`build_s242_helpers.py` and `build_s235_helpers.py` under `tests/evidence/`.
Collectors `s235-linux-network.py` and `s235-pixel-smoke.py` accept the source-bound
build/helper manifests. Linux requires `unshare --user --map-root-user --net`;
the peer setup additionally needs the installed Python cryptography X25519 API.
WireGuard configuration uses the Linux generic-netlink UAPI, without installing
NetworkManager or wireguard-tools. No private test keys are logged.

Issue status and follow-up acceptance scope live in Plane; this document is the
dated implementation and measurement record, not a separate work ledger.
