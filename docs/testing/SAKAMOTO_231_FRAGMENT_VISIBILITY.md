# SAKAMOTO-231 — NFQUEUE fragment visibility

PASS, 2026-09-08. The same current Product source passes **261 actual NFQUEUE
packets**, independent Ethernet captures, ordinary UDP/TCP regressions and native
stop checks. **Pixel sees kernel-reassembled packets at all four tested hooks.**
The isolated Linux namespace sees original fragments at raw IPv4 OUTPUT and
IPv6 INPUT/OUTPUT, but kernel-reassembled packets at IPv4 INPUT. This establishes
test entry points, not Product reassembly readiness.

The registration below was written before collection. Final evidence is
`build-output/s231-fragments/linux-d` and `build-output/s231-fragments/pixel-e`.

## Measured matrix

Each raw-fragment row includes two distinct datagrams: offset-zero-first and
reverse order. Each sender creates two checksum-valid IP fragments with known
nonce bytes. INPUT also has complete, unfragmented UDP controls from the same
Ethernet peer before and after the fragment pair.

| Platform / generation | Family | Product hook | NFQUEUE shape for explicit fragments | NFQ packets for two datagrams |
| --- | --- | --- | --- | ---: |
| Linux 23110 | IPv4 | LOCAL_IN / INPUT | Kernel-reassembled UDP | 2 |
| Linux 23111 | IPv4 | LOCAL_OUT / OUTPUT | Original fragments | 4 |
| Linux 23112 | IPv6 | LOCAL_IN / INPUT | Original fragments | 4 |
| Linux 23113 | IPv6 | LOCAL_OUT / OUTPUT | Original fragments | 4 |
| Pixel 882 | IPv4 | LOCAL_IN / INPUT | Kernel-reassembled UDP | 2 |
| Pixel 883 | IPv4 | LOCAL_OUT / OUTPUT | Kernel-reassembled UDP | 2 |
| Pixel 884 | IPv6 | LOCAL_IN / INPUT | Kernel-reassembled UDP | 2 |
| Pixel 885 | IPv6 | LOCAL_OUT / OUTPUT | Kernel-reassembled UDP | 2 |

The original IPv4 pieces are 68/76 bytes; the complete NFQUEUE packet is 124
bytes. The original IPv6 pieces are 96/104 bytes; kernel reassembly removes the
Fragment header and yields a 144-byte UDP packet. The independent INPUT capture
contains the exact two original frames in their sent order, even when NFQUEUE
only receives the complete datagram.

Ordinary socket output is a different case. In both platforms and families, a
normal UDP socket sends a 1300-byte payload through MTU 1280. NFQUEUE at LOCAL_OUT
receives one complete packet: 1328 bytes for IPv4, 1348 for IPv6. The independent
link subsequently sees two fragments: 1276/72 bytes for IPv4, 1280/124 for IPv6.
Wire fragmentation therefore does not establish original-fragment visibility at
LOCAL_OUT.

Pixel's explicit raw OUTPUT datagrams also appear as complete packets in
NFQUEUE and are then refragmented before the link. For IPv6, that later kernel
operation chooses a new IP fragment ID. The oracle binds the new ID through the
unique first-fragment UDP nonce and complete byte comparison; it does not
confuse IP fragment ID with the original NFQUEUE packet ID or generation.

Linux's four raw IPv4 OUTPUT fragments reach the actual Product NFQUEUE socket
but are rejected by the current graph's runtime-envelope path, before policy.
Their final reason is `DROP_INVALID_ENVELOPE`, and each completes once with
`NF_DROP`; no corresponding frame reaches the link. This is neither a Policy
DROP nor successful Product reassembly. The visible Linux IPv6 fragments pass
the current graph as Fragment-header/L3 traffic; their successful delivery does
not qualify port-aware fragment enforcement. Those capabilities remain S212/228
work.

## Entry points fixed for S212 and S228

| Follow-up | Pixel in this measured Root configuration | Real Linux endpoint in this measured namespace |
| --- | --- | --- |
| S212 IPv4 native full reassembly | Use a bounded, explicitly `GRAPH_INJECTED` VPP buffer/frame injector through actual native nodes. Do not invent per-fragment NFQ IDs or claim Pixel NFQ fragment E2E. | Explicit raw LOCAL_OUT fragments are reachable. Use their actual per-fragment NFQ generation/ID and origin completion in addition to native graph tests. |
| S228 IPv6 native full reassembly | Use the same explicit graph-only provenance for native graph tests; this matrix did not expose original IPv6 fragments to Pixel NFQUEUE. | Original fragments are reachable at INPUT and explicit raw OUTPUT. Use real NFQUEUE identities where exercised; ordinary socket OUTPUT is pre-fragmentation. |

This selection is scoped to these kernels, namespaces, hooks and current
conntrack/defrag configuration. A different deployment must remeasure its entry.
Lack of original fragments at the Pixel hook does not remove or replace the
planned native reassembly capability.

## Registered scope

Measure Pixel Root and an isolated real Linux NFQUEUE endpoint independently,
for IPv4/IPv6 and LOCAL_IN/LOCAL_OUT. Preserve the Product mangle-table hooks
and their priority; do not move capture to PREROUTING or add a Product Adapter.
Compare native NFQUEUE payload bytes, length and available SKB attributes with
an independent AF_PACKET capture. Record missing attributes as unknown.

The test peer is a temporary veth pair with only the receiving endpoint
configured: `198.18.231.2/24` and `fd20:6231::2/64`. The emulated peer addresses
`.1`/`::1` have a static neighbor entry. Both links have MTU 1280. Narrow
test-destination routing rules may be needed on Android and must be removed
with the links. This is a packet-generator/capture fixture; Product ingress
remains the actual kernel NFQUEUE path at LOCAL_IN/LOCAL_OUT.

For INPUT, send Ethernet frames through the peer veth endpoint and capture at
the receiving link before the IP stack. For OUTPUT, compare explicit raw IP
fragments with a normal UDP socket sending a 1300-byte payload through the
1280-byte link. Observe its wire fragmentation separately from the packet shape
seen at LOCAL_OUT. Raw fragments are generated in both offset-zero-first and
reverse order. Each test uses unique payload nonces and fragment identifiers.
Ordinary UDP/TCP echo traffic is recorded separately and checked again after
the fragment phases.

The native sender creates its socket under the actual configured UID; raw
transmission uses retained `CAP_NET_RAW` in the diagnostic process. It does not
fabricate NFQUEUE identity, assign a graph owner or inject into Product VPP.
The only Product change for this task is bounded NFQUEUE payload/attribute
observation, before the existing graph transfer.

## Acceptance interpretation

A row is conclusive only when the sent bytes, independent capture and actual
NFQUEUE record explain the observed shape. A missing fragment is not inferred
from successful UDP delivery. Original fragments seen by NFQUEUE use only their
real queue generation, packet ID, completion and verdict. If no original
fragments reach the actual Pixel hook, S212/228 will instead use explicitly
marked `GRAPH_INJECTED` native buffers/frames for their graph tests; those tests
must not claim NFQUEUE fragment E2E.

Every captured Product carrier must settle and return its buffer. Native stop
must show zero outstanding obligations, frames, buffers and handoff debt, closed
queue sockets and empty kernel queues. Temporary links, routes, rules and test
processes must be removed, and Pixel Wi-Fi restored. This task does not implement
reassembly or qualify its capacity or correctness.

## Kernel and hook evidence

Pixel is `bluejay`, kernel
`6.1.134-android14-11-g66e758f7d0c0-ab13748739`, with the existing KernelSU
environment. The reported GKI base resolves to
`66e758f7d0c01a696c3a9db8929417e7403a1571`. Linux is an isolated user/network
namespace on `6.6.114.1-microsoft-standard-WSL2`, whose official release tag
resolves to `308063c46f2741b64f3f9120fd85372ac842d6d8`.

The pinned IPv4 local-delivery code runs reassembly before LOCAL_IN. IPv6's
LOCAL_IN hook precedes its protocol delivery, which includes the Fragment
handler. These different positions explain why one family cannot stand in for
the other. See the reported-base [IPv4 local-delivery source](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/ipv4/ip_input.c)
and [IPv6 input source](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/ipv6/ip6_input.c).

When enabled for a namespace, netfilter defrag also registers PRE_ROUTING and
LOCAL_OUT hooks at conntrack-defrag priority **-400**, ahead of the Product
mangle priority **-150**. The source excerpts explain possible ordering; the
actual packet records, not an assumption about module presence, establish the
matrix. See [IPv4 defrag registration](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/ipv4/netfilter/nf_defrag_ipv4.c),
[IPv6 defrag registration](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/ipv6/netfilter/nf_defrag_ipv6_hooks.c),
and the [pinned WSL kernel](https://github.com/microsoft/WSL2-Linux-Kernel/tree/308063c46f2741b64f3f9120fd85372ac842d6d8).

The Linux fixture contains only its explicit Product NFQUEUE mangle rules and
reports `nf_conntrack_count=0` before and after all four cases. Its detailed
conntrack table is permission-denied inside the user namespace, which is
retained as a limitation rather than replaced with a host-namespace reading.
Pixel retains the platform's existing conntrack/CONNMARK rules; its recorded
count is 12 initially and 15/19/20/21 after the four cases. No NOTRACK rule,
defrag toggle, earlier Product hook or XDP/TC Adapter was added.

The Android test address exists without an automatic IPv6 prefix route in
`main`; the final fixture adds an explicit `fd20:6231::/64` route on `s231rx`
along with priority-9987 destination-only lookup rules. Route lookup is recorded
before traffic. Both rules, the route, neighbors and interfaces disappear at
cleanup. These are test-peer routing resources, not Product ingress changes.

## Product delta, conservation and regressions

Only `product_root_nfqueue_adapter.c` changes relative to the sealed S210 Product
source. Its bounded capture diagnostic reads NFQA_CAP_LEN and NFQA_SKB_INFO with
explicit presence bits, and records the exact NFQUEUE payload before the
existing VPP transfer. These observations do not enter PacketFacts, policy,
OwnerAssignment or public ABI, and do not implement a reassembler.

All 261 NFQUEUE records match capture/admission, native node/thread vectors,
terminal, original-lane completion, unique verdict and original buffer return.
The raw datagram comparisons separately verify the complete UDP checksum and
payload against the independent capture. No synchronously reassembled Host
packet or graph-injected carrier contributes to this task's NFQUEUE claims.

The eight generations include 48 ordinary probe operations: before/after UDP
and TCP echoes, a real Gate DROP, and subsequent recovery. All expected echoes
arrive; all eight Gate DROP probes fail delivery with their actual policy
verdict. Kernel-generated fragmentation is a separate four-datagram test.
Complete peer controls also pass for both INPUT families on both platforms.

Native Root stop is observed before process exit: all four queue sockets close,
their recorded socket inodes disappear, FlowEntries flush, and completion,
buffer, frame, obligation and handoff debt are zero. Linux rebinds each queue
successfully. Pixel then stops RuntimeService, leaves no kernel NFQUEUE entry
or Product hook, and restores Wi-Fi. Both test links, test routes/rules and
diagnostic processes are absent. The final Pixel generation is **885, stopped**.

The bounded-observation source audit passes. Seven semantic corruptions correctly
fail: a false original-fragment claim, a missing independent frame, changed NFQ
packet ID, duplicate verdict, fabricated absent attribute, graph-injection
provenance, and invalid sender UDP checksum.

## Source and reproducibility

Both builds snapshot current Product source and the complete dirty diff against
`9c67175713baceb46cef015f3464893fa3d69950`; the work remains uncommitted.

| Identity | SHA-256 |
| --- | --- |
| Product source manifest | `3829f8b85412846b372c8fe8c1f0cef2168f236ecee5c994b19b3ac84b38dcaa` |
| Linux native plugin | `5b00943f8241013c2e6b1daebe97c75cae431a65366cb35017ce4aa69e3874e1` |
| Pixel APK | `40532a05e8842b689e35ef9a88d878e4039b849a1adda9b87648e7885e723c71` |
| Pixel native plugin | `a6e265109c34597f88e9deb55576dd9de80d8663a32e8d9b13f37f1b1900051d` |
| Pixel VPP runtime | `52f690bb5fda680ebafcd84061e2d93eb3b4c63ce41917483c642609872e97b7` |

The collector checks installed APK/native hashes, kernel, actual native threads,
generation and every original NFQUEUE identity. Pixel PCAP transfer is binary
`./dev/adb pull` and is checked against the device-side SHA-256. Kernel source
files and their official URLs/hashes are in `kernel-source/manifest.json`; the
source is explanatory evidence, not imported Product code.

`evidence-tools/manifest.json` seals the final collector/oracle/helper sources
with SHA-256 `ef96c845116f7c800f333e3f736603135908d74dbe827f99b47a3d0dba2eb6bb`.
`records.json` binds the build, verification, negative-test, kernel-source and
S231-only diff records with SHA-256
`02b7bc39766d6a47281381ce4610fe4601342125acb3858e71b8ae5942be23b0`.
Current-source verification intentionally becomes stale after later Product
changes; use the sealed source and tools for historical reproduction.

```sh
rtk proxy python3 tests/device/verify-s231-fragments.py build-output/s231-fragments/linux-d --build build-output/s231-fragments/linux-build-a/build.json --platform linux
rtk proxy python3 tests/device/verify-s231-fragments.py build-output/s231-fragments/pixel-e --build build-output/s231-fragments/pixel-build-a/build.json --platform pixel
rtk proxy python3 tests/evidence/test_s231_fragment_negatives.py build-output/s231-fragments/linux-d --output /tmp/s231-negatives.json
rtk proxy python3 tests/host/s231-nfq-observation-contract.py
```

Earlier collector runs remain separate: Linux's initial setup used the host
sysfs view instead of namespace rtnetlink; subsequent Linux runs were superseded
by complete peer controls and the final bounded xtables wait. Pixel's early
runs encountered WSL destination conversion, an unsuitable text command for
binary output, a transient xtables lock, and the missing test IPv6 route. Each
was cleaned up, and none is substituted for the final complete matrix. The
IPv6 refragmentation oracle additionally accounts for the directly observed new
kernel fragment IDs; complete UDP byte equality remains required.

These findings cover the current two-fragment UDP datagrams and MTU-1280 test
link, not all fragment shapes, real-network MTUs, malformed/overlap handling,
Product reassembly capacity, VPN transport, or release readiness. They do not
justify deleting planned native reassembly or changing Product hook placement.
