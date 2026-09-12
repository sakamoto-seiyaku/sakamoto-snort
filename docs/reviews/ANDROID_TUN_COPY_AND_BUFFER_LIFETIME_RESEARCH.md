# Android TUN copy and buffer lifetime investigation

Status: research input, not an architectural decision. Investigated 2026-09-11.
Scope: ordinary Android `VpnService` file-descriptor I/O; distinguish packet
storage lifetime from delivery, and userspace copies from kernel crossings.
No product or ADR changes are implied.

## Platform contract

`VpnService.Builder.establish()` returns a descriptor for IP packets: reads obtain
outgoing packets and writes inject incoming packets. Nonblocking is the default;
`setBlocking()` can change it. This is packet I/O, not a promise that a write has
been consumed by its destination application. Native code can detach the fd.
[Android Builder API](https://developer.android.com/reference/android/net/VpnService.Builder#establish()).

The inspected AOSP framework JNI opens `/dev/tun` with `O_NONBLOCK` and creates
`IFF_TUN | IFF_NO_PI`, without `IFF_MULTI_QUEUE` or `IFF_VNET_HDR`. This is inspected
upstream source, not a byte-for-byte verification of the test device framework.
[AOSP JNI, blob ea5e7183c9056e62858665d0b62c315bf7d51fd8](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/services/core/jni/com_android_server_connectivity_Vpn.cpp).

## Ordinary syscall lifetime: source evidence

Linux v6.6 `tun_chr_write_iter()` calls `tun_get_user()` with null message control.
Its zero-copy branch requires non-null control; ordinary payload input uses
`skb_copy_datagram_from_iter()`. The alternate skb-building path also copies via
`copy_page_from_iter()`. Read-side `tun_put_user()` uses
`skb_copy_datagram_iter()`. Thus ordinary synchronous TUN I/O copies bytes across
the userspace/kernel boundary. A successful write's source storage can be reused
after the call returns; no application-delivery acknowledgement is required.
Before return, it must remain valid. This lifetime conclusion is an inference
from these concrete copy paths.

`writev` supplies one iterator to that same one-packet write path: iovecs describe
pieces of one packet, not a batch of independent IP packets. The driver exposes
character-file operations; its internal `tun_get_socket()` is an exported kernel
interface, not a socket fd returned to an Android application. These facts do
not establish support for `sendmmsg` on the TUN descriptor.
[Linux v6.6 TUN source](https://github.com/torvalds/linux/blob/v6.6/drivers/net/tun.c).

Version caveat: this identifies upstream mechanisms, not all OEM kernels. Match
the device build and inspect its actual TUN flags before claiming device-specific
zero-copy or batching support.

## Zero-copy and multiqueue are separate capabilities

Linux documents `MSG_ZEROCOPY` for TCP/UDP socket sends. It introduces page
accounting and completion notifications: callers cannot immediately overwrite
shared buffers after syscall return. Completion means the kernel released its
hold, not necessarily transmission completion. Copy avoidance can fall back to
copying; the documentation warns its overhead usually only pays off for writes
larger than roughly 10 KB. None of this makes ordinary TUN `write()` zero-copy.
[Linux v6.6 MSG_ZEROCOPY documentation](https://www.kernel.org/doc/html/v6.6/networking/msg_zerocopy.html).

Linux TUN multiqueue requires opening and attaching multiple descriptors using
`TUNSETIFF` and `IFF_MULTI_QUEUE` with the same interface name. Duplicating a
descriptor is not this procedure. Android's documented Builder contract does
not expose that configuration, and the inspected JNI does not request it.
Consequently multiqueue cannot be assumed for standard `VpnService`; a privileged
experiment would be a separate platform/integration question, not evidence that
every Android VPN has it.
[Linux multiqueue TUN documentation](https://kernel.org/doc/html/latest/networking/tuntap.html#multiqueue-tuntap-interface),
[Android Builder API](https://developer.android.com/reference/android/net/VpnService.Builder).

## Fair comparison: remote tunnel versus local Direct

AOSP ToyVpn reads an IP packet into an array-backed buffer, writes it to its
remote `DatagramChannel`, and reverses this operation for incoming packets.
The same userspace buffer is reused. It does not reconstruct every original flow
through a local userspace TCP/IP stack. The sample is useful for identifying
boundaries, not as a production performance recommendation or proof of all VPN
applications' internal copy counts.
[AOSP ToyVpnConnection](https://android.googlesource.com/platform/development/+/refs/heads/main/samples/ToyVpn/src/com/example/android/toyvpn/ToyVpnConnection.java).

Analysis: comparing that remote-gateway tunnel with a local Direct flow adapter
requires naming which work has moved to the gateway. Counting only explicit
userspace `memcpy` calls would hide kernel I/O crossings and Java/native details.
Count full-IP copies separately from UDP/TCP payload copies and from metadata
handoffs; do not report a universal end-to-end copy count for all packet shapes.

## Current Product UDP path and pinned HEV comparison

The following is a logical copy-boundary inventory for ordinary UDP, not a
hardware memory-transaction count, TCP claim, or measured throughput result.
The existing "two copies" decision names the two VPP/lwIP ownership boundaries
across the two directions; it does not count all kernel I/O copies.
[Accepted copy contract](../adr/0007-owner-local-lwip-direct-egress.md#buffer-ownership-and-copying).

| Direction | Operation | Packet/payload copy |
| --- | --- | --- |
| App outbound | TUN `read` directly into VPP buffer data | Kernel → userspace IP packet |
| App outbound | `pbuf_take` into lwIP-owned pbuf | VPP → lwIP IP packet; explicit ownership copy |
| App outbound | Direct `sendmsg` over pbuf iovecs | Ordinary userspace → kernel UDP payload |
| App inbound | Direct `recvmsg` into owner scratch | Kernel → userspace UDP payload |
| App inbound | `pbuf_alloc_reference` over scratch, prepend UDP/IP headers | No extra full-payload copy at this step |
| App inbound | Output spans copied into a new VPP buffer | lwIP → VPP IP packet; explicit ownership copy |
| App inbound | Native frame handoff to TUN lane | Buffer index/metadata transfer, no packet-byte copy |
| App inbound | Ordinary TUN `write` from that VPP buffer | Userspace → kernel IP packet |

Product call sites: [TUN read, return copy and write](../../src/product/vpp/product_vpn_tun_adapter.c),
[owner input copy](../../third_party/hev/product/hev-owner.c),
[Direct sendmsg/recvmsg and PBUF_REF implementation](../../third_party/hev/patches/0004-direct-udp-session.patch),
[native graph submission/completion routing](../../src/product/vpp/product_packet_graph.c).
Ordinary kernel crossings follow the platform sources above. No additional
payload buffer is currently copied merely to transfer a return to the TUN lane.

For this ordinary UDP path, grouping by payload-bearing copy boundaries gives
three per direction: two kernel crossings and one VPP/lwIP ownership copy.
Full-IP packet sizes and UDP payload sizes differ; checksums, headers, kernel
internal copies, application socket operations and protocol-specific paths are
outside this count. It must not be presented as an exact total memcpy count.

The pinned HEV tunnel helper reads the TUN packet directly into a pbuf payload,
then feeds that pbuf to lwIP. Its output writes a pbuf directly or uses `writev`
to gather a pbuf chain. It therefore demonstrates how a stack without VPP can
avoid these intermediate VPP/lwIP ownership copies, while retaining ordinary
kernel crossings. This is an implementation comparison, not a claim that the
upstream SOCKS tunnel and the Product Direct adapter have identical workloads.
[Pinned HEV tunnel I/O](../../third_party/hev/upstream/src/hev-tunnel.h),
[pinned HEV tunnel input/output](../../third_party/hev/upstream/src/hev-socks5-tunnel.c).

Lifetime consequences verified in the current source:

- The outbound VPP input borrow ends when `input_copy` returns. Existing VPP
  completion still runs; the original buffer is not retained until HEV finishes
  authorization, socket transmission or receipt of a reply.
- The inbound pbuf can reference reusable owner scratch. `udp_sendfrom` and the
  output callback run before scratch is reused; copying into VPP makes later
  graph/lane processing independent of that scratch and pbuf lifetime.
- Once the TUN synchronous write returns, no later application-delivery event
  is awaited before native VPP free. A queued cross-lane buffer must remain
  valid before that write, because the index handoff did not copy its bytes.

These follow from the Product call sites above and the existing
[origin completion consumer](../../src/product/vpp/product_packet_graph.c).
Removing an ownership copy would require a different storage/borrow contract,
not simply deleting `memcpy` or freeing a buffer earlier. This investigation
does not approve such a change.

## Design implications to investigate, not decisions

### Existing performance evidence changes the next-step recommendation

The historical S125 memo already records a user-selected engineering direction:
retain the two-copy path and prioritize scheduling, batching, queue/lock and
checksum work rather than start zero-copy or lwIP memory-model redesign.
Representative measured copy-share was approximately 0.1–0.4%; a separate
simpleperf sample attributed about 2.11% to memcpy/memmove, below checksum,
kernel locking and netfilter. Those measures have different denominators and
must not be conflated. The formal investment campaign remained INCONCLUSIVE
because its complete control/instrumentation gates were not closed, but that
did not invalidate the recorded engineering direction.
[S125 copy-investment memo, final stage decision](../../experiments/vpp-nfq-poc/S125_COPY_INVESTMENT_MEMO.md#阶段决策暂停补充矩阵转入现有路径优化2026-08-22).

These are historical POC measurements, not a performance certification of the
current Product artifact or every kernel I/O copy. They nevertheless mean this
design discussion need not restart the already-paused copy-investment campaign
before progressing. The recommended baseline remains independent VPP/lwIP
copies with no extra TUN-lane payload copy. Targeted current-Product profiling
can check for a new bottleneck once the W2 path exists; it should not be turned
into a prerequisite to re-approve the existing copy contract. This paragraph
records evidence and a recommendation, not acceptance of the still-discussed
return-credit lifetime or write-retry policy.

- A buffer-index handoff is not a byte copy. The receiving lane still needs the
  original bytes until its synchronous write has returned or it abandons writing.
- Adding a lane-owned payload copy would shorten the original buffer lifetime
  but add storage, bandwidth cost, and a second lifetime to bound. It does not
  remove the ordinary TUN kernel crossing.
- Keeping a buffer alive while queued does not inherently block its generating
  worker. Scheduling, queue capacity and ownership transfer must be specified
  separately from storage validity.
- Nonblocking I/O still takes CPU time. Bounded graph batches, syscall budgets,
  saturation behaviour and tail latency need measurement; copy counts alone do
  not establish that the current or an alternative design is faster.
- Do not equate lwIP ownership completion, graph handoff, TUN syscall return,
  and application delivery. They are different events.

No performance benchmark was performed in this investigation. Evidence needed
to compare designs includes copy bytes/time, handoff residence, outstanding
buffers per worker, TUN syscall latency, allocation failure and saturation
behaviour, for small and MTU-sized packets, both owners and both directions.
These are measurement dimensions, not a separate task ledger or a claim that
an alternative implementation is already authorized.
