# Independent NFQUEUE verdicts in one Netlink datagram

Date: 2026-10-12. Primary-source research with narrow isolated host probes. This report describes a candidate
beyond the existing sendmmsg experiment; it does not implement, benchmark, adopt
or enable that candidate. Accepted origin ownership and completion outcomes
remain unchanged. Durable conclusions are summarized in the
[Root verdict memo](../memos/ROOT_NFQUEUE_VERDICT_OPTIMIZATION_MEMO.md).

Subsequent authorized implementation and comparison are recorded in the
[three-sender experiment](../testing/2026-10-11_ROOT_WHOLE_PATH_BATCH_EXPERIMENT.md#三种同窗口-verdict-发送器的对照--2026-10-12).
The research and isolated probe claims below retain their original scope.

## Conclusion and evidence status

**The inspected kernels support one Netlink datagram containing multiple
independent `NFQNL_MSG_VERDICT` messages.** The ordinary NFNETLINK receive path
walks every aligned `nlmsghdr` in one skb and invokes the NFQ verdict callback
for each message. Each message retains its own queue number, exact packet ID
and verdict; mixed ACCEPT/DROP requires no same-verdict range operation.
[Android netlink_rcv_skb, lines 2477–2519](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netlink/af_netlink.c#2477),
[Android nfnetlink_rcv, lines 642–660](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netfilter/nfnetlink.c#642),
[Android nfqnl_recv_verdict, lines 1225–1288](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netfilter/nfnetlink_queue.c#1225).

| Question | Status |
| --- | --- |
| One skb carrying several independent verdict messages | Established in matched Android and upstream source |
| Fewer datagram allocation/transport-dispatch operations than sendmmsg | Established call-count mechanism |
| One total security check or one NFQ lock per packed datagram | False: important checks and NFQ work remain per message |
| Atomic all-or-nothing handler execution | False: ordinary message errors can coexist with successful neighbors |
| Positive send result confirms each NFQ callback/reinjection | False: it reports the native transport operation |
| Positive full send can preserve current `SUCCEEDED` operation semantics | Compatible with the accepted current contract; no ACK wait is implied |
| Product correctness and CPU/p99 improvement on the device | Untested for this candidate |

## Pinned sources and scope

The retained profiles identify device kernel
`6.1.134-android14-11-g66e758f7d0c0-ab13748739`. The matching official Android
Common commit is `66e758f7d0c01a696c3a9db8929417e7403a1571`, tree
`3af870e65f83f28194791550ffe26f13f58eb1c7`; its Makefile specifies 6.1.134.
[Retained device metadata](../../build-output/root-sendmmsg-20261012/runs/dense0-B/graphs/root-udp-fixed-hotspots.json),
[Official commit metadata](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571?format=JSON),
[Official Makefile](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/Makefile#2).

Upstream comparison uses Linux v6.1 commit
`830b3c68c1fb1e9176028d02ef86f3cf76aa2476`.
[Release commit](https://github.com/torvalds/linux/commit/830b3c68c1fb1e9176028d02ef86f3cf76aa2476).
Android sources were retrieved from the official Gitiles `?format=TEXT` API.
Upstream raw files were checked against the same pinned commit on
kernel.googlesource.com and matched. All cited line numbers below are actual raw
source lines; browser text rendering can collapse blank lines and is unsuitable
for deriving source anchors.

Matching the advertised kernel suffix does not identify vendor-module binaries,
KernelSU additions, enabled LSMs, SELinux policy or the full device kernel build
configuration. Source support is therefore a strong feasibility result, not a
device execution or supported-device claim. No POC or removed C++ source was used.

## Wire shape and ordinary dispatch

The candidate datagram consists of adjacent independent messages:

```text
one send operation to the origin lane's Netlink FD
  [nlmsghdr + nfgenmsg(queue) + NFQA_VERDICT_HDR(id A, ACCEPT)]
  [nlmsghdr + nfgenmsg(queue) + NFQA_VERDICT_HDR(id B, DROP)]
  [nlmsghdr + nfgenmsg(queue) + NFQA_VERDICT_HDR(id C, ACCEPT)]
```

Each `nlmsg_len` describes only its own message. The next message starts at
`NLMSG_ALIGN(nlmsg_len)` from the current message. The send length is the sum of
those aligned message lengths, not the first message's length. Every message
requires `NLM_F_REQUEST`; the current no-success-ACK behavior can keep that as
the sole Netlink header flag. `NLM_F_MULTI`, `NLMSG_DONE`, a syscall `MSG_BATCH`
flag and `NFNL_MSG_BATCH_BEGIN/END` are not required for ordinary concatenation.
[Android Netlink UAPI, lines 52–117](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/include/uapi/linux/netlink.h#52),
[Ordinary message walker, lines 2485–2515](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netlink/af_netlink.c#2485).

The actual path is one transport allocation/copy and Netlink unicast, followed
by one NFNETLINK receiver invocation and several ordinary message callbacks.
The receiver checks the datagram and capability, then selects ordinary dispatch
unless its first message is `NFNL_MSG_BATCH_BEGIN`. For each ordinary message,
`nfnetlink_rcv_msg` parses attributes only within that message's declared length
and performs the registered NFQ callback under RCU.
[Android netlink_sendmsg, lines 1778–1865](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netlink/af_netlink.c#1778),
[nfnetlink_rcv_msg, lines 216–314](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netfilter/nfnetlink.c#216),
[NFQ callback registration, lines 1434–1466](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netfilter/nfnetlink_queue.c#1434).

This is separate from the NFNETLINK transactional batch protocol. That protocol
requires batch-capable callbacks and subsystem commit/abort/generation methods;
NFQ registers ordinary RCU verdict callbacks and no such transaction methods.
It is also separate from `NFQNL_MSG_VERDICT_BATCH`, which consumes a queue-ID
prefix under one common verdict. Neither mechanism is needed to pack distinct
messages, and neither should be substituted for their exact packet identities.
[Android transaction prerequisites and callback type, nfnetlink_rcv_batch](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netfilter/nfnetlink.c#377),
[NFQ range-verdict implementation, lines 1113–1160](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netfilter/nfnetlink_queue.c#1113).

Upstream v6.1 independently has the same ordinary receiver/walker/verdict shape.
[Linux netlink_rcv_skb, lines 2514–2556](https://github.com/torvalds/linux/blob/830b3c68c1fb1e9176028d02ef86f3cf76aa2476/net/netlink/af_netlink.c#L2514),
[Linux nfnetlink_rcv, lines 642–660](https://github.com/torvalds/linux/blob/830b3c68c1fb1e9176028d02ef86f3cf76aa2476/net/netfilter/nfnetlink.c#L642),
[Linux nfqnl_recv_verdict, lines 1192–1256](https://github.com/torvalds/linux/blob/830b3c68c1fb1e9176028d02ef86f3cf76aa2476/net/netfilter/nfnetlink_queue.c#L1192).

## What can be amortized, and what cannot

For N valid minimal verdicts with no requested success ACKs and no handler
errors, compare the existing single sendmmsg window with one packed datagram:

| Operation | Existing N-message sendmmsg | One packed datagram |
| --- | --- | --- |
| User/kernel syscall entry | One | One |
| Outer socket lookup | One | One |
| Outer `security_socket_sendmsg` | Normally first message only for the same destination, already cached by sendmmsg | One |
| Netlink `scm_send`, size/bound checks, transport skb allocation and transport copy invocation | N | One |
| `security_netlink_send` hook invocation | N | One, but the SELinux hook still walks N message headers |
| Netlink destination lookup, receiver skb ownership/accounting and receive invocation | N | One |
| Receiver `netlink_net_capable(..., CAP_NET_ADMIN)` invocation | N | One |
| Ordinary NFNETLINK message validation, attribute parsing and RCU callback dispatch | N | N |
| NFQ queue lookup, peer-port authorization, exact-ID search/removal and queue locking | N | N |
| Original packet reinjection/local delivery/driver work | N | N |
| Logical product verdict attempts and packet settlements | N | N |

The transport counts follow
[netlink_sendmsg](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netlink/af_netlink.c#1778),
[netlink_unicast_kernel, lines 1300–1319](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netlink/af_netlink.c#1300),
[skb receiver ownership/accounting, lines 386–393](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netlink/af_netlink.c#386),
[receiver capability check](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netfilter/nfnetlink.c#642),
and [existing sendmmsg same-destination security shortcut, lines 2491–2519](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/socket.c#2491).
The per-message work follows
[nfnetlink_rcv_msg](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netfilter/nfnetlink.c#216),
[find_dequeue_entry, lines 206–226](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netfilter/nfnetlink_queue.c#206),
and [nfqnl_recv_verdict](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netfilter/nfnetlink_queue.c#1225).

`security_netlink_send` calls the enabled LSM hooks. The inspected SELinux hook
scans every aligned Netlink header;
for `NETLINK_NETFILTER_SOCKET`, its message permission-table lookup takes the
unhandled-class path rather than establishing a new per-verdict permission
mapping. Other configured/vendor hooks may differ. A single hook invocation
therefore does not establish that all security work becomes constant per group.
If an enabled hook rejects a later header, that scan occurs before receiver
dispatch and can reject the entire datagram before any NFQ callback runs.
[Android security_netlink_send, lines 2126–2129](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/security/security.c#2126),
[SELinux netlink_send, lines 5963–6019](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/security/selinux/hooks.c#5963),
[SELinux message-class mapping, lines 168–218](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/security/selinux/nlmsgtab.c#168).

One packed transport copy still copies approximately the same verdict bytes as
N separate transport copies. The source establishes fewer allocation/copy
invocations and metadata operations, not an N-fold reduction in bytes moved or
an N-fold speedup. The normal callback loop remains sequential on the sending
worker, with per-message RCU sections; it does not execute the group's verdicts
in parallel or acquire the NFQ queue lock only once.

## Shared skb assumptions

The shared skb is the userspace command datagram. The walker advances its data
pointer with `skb_pull` only after the current callback/ACK step. The minimal
NFQ callback reads the transport skb's peer port ID and reads the current
`nfgenmsg`/attributes; it does not consume, retain or pull that transport skb.
Packet mutation and reinjection concern `entry->skb`, the original queued packet,
not the command datagram. Attribute parsing uses `nlh->nlmsg_len`, preventing
the next message's attributes from being incorporated into the current one.
These are established for the current minimal verdict shape; optional payload,
bridge or conntrack extensions should be audited independently if later added.
[Android walker](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netlink/af_netlink.c#2477),
[message attribute boundaries](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netfilter/nfnetlink.c#253),
[minimal and optional NFQ callback branches](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netfilter/nfnetlink_queue.c#1225).

## Errors, continuation and ACKs

**Transport result and handler result are distinct.** `netlink_unicast_kernel`
records the original skb length before calling the void receiver and returns
that length afterward. The ordinary walker returns zero even when a message
callback returned an error. Thus sendto/sendmsg can return the full datagram
length after one or more individual verdicts failed validation or found no
queued packet. The same distinction already exists with scalar verdict sends
and each sendmmsg element; packing does not create it.
[Android netlink_unicast_kernel](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netlink/af_netlink.c#1300),
[Android netlink_rcv_skb](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netlink/af_netlink.c#2477),
[Linux v6.1 equivalents](https://github.com/torvalds/linux/blob/830b3c68c1fb1e9176028d02ef86f3cf76aa2476/net/netlink/af_netlink.c#L1307).

| Failure location | Handler execution and continuation | Observable transport/reply behavior |
| --- | --- | --- |
| sendto import/copy, invalid destination/flags, allocation or pre-dispatch LSM rejection | Receiver has not run for this datagram | Negative send result; no per-message successful prefix is returned |
| Outer NFNETLINK capability rejection | No verdict callback runs | Receiver attempts one EPERM error reply for the first header; the transport can still return full datagram length |
| Ordinary callback error, such as missing queue, peer mismatch, absent verdict attribute or unknown packet ID | That message fails; later well-framed messages continue; earlier successful messages are not rolled back | Receiver attempts that message's error reply even without `NLM_F_ACK`; transport result does not count successful handlers |
| Invalid `nlmsg_len` at the first or a later header | Walker stops at that header; a previously handled prefix remains handled; current/tail messages are unprocessed | No framing-error ACK from this check; transport can still return full length |
| Header lacks `NLM_F_REQUEST`, is a reserved control type, or has too-short NFNETLINK body | Current message is skipped/no-op; normal traversal can continue | Not a proof of verdict handling; no success reply unless requested |

The first row follows
[Android sendto, lines 2110–2148](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/socket.c#2110)
and [Netlink send path](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netlink/af_netlink.c#1778).
The remaining rows follow
[NFNETLINK receiver](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netfilter/nfnetlink.c#642),
[ordinary walker](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netlink/af_netlink.c#2477),
[short NFNETLINK body check](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netfilter/nfnetlink.c#224),
and [NFQ validation](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netfilter/nfnetlink_queue.c#1225).
The walker also special-cases a callback result of `-EINTR`: it skips ACK for
that message and proceeds. This is a generic walker behavior, not a normal
return from the current minimal NFQ verdict callback.

Netlink supports optional success ACKs per message through `NLM_F_ACK`, and
attempts error responses for ordinary nonzero callback results regardless of
that flag. `netlink_ack` constructs `NLMSG_ERROR`, carrying the error and original
request header/sequence; uncapped errors also include the original message
body. Responses have their own allocations and receive-socket pressure, and
can fail or be lost. There is no one final aggregate ACK for the packed group.
[Android netlink_ack, lines 2416–2474](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netlink/af_netlink.c#2416),
[per-message ACK selection](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netlink/af_netlink.c#2503),
[Linux v6.1 netlink_ack/walker](https://github.com/torvalds/linux/blob/830b3c68c1fb1e9176028d02ef86f3cf76aa2476/net/netlink/af_netlink.c#L2466).

The current product deliberately requests no verdict success ACK, leaves header
sequence zero, and performs native-operation accounting. Its receive path does
not correlate control replies into per-packet handler outcomes: an `NLMSG_ERROR`
is not admitted as `NFQNL_MSG_PACKET`, and a control-only envelope currently
falls through the unadmitted-envelope identity-loss diagnostic. Enabling success
ACKs would therefore be a separate receive/control and correlation change, with
additional cost; it is not required by this batching mechanism.
[Product verdict flags](../../src/product/vpp/product_root_nfqueue_adapter.c:645),
[Product receive envelope validation](../../src/product/vpp/product_root_nfqueue_adapter.c:1384),
[Unadmitted-envelope accounting](../../src/product/vpp/product_root_nfqueue_adapter.c:836).

Preserve the accepted contract: a trusted full native send result can settle
each included logical verdict as `SUCCEEDED`; that means the native terminal
operation completed, not that every handler accepted its ID or that downstream
delivery succeeded. A known pre-dispatch rejection can settle the included
operations as `FAILED_DEFINITE`. Unexpected short/ambiguous results must retain
the existing conservative `OUTCOME_UNKNOWN` distinction. Lack of success ACKs
alone is not a reason to mark every normal send unknown or introduce a new
waiting queue. Never retry a packed datagram after dispatch uncertainty: it may
reissue verdicts for already consumed IDs.
[Accepted completion contract](../decisions/PER_WORKER_FLOW_OWNERSHIP.md:113),
[Current product settlement](../../src/product/vpp/product_root_nfqueue_adapter.c:1050),
[Current no-physical-retry sendmmsg boundary](../../src/product/vpp/product_root_nfqueue_adapter.c:1120).

| Packed send observation | Current-contract settlement of the included identities |
| --- | --- |
| Trusted return equals the complete packed byte length | Each `SUCCEEDED` for its native operation; no per-ID handler or delivery confirmation claimed |
| Known pre-dispatch negative sendto result in the selected kernel-port-0 path | Each `FAILED_DEFINITE`; no handler prefix has executed |
| Unexpected short positive return | Each `OUTCOME_UNKNOWN`; no trustworthy per-message prefix can be derived |
| No trustworthy result because the operation/process is interrupted ambiguously | Preserve existing unknown/reclaim handling; never resend the group |

A narrow documentation clarification follows: “NFQUEUE does not
provide an independent ACK” is too absolute for these kernels. The accurate
current-product statement is: “The product does not request or await per-verdict
success ACKs; its observed send result establishes native-operation completion,
not per-ID handler confirmation or downstream delivery.” This report recommends
that wording clarification without changing the outcome contract or adding an
ACK protocol.

## Bounded origin grouping and storage

The current builder creates a minimal 32-byte verdict: 16-byte `nlmsghdr`,
4-byte `nfgenmsg`, and a 12-byte aligned `NFQA_VERDICT_HDR` attribute containing
two 32-bit fields. The origin window is at most 16 messages, so the present
shape fits in a fixed 512-byte packed buffer. This is a current-shape derivation,
not a size promise for future payload or optional-attribute messages.
[Product fixed request and builder](../../src/product/vpp/product_root_nfqueue_adapter.c:637),
[Product window bound](../../src/product/vpp/product_packet_batch.h:7),
[nfgenmsg UAPI](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/include/uapi/linux/netfilter/nfnetlink.h#34),
[verdict header UAPI](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/include/uapi/linux/netfilter/nfnetlink_queue.h#70).

A contiguous bounded buffer plus one sendto, or one sendmsg with one contiguous
iovec, is a straightforward candidate. One sendmsg with N iovecs also creates
one transport datagram, but 16 iovecs exceed the inspected `UIO_FASTIOV = 8` and
can allocate an imported iovec array in the kernel. It should not be presented
as unconditionally cheaper than constructing the small contiguous buffer.
[Android sendmsg stack iovecs, lines 2548–2566](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/socket.c#2548),
[UIO_FASTIOV](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/include/uapi/linux/uio.h#27),
[iovec_from_user allocation, lines 1730–1763](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/lib/iov_iter.c#1730).
Netlink also checks the total datagram against `sk_sndbuf - 32`; its allocator
can use a different large-buffer path beyond `NLMSG_GOODSIZE`. Fixed current
messages do not justify arbitrary future datagram growth.
[Android size/allocation checks](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netlink/af_netlink.c#1831),
[Netlink large-skb allocator](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netlink/af_netlink.c#1177).

Grouping must use only current, already prepared completions from the same
origin lane/FD, queue generation and send-flags value. Preserve the immutable
queue/packet ID/token association and the lane's live socket validation for
every item. The kernel validates each queue's peer port ID, while product queue
generation remains a userspace lifetime guard; it is not transmitted in the
minimal verdict. Pack each verdict independently, preserve current order, flush
when lane or flags change, and do not wait for future packets or introduce a
retained verdict queue. A fault flag such as MSG_OOB must not spread from its
one intended item to neighboring normal verdicts.
[Product prepare identity checks](../../src/product/vpp/product_root_nfqueue_adapter.c:943),
[Current lane/flags window grouping](../../src/product/vpp/product_root_nfqueue_adapter.c:1181),
[Kernel peer validation, lines 1077–1090](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netfilter/nfnetlink_queue.c#1077).

One syscall/datagram counter must remain separate from N logical verdict-attempt
and settlement counters. Keep the original live buffers until that current
native operation produces the trusted result, then apply the existing per-item
outcome and pool-return lifecycle. Single-item windows remain valid; grouping
does not require a full 16-message window or change the origin's exclusive FD
authority.
[Origin completion contract](../product/VPP_ROOT_BATCH_EXECUTION_SPEC.md:84),
[Product finish/return lifecycle](../../src/product/vpp/product_root_nfqueue_adapter.c:1050).

## Narrow host protocol and layout probes

Three read-only `NETLINK_ROUTE` GETLINK requests were sent in one 96-byte
datagram. Independent results were success, ENODEV, success, demonstrating the
ordinary walker continues after a middle callback error on that host.
[Probe result](../../build-output/root-verdict-datagram-research-20261012/probes/sakamoto-packed-netlink-probe.json),
[Probe source](../../build-output/root-verdict-datagram-research-20261012/probes/sakamoto-packed-netlink-probe.py).
Separately, uid 1000 with zero effective capabilities sent three ordinary NFQ
verdict messages without requested ACKs: sendto returned all 96 bytes, but only
the first message received EPERM from the global capability check. No queue was
configured and no verdict callback ran.
[Denial result](../../build-output/root-verdict-datagram-research-20261012/probes/sakamoto-packed-nfnetlink-denial-probe.json),
[Denial probe source](../../build-output/root-verdict-datagram-research-20261012/probes/sakamoto-packed-nfnetlink-denial-probe.py).
The actual request-union layout was also compiled with warnings as errors:
32-byte size/stride, alignment 4, and 512 bytes for 16 requests passed. The
existing contiguous `requests[]` can therefore be the candidate sendto buffer,
without a second userspace packing copy for this fixed shape.
[Layout source](../../build-output/root-verdict-datagram-research-20261012/probes/sakamoto-packed-verdict-layout.c),
[Layout result](../../build-output/root-verdict-datagram-research-20261012/probes/layout-result.json).
These host probes do not prove live NFQ mixed-verdict execution on Android or
performance gains; they supplement the pinned-source feasibility result.

## Existing CPU evidence and the remaining hypothesis

An offline reanalysis of all six retained dense A/B client-window perf records
separates visible callchain categories. In the existing sendmmsg B samples,
reinjection accounts for 42.31% of sampled VPP process CPU, NFQ callback work
without visible reinjection 1.39%, Netlink without a visible NFQ callback 10.72%,
and syscall frames without visible Netlink 3.28%. The Wi-Fi path's inclusive
18.60% and queue_work_on leaf's 13.66% overlap the reinjection category.
[Reproducible stack attribution](../../build-output/root-verdict-datagram-research-20261012/stack-attribution.json),
[Analysis script](../../build-output/root-verdict-datagram-research-20261012/analyze-attribution.py).

These are visible-stack partitions, not intrinsic function time or an achievable
speedup budget. They cover the sampled VPP process, excluding the capture app
and later driver workers; cpu-clock does not measure off-CPU waiting or establish
p99 causes. A packed datagram could reduce some transport work within the
Netlink category, while per-message parsing and downstream reinjection remain.
No reducible fraction or performance improvement is established.

A fresh comparison should hold origin dispatch timing constant while selecting
sendmmsg versus packed sendto within the same current window. Historical scalar
OFF sends earlier than the batch-ON reclaim flush; comparing it directly also
changes waiting/dispatch timing. A three-sender study would need one common
window schedule to isolate sender cost, with the historical timing difference
recorded explicitly.

Before a performance conclusion, a bounded implementation experiment would need
to distinguish: mixed exact-ID verdict handling; valid messages around an
intentional bad-ID/attribute error; malformed-header prefix/tail behavior;
whole-datagram pre-dispatch rejection; lane/generation/flags boundaries; scalar
and partial windows; and exactly-once buffer/debt settlement through stop/restart.
Any device CPU/p99 comparison must use the same qualified-packet denominator and
retained outcome/delivery evidence as the existing experiment. These are proposed
discriminators, not executed tests or a new tracker backlog.

The research wrote this report and temporary source caches. No product/test
source, defaults, device state, new benchmark capture, Plane records or commits
were changed; the [source closure proof](../../build-output/root-verdict-datagram-research-20261012/source-and-layout-proof.json) retains the unchanged Product identity.
