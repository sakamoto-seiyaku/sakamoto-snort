---
status: accepted
date: 2026-10-21
---

# Configurable FlowOwners and a dedicated VPN TUN I/O worker

At the time of this decision, the Product runtime used two FlowOwner workers
and performed TUN reads and writes on the first one. That count was an
architectural requirement. An experiment with an external TUN pthread inserted
an Adapter-to-VPP whole-packet copy and a separate write-result route; it was
withdrawn because those costs violate the accepted direct-materialization and
native-completion contracts. Its raw measurements remain historical evidence,
not acceptance of that implementation.

The intended Worker Layout contains a startup-configured number `N >= 1` of
equally participating FlowOwner workers. It is not restricted to two, even
numbers, or powers of two, and remains immutable for one runtime generation.
Canonical owner selection remains the existing direct `hash % N` distribution;
CPU placement neither enters the hash nor changes any worker's weight.
There is no additional arbitrary Product maximum: startup must reject counts
that exceed the pinned VPP thread limit or resources needed for the complete
per-worker state and bounded queues. Root launches `N`
VPP workers for its existing NFQUEUE lanes. VPN launches `N` FlowOwner workers
and one further VPP worker dedicated to the sole TUN Platform I/O Lane. The
main VPP thread is separate. The I/O worker is excluded from Canonical Owner
Key hashing, FlowEntry, policy and HEV ownership. Thread and lane identity
never enter the canonical key.

The VPP owner workers occupy logical positions `0..N-1`; VPN's I/O-only worker
is appended at position `N` (VPP thread index `N+1`). Root has no TUN worker.
This keeps each FlowOwner's logical position independent of the platform lane.
The Product graph must compare its owner count with the profile's expected VPP
thread topology rather than equating it to `vlib_num_workers()` in both profiles.
Root NFQUEUE lane count remains a separate Adapter setting; each lane may start
on an ingress worker and the shared selector still sends every valid packet to
its `hash % N` owner.

Each of the `N` FlowOwners has an explicit ordered CPU binding. An owner CPU
may appear more than once: `N=3` with bindings `1,2,1` launches three separate
FlowOwners on two CPUs. The number of bindings must equal `N`; the runtime
never assigns an unbound worker to a CPU implicitly. VPN additionally requires
an explicit `tunIoCpuId`; absence of that setting is a startup error, with no
implicit CPU choice or compatibility fallback. All chosen CPUs must be online
and allowed by the process affinity. The I/O CPU must differ from the
main-thread CPU and every owner CPU; owner CPUs may repeat. Invalid placement
fails before packet capture begins. The current Android and pinned VPP
`ordered-workers` duplicate-CPU rejection must be deliberately revised to
support this explicit shared-core binding.

The VPN I/O worker reads TUN packets directly into exclusively owned VPP
buffer data. It performs the shared stateless L3 parse and one canonical owner
selection, then transfers the original buffer index and bounded metadata to
the selected FlowOwner. It does not run owner-local policy, FlowEntry or HEV.
Normal TUN ingress therefore has one buffer-index handoff to its owner, even
when that owner would formerly have been local to the TUN callback. The
fragment-steering exception retains its existing bounded reassembly and final
owner rules. There is no Adapter scratch-packet queue or additional
Adapter-to-VPP full-packet copy.

Invalid or incomplete ingress remains an origin-lane runtime fault, with no
fabricated FlowOwner state. On buffer exhaustion, the lane does not consume a
TUN packet into scratch storage; it applies the existing bounded capacity-fault
behavior without spinning or allocating an unbounded queue. On a primary
handoff rejection, it retains and settles the same buffer under the existing
capacity-fault policy; it never reroutes to another owner or runs owner-local
state on the I/O worker. Completion-frame congestion uses the existing
bounded native return/retry route, carrying indexes and metadata only.

The owner-local VPN Flow Stack boundary retains its accepted independent
VPP/lwIP storage copies. Return packets still traverse the shared graph.
Terminal completion routes their original live VPP buffer index back to the
dedicated TUN origin lane. That lane performs the existing single nonblocking
TUN `write`, records its immediate result, settles the obligation and frees
the native buffer. No separate write-result callback, borrowed asynchronous
payload, new completion ledger, payload copy, or retry is introduced.
Short writes and `EAGAIN` remain failed completion attempts, not a reason to
retain a packet for an unbounded retry or claim downstream delivery.
The one event-driven lane must make bounded progress on both ready TUN reads
and queued completion writes under sustained traffic, without busy polling or
depending on a later unrelated packet to wake it.

Per-owner flow/session state, return allowances, expiry, observation and
handoff accounting must be provisioned for the selected `N` before admission.
Capacity arithmetic must be checked before allocating; a partial startup
releases what it obtained and does not silently reduce `N`. Quiesce stops new
TUN reads first, retains completion and transport progress through the bounded
drain, then closes the TUN lane only after all original and return-buffer
obligations are settled. No packet or token crosses a runtime generation.

At the decision date, fixed-two assumptions spanned the graph and fragment routes,
FlowEnd/expiry, VPN Flow Stack and return credits, observation transport and
status ABI, Root lane placement, Android worker placement, and the pinned
VPP `ordered-workers` duplicate-CPU check. Implementing this decision required
each to use the configured owner count or the distinct VPN I/O thread index
as appropriate; changing the graph constant alone is not sufficient. The
TUN origin obligation must identify the dedicated lane without being mistaken
for a FlowOwner. Stateless admission must accept that origin context without
allowing owner-local nodes to run there.

Acceptance of this decision was not evidence that Product code or an artifact
passed. Functional qualification must include `N=1`
and multiple-owner VPN and Root paths, direct TUN buffer materialization,
canonical owner identity, exactly-once completion and clean stop/restart.
Performance results, including the former local-owner path, must be reported
without silently imposing an adoption or rollback threshold; that decision
belongs to the user after measurements.

The [pinned-VPP throwaway prototype](../testing/2026-10-21_VPN_TUN_IO_WORKER_PROTOTYPE.md)
proves only the isolated Host thread/buffer-index mechanism and a temporary
duplicate-CPU startup modification; it is not Product or Android acceptance.
The subsequent [S303 Product functional qualification](../testing/2026-10-22_S303_ANDROID_CONFIGURABLE_TOPOLOGY.md)
covers controlled Pixel Root and VPN `N=1`/`N=3` paths, while
[S304](../testing/2026-10-22_S304_VPN_IO_PERFORMANCE.md) reports the measured
performance trade-off. These records do not select an adoption or rollback
threshold; that decision remains with the user.

## 2026-10-22 Accepted packet-path and batching decisions

After reviewing S306–S308, the user adopts the following design. These choices
supersede the earlier unresolved parameter/adoption discussion for these items;
they do not claim that the measurements established a whole-path CPU benefit.
Implementation and qualification follow this design update through S308.

### Generation topology and primary capacity

Startup validates the requested topology before enabling admission and stores
the generation's owner count and Adapter kind in the graph. Packet-path origin
and owner-return checks use that immutable, validated graph state instead of
reparsing startup environment variables. Restart validates and publishes the
new generation independently. Invalid topology, stale generation, invalid
origin, per-owner identity and exactly-once settlement remain checked.

VPN primary handoff defaults to **48 packet credits per target owner**. Root's
already selected 48-credit default remains. These packet credits do not change
native frame-queue element counts or promise a 48-packet native frame. Explicit
bounded diagnostic overrides, including 32 and zero, remain separate settings
with their existing empty-graph configuration constraints.

### Ready-capture batch

A capture batch contains original VPP buffer indexes and metadata for packets
already read during one TUN readiness callback. Each packet is still read
directly into its exclusive VPP buffer. The default capture submission threshold
and callback read budget are both **64 packets**, independent of the TCP
experiment flag.

- Submit the collected captures when 64 have been collected or a nonblocking
  read returns `EAGAIN`/`EWOULDBLOCK`.
- Also submit the valid partial batch on any callback exit, including budget,
  capacity, allocation failure, interruption, read error or shutdown handling;
  settle rejected items through their existing individual obligations.
- `EAGAIN` means the fd is temporarily drained. Reaching a budget or capacity
  bound does not prove it is drained. Remaining runnable/readiness work must
  retain progress without depending on a future unrelated packet.
- Do not wait for future packets, retain a capture batch across callbacks or
  add a timer, persistent staging queue, payload copy or busy polling.

The shared graph still selects each canonical owner and partitions publications
using the unified windows below and available per-owner credits.
A 64-capture submission is not a promise of one 64-vector frame per owner.
The bounded callback yields execution opportunities to completion/write work
under continuous ingress.

### Return graph batching and TUN writes

HEV/lwIP continues to produce individual return packets; multiple spans describe
one packet's storage, not a batch of independent packets. Each accepted return
is copied into its independently owned VPP buffer under ADR-0007 and traverses
the normal return parser/policy graph before TUN completion.

Group already available returns through native owner-local graph frames,
completion handoff to the dedicated I/O worker and consumption of the received
frames. Reuse native frame scheduling and existing completion batching rather
than introducing a separate persistent return queue or waiting to fill a batch.
Output callbacks retain their acceptance result and return before the submitted
return graph executes. Per-flow ownership/order, partial rejection and bounded
completion congestion retain their existing semantics.

Return batching is independent of unrelated TCP experiment settings. The user
subsequently accepts the unified handoff and completion windows below. These
windows group independent packet operations; they do not introduce a batched
TUN write syscall.

The I/O worker still performs **one nonblocking TUN write per packet** and
records that packet's immediate result before its own settlement/free. Short
writes and `EAGAIN` remain failed individual attempts. A batch does not become a
single delivery acknowledgement, multi-packet TUN syscall or retry unit. No
extra packet copy, asynchronous borrowed payload, completion ledger, owner
rerouting or new retry policy is introduced.

### Unified handoff and completion windows

After distinguishing packet capacity from execution windows, the user selects
**64 packets** as the common bounded window for this path:

| Stage | Selected window |
| --- | --- |
| TUN ready-capture collection and callback read budget | 64 packets |
| Primary handoff publication | Up to 64 packets across canonical target owners |
| Normal completion handoff publication | Up to 64 packets |
| Existing completion retry window | Up to 64 candidates |
| Origin/I/O completion consumption and native reclamation | Up to 64 packets per settlement/free window |

Replace the former Product-specific 16-packet primary publication, normal
completion publication and origin reclamation windows. All associated index,
metadata, result-mask and rejection arrays must support the selected bound.
Share an explicit window definition where the same execution bound applies;
do not leave an implicit 16-packet split in another part of this path.

Primary credits remain **48 per target owner** and are reserved per packet
before publication, then returned when that owner receives the handoff at its
processing entry, or when the publisher settles a failed enqueue. They do not
cover the packet's entire graph/transport/completion lifetime. A mixed-owner
publication can contain 64 packets; the single-owner credit limit must not
become a global 48-packet publication cap. Exhaustion flushes already collected
work and uses the existing bounded admission/failure path without waiting for
credits, rerouting or adding storage. One 64-packet capture is not guaranteed
admission of all 64 to one owner.

Owner-local return graph scheduling retains the pinned VPP native frame
capacity, **256 buffer indexes**. It does not wait for 256 packets, recursively
run the return graph from the HEV output callback, or impose a new 16-packet
split. The following completion handoff and origin consumption use the selected
64-packet windows. TUN completion still attempts each packet's write once and
settles each independently; reclamation releases each return stamp/credit only
after that packet's buffer has actually been freed.

Every window submits available work at its bound and flushes any valid partial
work before returning. Received native graph frames larger than 64 are consumed
in bounded 64-packet windows with a final partial window. Readiness, retry
rearming, owner order and stop/drain retain progress under continuous traffic
and congestion. No fill timer or new persistent packet queue is introduced.

Native frame capacity, native queue element counts, packet credits, policy
snapshot claim cadence and parser/prefetch loop unrolling are distinct units.
This decision does not change queue capacities, Root's platform receive budget,
the policy snapshot claim cadence or parser unrolling just to match the number
64. Existing Root and VPN paths sharing these handoff/completion helpers must
both be qualified. Historical measurements do not establish that this new
combined configuration is a CPU optimum.

### Qualification and historical evidence

Qualify the combined implementation at its selected defaults: generation and
topology rejection/restart; capture full and partial exits; native return graph
scheduling; mixed packet outcomes and rejection positions; per-packet write
failure; credit/stamp/buffer conservation; readiness progress; and bounded
stop/drain for Root and VPN at N=1 and N=3. Frame-pressure faults must actually
exercise their stated cause; a held-completion test is distinct from a native
ring-full test. Preserve explicit diagnostic configurations where needed.

S304–S308 measurements keep their original source/artifact identities and
32-credit/scalar control labels. They do not measure this combined adopted
configuration. Adoption is the user's design decision; fresh functional
qualification and any later performance evidence are reported separately.
