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
