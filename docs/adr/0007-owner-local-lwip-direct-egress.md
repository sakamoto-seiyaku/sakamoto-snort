---
status: accepted
date: 2026-08-12
---

# Owner-local lwIP direct egress for Android VPN

Android `VpnService` gives an unprivileged application an L3 TUN interface. After Sakamoto/VPP permits an
outbound packet, Android provides no public operation that submits that original packet to the kernel's
ordinary TCP/UDP egress or NAT path. `VpnService.protect()` applies to a socket created by the application; it
does not turn a TUN packet into a kernel flow. Direct forwarding therefore requires a userspace flow stack
that terminates the inner TCP/UDP packet flow, operates protected kernel sockets, and synthesizes return L3
packets.

Sakamoto selects the lwIP family and uses a project-owned HEV fork as the starting implementation. HEV is
chosen because it already combines lwIP, TCP/UDP session lifecycle, Android/NDK support, and socket bridging;
it is not retained because SOCKS5 defines the product. The first release has one VPN forwarding mode:
Direct Egress to the original IPv4/IPv6 TCP or UDP destination. SOCKS5 is only a possible later explicitly
selected connector. If it is ever enabled, its failure never falls back implicitly to Direct.

The current external HEV child and `SOCK_SEQPACKET` seam remain useful correctness evidence but are not the
target product architecture or evidence of minimized copying. The target is a heavy VPN Userspace Flow Stack
inside the VPP-native VPN Adapter architecture. This refines the VPN portion of ADR-0006: Android TUN I/O may
begin at one Platform I/O Lane, but post-policy transport is distributed by the existing Canonical Flow Key
and fixed FlowOwner ownership rather than funnelled through one global HEV/lwIP runtime.

## Packet and flow model

Packets remain the unit crossing the VPP/lwIP boundary. Flow state exists in two related but distinct domains:

- the VPP `FlowEntry` owns shared policy facts, recognition, activity, accounting, and the canonical
  bidirectional owner;
- the HEV/lwIP transport flow owns PCB/session state, timers, buffering, and the protected Direct socket.

The two domains are aligned by the direction-independent canonical five-tuple and FlowOwner, but they are not
the same object and do not acquire a shared lifecycle. This ADR does not reinterpret a packet verdict as a
transport-flow lifecycle command. A packet permitted for VPN egress may be consumed by an existing or newly
created transport flow; a packet not permitted for egress is simply not handed to that flow stack.

Each packet also carries immutable VPN Packet Provenance. A TUN-origin packet that completes the normal shared
graph at the forwarding exit goes to its owner-local egress shard. A flow-stack-origin return packet re-enters
the normal shared packet graph, selects the same canonical FlowOwner, and completes at Android TUN. Provenance
does not enter the flow key and is never inferred from flow-relative `ORIG/REPLY`. This distinction is a
first-order anti-loop invariant: a synthesized return packet cannot be routed back into lwIP, while lwIP
cannot bypass VPP and write directly to TUN.

## Owner-local execution

VPN egress remains local to the packet's canonical VPP FlowOwner. The egress path does not introduce a second
hash, migrate a live flow, spill work to another owner under load, or funnel every owner through a
process-global transport-state authority. This locality invariant does not itself select the number or layout
of HEV/lwIP state domains.

Real pinned-source and target-device POCs select the concrete instance-isolation shape, mutable-state
partition, shard count, and execution topology. Owner-inline nonblocking work and statically paired native
threads remain candidates until that evidence closes. A FlowOwner-local Egress Shard is therefore an
ownership-locality term, not a promise of one HEV/lwIP instance or one OS thread per FlowOwner.

### 2026-08-23 POC evidence-selected topology

The bounded OI1–OI5 evidence recorded in
`experiments/vpp-nfq-poc/OI_REQUIREMENT_AUDIT.md` selects the owner-inline
external-driver topology as the current Evidence-backed Architecture Baseline.
Each canonical FlowOwner owns and drives its opaque Flow Stack shard; only that
owner executes HEV/lwIP mutable callbacks.  A wait-only helper may publish
opaque generation-tagged fd/timer wakes, and an Android broker may perform
underlay bind and `VpnService.protect()`, but neither owns transport state or
executes Flow Stack callbacks.  Shards remain fixed and owner-local, with no
live migration, overload spill, process-global mutable transport authority, or
global lwIP core lock.  Paired-thread execution is no longer the default
candidate.

This is a revisable POC evidence selection, not production completion.  An
ordinary harness or implementation-seam correction does not reopen the
topology decision; contradictory higher-fidelity evidence or a material new
platform constraint may. Worker/shard counts, capacity, timer budgets, exact
copy/release call sites, performance tuning, and release lifecycle remain
evidence-selected implementation questions within the copy-based contract below.

VPP workers never wait for socket I/O, socket protection, timers, name resolution, or capacity. Owner-inline
work is nonblocking and budgeted. Exhausted flow capacity rejects new PCB/session/socket creation without
evicting existing flows. Exhausted packet-handoff or buffer credit discards only the current packet without
implicit flow termination. Neither case changes Policy Verdict or permits Direct bypass; sustained overload
is explicit Runtime-health evidence.

## Buffer ownership and copying

Zero-copy is a performance goal, not an absolute product claim. The VPN Flow Stack Packet Boundary must have
bounded, exactly-once ownership settlement, and an asynchronous consumer never retains an unprotected borrowed
pointer. The 2026-09-05 decision below selects independent copy-based storage; real VPP/lwIP experiments
verify its concrete call sites, ownership settlement, and capacity rather than reopening that selection.

Every full-payload copy requires a named lifetime or protocol reason and measurement. Removing a copy never
takes priority over buffer conservation, generation safety, bounded credits, or teardown correctness; this
ADR does not require custom pbuf adoption or lwIP allocating output directly from VPP-owned storage.

### 2026-09-05 KISS copy and ownership contract

Keep the two ownership-interface copies: VPP input buffer to lwIP-owned storage, and lwIP output to a new
VPP-owned buffer. S121/S122 establish the bounded two-direction copy evidence; S125's final stage decision
retains that path without starting zero-copy or lwIP memory-model redesign. Its formal investment campaign
remains `INCONCLUSIVE`; the engineering direction is accepted, not a claim of completed production performance
validation. The two copies do not count all movement inside lwIP or the kernel.

- Input: the Flow Stack may read the original VPP buffer during the input call, but retains no asynchronous
  reference to that buffer or its metadata after the copied handoff. VPP retains responsibility for its buffer
  through the existing Adapter Completion and native free lifecycle; it does not wait for a network reply.
  A completed `memcpy` alone does not authorize freeing storage still used by the call or its completion.
- Output: the original pbuf follows the pinned lwIP callback's ownership and lifetime rules; VPP does not
  arbitrarily free it or retain a borrowed pointer for later graph work. After copying, the new VPP buffer
  has an independent lifetime. Its current holder settles failures before graph acceptance; after acceptance,
  the graph owns its completion/free path. VPP processing does not extend the original pbuf's borrowed lifetime.
- Rejection and partial allocation failure settle each side's own resources exactly once. Flow Stack
  acceptance means data handoff, not delivery; failure does not rewrite Policy Verdict. Do not add shared
  buffer ownership, cross-module reference counting, a generic packet map, or an asynchronous input-return
  protocol to support this copy-based interface.

SAKAMOTO-245, SAKAMOTO-246 and SAKAMOTO-247 respectively verify input settlement, output settlement and
simultaneous resource occupancy on Pixel using real pinned HEV/lwIP and the current experiment artifact.
They are evidence inputs to SAKAMOTO-237, not prerequisites that require S237 itself to be complete, and
not substitutes for its product-artifact acceptance. Experimental pbuf/credit counts are not product defaults.
Contradictory evidence pauses the affected path for review; it does not silently authorize shared storage.

### 2026-09-05 Output callback and graph scheduling

The lwIP output callback copies the packet into a new VPP-owned buffer, fills the minimal return facts,
and submits that buffer to normal VPP graph scheduling on the same canonical owner, then returns.
The callback does not recursively execute the return parser/policy/completion graph or wait for a TUN write.
This ordering also applies when lwIP produces output synchronously before an input call has returned.
Prefer native VPP frame scheduling; this decision does not introduce a separate output queue or dispatcher.

The callback result reports only whether this output submission succeeded. A later graph Policy DROP or
TUN completion failure is recorded at its own stage and is not retroactively reported as lwIP submission
failure. Allocation or submission rejection is settled by the current holder before graph acceptance;
after acceptance, the graph owns the new buffer's completion/free path. The original pbuf retains its
pinned lwIP lifetime independently of that graph work.

SAKAMOTO-246 verifies the actual submit/accept point, callback return-value mapping, failure settlement,
and callback-return-before-graph-execution trace; SAKAMOTO-237 consumes that evidence for the product
Interface. No exact C signature or lwIP error code is frozen before this verification.

### 2026-09-05 Minimal return facts and lifecycle

The existing transport session carries only the necessary reliable application identity and its explicit
known/unknown state. Return packets receive these small facts by value, not references to an input buffer,
its metadata, or a VPP FlowEntry. Missing identity remains unknown without waiting or guessing; the UID of
Sakamoto's Direct socket is not the original application's identity. Do not introduce an identity mapping
manager, subscription, broadcast or background synchronization system for this interface.

Network facts reuse the transport flow's existing underlay binding and epoch record. Do not create another
snapshot system or replace an existing flow's binding with the system's newly selected network. Unavailable
binding facts remain unknown; invalidated epochs still follow the lifecycle rules below. A new return packet
is `FLOW_STACK_RETURN` with Device Packet Direction `INPUT`; the shared graph derives its own PacketFacts
and Policy Verdict rather than inheriting those of an input packet.

Reuse the existing owner and Adapter generation. Only the owner executes mutable callbacks; stale events
cannot operate on a new session, but must still settle any resources they carry. The existing
quiesce/drain/close sequence remains authoritative: no new per-packet token table or reclamation queue is
introduced here. SAKAMOTO-243 retains the full lifecycle acceptance scope; each experiment still cleans up
its own resources. Additional identity cases require a concrete scenario and minimal review, not speculative
synchronization machinery.

## Android socket and lifecycle boundary

Every Direct TCP/UDP socket is associated with the current Android underlay snapshot, bound to that underlay,
and successfully protected before `connect()` or first send. Bind or protect failure closes the socket; there
is no unprotected retry or fallback. The failure is an Infrastructure Fault and failed Transport Outcome, not
a Policy `DROP`.

The socket's underlay epoch is fixed at creation. New flows use the latest snapshot. Sakamoto does not
transparently migrate or reconnect a live TCP byte stream across Wi-Fi/mobile changes; invalidation ends the
transport flow and the application may reconnect. Any future UDP mapping rebuild across underlays requires
explicit tested semantics and cannot silently reuse the old socket.

Stop, crash recovery, and Runtime Profile switching preserve the existing Adapter teardown barrier: quiesce
new admission, keep return/completion paths alive for a bounded drain, close or abort shard sessions and
protected sockets, reclaim every transferred buffer exactly once, then close transport and TUN resources.
No packet, callback, timer, or ownership token crosses Adapter generations. If the VPN Userspace Flow Stack
cannot start or crashes, the product attempts one bounded restart and then tears down the unusable VPN
runtime, visibly reports that protection stopped, and restores ordinary connectivity when Android lockdown
policy permits.

## Scope, ownership, and evidence

The first-release forwarding contract is IPv4/IPv6 TCP and UDP. DNS remains its original TCP or UDP traffic
to the packet's original destination; this architecture adds no resolver or DNS redirect. ICMP Echo is
advertised only if the fork and device evidence prove it. Other IP protocols may still be matched, blocked,
and observed while an allow result can have Transport Outcome `UNSUPPORTED`.

The HEV fork is vendored for offline reproducibility, preserving its MIT license, upstream URL, base commit,
and local-change record. Sakamoto does not routinely rebase, track upstream for freshness, or plan upstream
contributions. Only a major bug fix or evidence-backed significant performance improvement justifies a
selective migration to a newly tested pinned base.

Acceptance has two independent levels. Controlled feasibility evidence compares Direct against the existing
HEV SOCKS path: Direct median throughput must be at least 90% of baseline; p95/p99 latency and CPU per byte or
transaction must be at most 110%, subject to a small absolute latency tolerance; steady RSS growth must be at
most 8 MiB; and repeated connections/restarts must show no increasing RSS, thread, or fd trend. Production
still requires absolute Android release-budget evidence. Passing only one level is insufficient.

Owner-inline execution and independent copy-based storage are the selected baselines above. Exact call sites,
shard and credit counts, timer scheduling, and production capacity remain evidence-selected implementation
details; neither historical POC constants nor this decision establish production completion.

## Consequences

- ADR-0008 removes the later C++ `VpnFlowStackBoundary` / `VpnHevLwipDriver` facade detour. Its types, runtime selection, fd fallback, and in-memory fake are not a product seam and must not be translated into C. The OI1--OI5 owner-inline C POC results are design evidence only; production receives a newly designed VPP-native C Module.
- Android's unavoidable packet-to-flow reconstruction cost is explicit rather than hidden behind a
  "packet sender" abstraction.
- The HEV fork must prove an isolation shape compatible with canonical FlowOwner locality; if the pinned
  source cannot do so safely, the result is a required refactor or architecture revisit rather than a hidden
  global mutex or external-process substitution.
- VPP retains one shared policy/FlowEntry graph for Root and VPN, while lwIP remains a VPN-only transport
  subsystem.
- Flow affinity removes a second egress hash and cross-owner migration. The resulting HEV/lwIP state layout,
  native execution cost, and buffer seam remain POC-selected consequences rather than accepted constants.
- Copy minimization is measurable and honest: avoidable copies are defects to optimize, but required copies
  are accepted when their ownership or protocol reason is proven.
- A remote L3 gateway, gVisor netstack, VPP host stack, bare-lwIP rewrite, and NIC-bypass stacks are not the
  selected product path. They either change the product topology, add a less compatible runtime, reproduce
  the protected-socket bridge, discard HEV's existing integration, or cannot use rootless Android's NIC.
