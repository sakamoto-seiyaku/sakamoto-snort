# Evidence-Guided Android VPN POC Campaign Specification

Date: 2026-08-23  
Plane owner: SAKAMOTO-137  
Output level: concrete POC design; no experiment executed by this document

This specification turns the
[campaign contract](ANDROID_VPN_FEASIBILITY_CAMPAIGN.md),
[Finding Ledger](POC_FINDING_LEDGER.md), and
[Evidence Gap Map](ANDROID_VPN_EVIDENCE_GAP_MAP.md) into the next continuous
Android VPN feasibility campaign.  It designs throwaway evidence work, not the
formal product implementation.

The current decomposition has five Evidence Batches and eleven POCs because
that is the smallest useful grouping of today's gaps.  The number is not a
completion rule.  A finding may split, merge, reorder, add, or remove POCs when
the change names the evidence that caused it.  Protocol/address-family cases
are cells inside an upper-level POC, not automatically separate tickets.

## 1. Campaign question and baseline

The campaign decides whether the accepted owner-inline Android VPN route reaches
**Android VPN Engineering Feasibility** on the dedicated Pixel 6a:

- a real whole-device IPv4/IPv6 TCP/UDP dataplane, including DNS and policy;
- nonblocking, lifecycle-safe real App UID attribution;
- convergent real underlay, stop, fault, restart and stale-event behavior;
- final-topology multi-owner isolation and explicit overload/resource behavior;
- a credible device-level resource, lifecycle and performance envelope.

The starting baseline remains ADR-0007's owner-inline external-driver topology:
one canonical FlowOwner executes each shard's mutable HEV/lwIP callbacks; a
wait-only helper publishes opaque wakes; the Android broker performs bind/
protect; shards do not migrate/spill; original destination and provenance remain
immutable; generation/epoch checks cover all asynchronous events.

Passing evidence may retain this route.  A POC correction may adjust the seam.
Only contradictory higher-fidelity evidence or a material new constraint
reopens the affected architecture decision.

## 2. Lightweight execution protocol

Each POC ticket registers only:

1. the question, current assumption and decisive falsifiers below;
2. exact artifact/device/network identity and the minimum cells selected for
   that run;
3. the safety boundary and cleanup command/path;
4. the raw facts required for a conclusion and known non-claims.

Exploratory cells, fault injection, random ordering, additional metrics and
harness corrections are allowed.  They stay visible and cannot weaken a gate.
At closure, every POC records:

- cell result (`PASS`, `FAIL`, `INCONCLUSIVE`, or `INVALID`);
- artifact/source/APK/plugin/library hashes and Pixel/Host/model provenance;
- raw packet, broker, owner, resource and cleanup evidence appropriate to the
  claim;
- new Finding Ledger entries and any POC Correction;
- plain-language supported claim, non-claim, and roadmap meaning.

This minimum discipline must not replace exploratory POC work with a rigid
form.  Evidence can be stored in the existing journal/result layout or a
lighter equivalent as long as the decisive facts remain reviewable.

### Correction and continuation rule

- Build, deploy, permission, fixture, timing, logging, FD, buffer ownership,
  cleanup and instrumentation defects receive the smallest POC Correction and
  rerun of affected cells.
- A valid local failure that preserves baseline invariants is recorded as
  `ADJUSTMENT_REQUIRED`; correct or redesign that seam, rerun, and continue.
- `INVALID` or `INCONCLUSIVE` never passes.  Add only the bounded evidence
  needed to decide the same question; do not turn it into open-ended research.
- Passing POCs and batches proceed continuously without a review checkpoint.
  Discussion is required only at a campaign interruption condition or the final
  combined audit.

## 3. Evidence Batch and blocker graph

| Batch | Upper-level question | Constituent POCs | Pixel final evidence | Host/model support |
| --- | --- | --- | --- | --- |
| A -- Identity foundation | Can real App UID attribution drive policy without blocking or contaminating ownership? | A1, A2 | A2 distinct-App UID/cache/policy matrix | A1 state/fault contract |
| B -- Whole-device real network | Does the complete owner-inline route carry real dual-stack TCP/UDP/DNS and keep outcomes distinct? | B1, B2 | Full-device positive and negative/failure matrices | Endpoint fixtures and classification model only |
| C -- Real network/runtime lifecycle | Do underlay epoch, stop, fault and restart converge while real traffic is active? | C1, C2 | Actual network transition plus real-traffic lifecycle | Complete late-event/fault matrix |
| D -- Ownership and overload | Do multiple final-topology owners remain isolated and exactly-once through admission and packet pressure? | D1, D2, D3 | Pixel multi-owner, distribution, resource and overload evidence | Tuple/fault/tripwire and exhaustion models |
| E -- Engineering envelope | Is the route stable across repetition/device state and free of an architecture-level performance cliff? | E1, E2 | Pixel resource trend, performance and Doze evidence | Analysis/fixture support only |

### True blocking edges

| POC | Blocked by | Why this is a real blocker |
| --- | --- | --- |
| A1 | Existing campaign contract/ledger only | Starts immediately |
| A2 | A1 | Pixel code needs a bounded nonblocking request/cache/generation contract to interpret misses and refresh |
| B1 | A2 | The final whole-device artifact must already carry the UID seam used by per-app policy/provenance cells |
| B2 | B1 | Negative/failure interpretation requires a known-good real-network positive path in the same architecture |
| C1 | B2 | A real underlay transition is meaningful only after positive and failure semantics work on the real path |
| C2 | C1 | Stop/fault/restart must reuse the proven network-epoch instrumentation and fresh-flow rule |
| D1 | B2 | Final multi-owner evidence requires a known-good single-owner/full-path artifact and outcome ledger |
| D2 | D1 | Resource admission must name the final shard/owner/resource owners before exhaustion is interpreted |
| D3 | D1 | Packet pressure must name the final queue/credit/buffer ownership path before drops are interpreted |
| E1 | C2, D2, D3 | Repetition is meaningful only after lifecycle and both overload classes have bounded settlement |
| E2 | E1 | Performance/device-state evidence uses the corrected, resource-stable final POC artifact/configuration |
| Final audit | A2, B2, C2, D2, D3, E2 | Every required claim family must have valid evidence |

C and D are independent after B2 and may be scheduled in either order.  D2 and
D3 are siblings, not artificial blockers for one another.  Device availability
may determine execution order without changing the evidence DAG.

## 4. Batch A -- Application identity foundation

### POC A1 -- Nonblocking UID attribution contract

- **Question / gaps:** EG-08 and EG-09.  Can UID miss, completion, cache hit,
  refresh and failure be represented without waiting on FlowOwner or changing
  the canonical owner key?
- **Working assumption:** Android lookup is an asynchronous fact provider;
  current-flow identity is sticky, cache entries are generation/network/app-
  lifecycle scoped, and policy consumes UID after ownership is selected.
- **Minimum model/Host evidence:** cache miss→completion→hit; concurrent misses;
  duplicate/stale/wrong-owner completion; lookup unavailable/queue-full;
  app/package refresh and network/generation refresh; expiry; reverse-direction
  lookup; owner sentinel progress; no FlowOwner-key change; bounded queue/cache
  accounting and zero residue.
- **Pixel evidence:** Not decisive in A1.  A minimal Android API smoke may be
  used to expose ABI facts, but A2 owns the device conclusion.
- **Lightweight falsifiers:** any owner-thread blocking lookup; UID included in
  the canonical owner key; stale completion changing a current flow; two App
  UIDs contaminating one cache entry; unbounded pending/cache growth.
- **Supported result:** a small explicit attribution interface/state contract
  is ready for device integration, with exact non-claims about production cache
  size and Android timing.
- **Interruption condition:** if Android can only provide the required identity
  by blocking owner execution or by changing existing-flow ownership, pause the
  campaign and reopen the attribution/ownership seam.

### POC A2 -- Pixel multi-App UID attribution and policy closure

- **Question / gaps:** EG-07--EG-09 and VPN-F026.  Does the A1 contract work for
  distinct real Android application UIDs on the target device?
- **Minimum Pixel evidence:** at least two controlled, distinct App UIDs (the
  terminal app is acceptable) generate real IPv4/IPv6 TCP/UDP tuples; observe
  miss→completion→hit, concurrent distinct tuples, reverse traffic, cache
  refresh after a registered app/network/runtime lifecycle event, and lookup
  unavailable.  UID allow reaches the transport boundary; UID drop creates no
  broker/socket; owner/sentinel progress and cache/pending bounds stay visible.
- **Host/model support:** Replay A1 stale/duplicate/wrong-owner and generation
  matrix against the exact message/cache schema used by the APK/plugin.
- **Lightweight falsifiers:** wrong UID, cross-App cache hit, owner stall, UID or
  provenance changing a live flow's owner, stale refresh reviving old identity,
  or a drop path entering Android broker/transport.
- **Supported result:** the per-app policy foundation is viable on Pixel for
  the bounded identity matrix.
- **Non-claims:** Complete Application Catalog, UI identity, production cache
  sizing, multi-user/product persistence, or OEM compatibility.
- **Interruption condition:** a stable correct UID cannot be associated with a
  flow without violating canonical ownership or nonblocking execution.

#### 2026-08-23 evidence-guided execution refinement

Pixel execution exposed a harness-classification mismatch rather than an
architecture contradiction: durable UID/cache events passed and lifecycle
control events were observed, but lifecycle closure remains unproven. A
volatile empty service-log capture remained a global gate, and the current
outbound-only fixture could not produce reverse or per-flow downstream-zero
evidence. The remaining A2 work therefore follows
[`S139_A2_POC_DESIGN_REVISION.md`](S139_A2_POC_DESIGN_REVISION.md).

The refinement preserves every A2 minimum claim. Controlled reverse traffic
uses the actual Flow Stack return interface, normal VPP graph, TUN Adapter, and
app receipt on Pixel. UID drop is proved at the real transport-admission,
broker, and socket call sites, with a live allow control and a fresh dropped
tuple. Neither cell claims B1 whole-device Direct Egress. B1/B2 later repeat
those properties at full real-path fidelity. Volatile logcat is diagnostic
only; a durable VpnService builder receipt, package-to-UID mapping, allowed
scope, runtime VPN binding, exact tuple, and source provenance are joined as
the session authority.

## 5. Batch B -- Whole-device real network

### POC B1 -- Full-device real dual-stack Direct Egress and DNS

- **Question / gaps:** EG-03--EG-06.  Can a full-device `VpnService` route carry
  real original-destination IPv4/IPv6 TCP/UDP and DNS through the selected
  owner-inline path and return packets through the same TUN?
- **Minimum Pixel evidence:** install a normal full-device/default VPN route on
  the dedicated Pixel; use real reachable network endpoints and traffic from
  controlled apps/terminal.  Close IPv4 TCP, IPv4 UDP, IPv6 TCP, IPv6 UDP, DNS
  over UDP and DNS over TCP (including fallback/large-response behavior where
  required to force TCP).  For each cell retain raw TUN/provenance, canonical
  owner, broker bind→protect, original underlay destination, Direct send/recv,
  TUN return, app result and exact cleanup/resource ledger.
- **Host/model support:** Endpoint fixtures, packet parsing, DNS response shape,
  checksum/provenance replay and deterministic failure setup.  Host never closes
  the real-network claim.
- **Lightweight falsifiers:** narrow/loopback route substituted for final cell;
  missing external IPv6; unprotected or fallback socket; SOCKS/second datapath;
  original destination lost; DNS redirect/resolver path introduced; return
  packet loops back to Flow Stack; competing TUN reader.
- **Supported result:** one exact Pixel artifact proves the minimum full-device
  positive dataplane for all required address-family/protocol/DNS cells.
- **Non-claims:** Throughput/capacity, network handover, long lifecycle, release
  safety, or third-party OEM behavior.
- **Interruption condition:** real external routing requires an unprotected
  fallback, second packet path, mutable global authority, or a violation of the
  dedicated-device safety/cleanup boundary.

### POC B2 -- Full-device policy, transport and infrastructure failure separation

- **Question / gaps:** EG-07 plus regression of EG-02/EG-03.  On the real path,
  do policy drop, transport refusal/no-reply, bind/protect failure, broker
  unavailable, and ordinary success remain separate outcomes with no fallback?
- **Minimum Pixel evidence:** reuse the B1 artifact/full-device route.  Include
  real-App UID allow/drop, representative IP/policy drop, bounded transport
  refusal, no-reply deadline, forced bind failure, forced protect failure,
  broker unavailable, and a success control.  Prove drop stops before broker/
  socket; accepted transport failure does not rewrite policy; no failed path
  retries unprotected or through SOCKS; each descriptor/buffer settles once.
- **Host/model support:** Complete duplicate/stale/wrong-owner/wrong-epoch and
  outcome-class matrix using B1/B2 schema.
- **Lightweight falsifiers:** any failure becomes policy drop, any drop reaches
  transport, any unprotected/alternate fallback, unbounded wait, ambiguous
  refusal/timeout, or cleanup residue.
- **Supported result:** the minimum real-network failure contract is valid on
  Pixel and B1 becomes the functional baseline for later lifecycle/pressure.
- **Non-claims:** All Internet failure modes, production timeout constants, or
  final overload behavior.
- **Interruption condition:** correctness requires implicit fallback or cannot
  separate policy from transport/infrastructure state.

## 6. Batch C -- Real network and runtime lifecycle

### POC C1 -- Real underlay epoch transition

- **Question / gaps:** EG-10.  Does a real Android Network/underlay change create
  a fresh epoch while old TCP and UDP state remain invalid?
- **Minimum Pixel evidence:** begin with active real B1 TCP and UDP traffic;
  trigger an actually observed Network handle/underlay loss or replacement
  available on the Pixel environment; record old/new network identity and
  epoch.  Old TCP must terminate without transparent reconnect, old UDP socket/
  mapping must not be reused, late broker/wake/output/TUN events must be
  rejected, and fresh IPv4/IPv6 traffic must bind/protect on the new snapshot.
  Exact transition mechanism is selected from real device capabilities and is
  not satisfied by a synthetic epoch counter alone.
- **Host/model support:** Full OI-5 TCP/UDP invalidation and all late-event kinds;
  fault injection for timing orders difficult to force on device.
- **Lightweight falsifiers:** old socket sends after epoch, transparent TCP
  reconnect, old UDP reuse, new flow bound to old Network, stale event mutation,
  owner blocking during transition, or policy/fallback rewriting.
- **Supported result:** the selected target device has one real, convergent
  underlay transition path for the final POC architecture.
- **Non-claims:** Every cellular/Wi-Fi/USB combination, seamless session
  migration, OEM behavior, or release network UX.
- **Interruption condition:** Android platform constraints force live migration,
  global transport authority, or unprotected retry to recover connectivity.

### POC C2 -- Real-traffic stop, injected fault and bounded restart

- **Question / gaps:** EG-11 and lifecycle regressions VPN-F006/VPN-F023/
  VPN-F024.  Does the full real path quiesce, settle and restart without stale
  revival?
- **Minimum Pixel evidence:** with real B1 traffic active, run normal stop,
  injected Flow Stack fault, one bounded restart, and fresh traffic after
  restart.  Include established TCP, active UDP/timer, pending broker work and
  queued wake/output/TUN tokens.  Admission closes before drain; old events are
  counted/rejected; watcher duplicates and inherited broker fds obey ownership;
  every socket/PCB/pbuf/credit/VPP buffer/timer/fd settles once; stopped traffic
  is not silently bypassed.
- **Host/model support:** Complete runnable/waiting/FIN/stale/duplicate event
  orders and exact quiesce→drain→close→settle history.
- **Lightweight falsifiers:** token starts context after stop; inherited broker
  channel closed; late event revives flow; resource residue; more than one
  implicit restart; ordinary connectivity not restored when the VPN is unusable
  and platform policy permits it.
- **Supported result:** bounded normal/fault/restart lifecycle is valid with real
  traffic on Pixel.
- **Non-claims:** Crash-loop/backoff product policy, reboot, upgrade, long soak,
  or release service UX.
- **Interruption condition:** bounded teardown cannot preserve exactly-once
  settlement or requires dropping generation/ownership guards.

## 7. Batch D -- Multi-owner ownership and overload

### POC D1 -- Pixel final-topology multi-owner isolation and distribution

- **Question / gaps:** EG-12/EG-13 and VPN-F010/VPN-F014/VPN-F015.  Does the
  final owner-inline artifact replicate into independent Pixel shards with a
  realistic tuple distribution?
- **Minimum Pixel evidence:** enable at least two final-topology owners without
  treating that count as a product constant.  A real full-device tuple corpus
  covers IPv4/IPv6 TCP/UDP and exercises every active test owner; record
  canonical hash input/output, fixed flow ownership, owner-local callbacks/
  timers/sockets/credits/output and per-owner counters.  Inject wrong-owner
  submit/output/completion/callback attempts and one bounded owner delay/fault;
  peers continue without migration, spill, cross-mutation or global lock.
- **Host/model support:** OI-4 full tuple/fault/tripwire matrix and deterministic
  resource ledgers using the exact final hash/schema.
- **Lightweight falsifiers:** realistic tuples collapse due to hash bias;
  mutable global transport/counters influence the path; foreign callback
  mutates state; fault stops a peer; live flow migrates/spills; second egress
  hash disagrees with canonical owner.
- **Supported result:** representative Pixel multi-owner isolation and tuple
  distribution are valid for the tested configuration.
- **Non-claims:** Production shard count, perfect balance, capacity, or all
  traffic distributions.
- **Interruption condition:** correct target execution needs a global core lock,
  paired mutable executor, migration/spill, or a second ownership hash.

### POC D2 -- Flow admission and transport-resource exhaustion

- **Question / gaps:** EG-14/EG-15 and VPN-F009/VPN-F012.  When flow/session/
  socket/PCB/pbuf/timer resources reach an explicit bound, do new admissions
  fail cleanly while existing flows and peer owners remain correct?
- **Minimum Pixel evidence:** increase controlled real flow demand until at
  least one named admission/resource bound is exercised; the exact levels are
  discovered and then registered, not assumed from old test pools.  Record per-
  owner limits/high-water, accepted/rejected flows, existing-flow progress,
  broker/socket/PCB/pbuf/timer/credit settlement, peer isolation and recovery
  after resources release.  No dynamic unbounded growth, eviction, spill,
  policy rewrite or hidden fixture ceiling is allowed.
- **Host/model support:** Exhaust each named resource deterministically,
  including delayed completion, stale release and partial allocation failures.
- **Lightweight falsifiers:** unexplained cliff, existing-flow eviction,
  cross-owner spill, owner blocking, resource-specific failure reported as
  policy, counter/ledger mismatch, or failure to recover capacity.
- **Supported result:** final topology has explicit, bounded flow admission and
  transport-resource semantics on Pixel; sizes remain POC envelope values.
- **Non-claims:** Production capacity constants, public benchmark, or soak.
- **Interruption condition:** bounded operation is impossible without unbounded
  growth, global serialization, migration/spill or ownership loss.

### POC D3 -- Packet queue, credit and buffer overload

- **Question / gaps:** EG-14/EG-15 and VPN-F013/VPN-F016.  Under packet pressure,
  are handoff/queue/credit/buffer outcomes nonblocking and exactly-once?
- **Minimum Pixel evidence:** increase controlled packet/burst demand until the
  selected queue/credit/buffer boundary is exercised.  Distinguish offered-load
  shape from accidental microbursts; record per-owner occupancy/high-water,
  enqueue success/rejection/drop reason, helper ownership transfer, packet/
  pbuf/VPP buffer settlement, existing-flow behavior, peer isolation and
  post-pressure recovery.  Policy verdict and transport/runtime overload remain
  separate.
- **Host/model support:** Queue full, credit full, partial allocation, delayed
  completion, duplicate/stale terminal and helper-owned drop cases.
- **Lightweight falsifiers:** double free/leak, silent byte clone, owner stall,
  unbounded queue, policy rewrite, existing-flow termination contrary to the
  registered contract, cross-owner pollution, or no recovery after pressure.
- **Supported result:** packet overload is explicit, bounded and conservative on
  Pixel in the tested envelope.
- **Non-claims:** Maximum throughput, production queue/buffer sizes, or release
  loss budget.
- **Interruption condition:** exactly-once ownership or nonblocking FlowOwner
  behavior cannot be preserved at a bounded limit.

## 8. Batch E -- Engineering envelope

### POC E1 -- Repeated real-path lifecycle and OS resource trend

- **Question / gaps:** EG-16 and lifecycle/resource portions of EG-15.  Across
  repeated traffic, stop, network epoch and fault/restart, do resource counts
  settle without an increasing OS/runtime trend?
- **Minimum Pixel evidence:** reuse the corrected B--D artifact/configuration and
  run a pre-registered sequence containing real dual-stack TCP/UDP/DNS traffic,
  normal stop/start, at least one real network epoch transition and injected
  fault/restart.  Choose enough repetitions before execution to evaluate a
  slope using prior 50-cycle/five-generation evidence as precedent; extend only
  when the registered trend decision is statistically ambiguous.  Track
  app/VPP/Flow Stack/broker fds, threads, RSS/HWM, sockets, PCB/session/pbuf/
  timers/credits/VPP buffers, route/TUN/process residue, failures and recovery.
- **Host/model support:** Deterministic long event-order/fault permutations and
  exact internal ledger checks; no substitution for OS trends.
- **Lightweight falsifiers:** monotonic FD/thread/RSS or internal-resource growth,
  incomplete route/TUN/process cleanup, stale generation activity, increasing
  restart cost, or a harness ceiling misread as target capacity.
- **Supported result:** no increasing resource trend or per-cycle residue in the
  registered target-device envelope.
- **Non-claims:** Infinite soak, production reliability duration, reboot/
  upgrade, release budgets or OEM retention.
- **Interruption condition:** a reproducible architecture-level leak or
  lifecycle divergence cannot be corrected locally without violating baseline
  ownership/generation rules.

### POC E2 -- End-to-end performance and device-state feasibility

- **Question / gaps:** EG-17/EG-18, VPN-F017/VPN-F018/VPN-F025.  Does the final
  copy-based owner-inline path avoid an architecture-level performance cliff,
  and what causes the historical screen-off TCP latency?
- **Minimum Pixel evidence:** matched real-network Direct and existing HEV SOCKS
  feasibility-baseline arms on the same device/endpoints/traffic, with ordering
  and observation cost controlled.  Cover representative IPv4/IPv6 TCP/UDP/DNS,
  single and multi-owner load, foreground, screen-off and forced-Doze/wake.
  Record throughput, p50/p95/p99, CPU/work/context switches/wakes, RSS growth,
  queue/credit pressure, packet loss, thermal state and cleanup.  Include a
  foreground/local-path control that can attribute or bound the historical
  roughly four-second background TCP latency.
- **Decision rule:** use ADR-0007's feasibility comparison: Direct median
  throughput at least 90% of baseline; p95/p99 latency and CPU per byte or
  transaction at most 110%, subject to a small absolute latency tolerance
  registered before execution; steady RSS growth at most 8 MiB; repeated
  connections/restarts show no increasing RSS/thread/fd trend.  Every accepted
  cell also passes correctness/resource/thermal/instrumentation validity.
- **Host/model support:** Build/symbolization and deterministic controls only;
  Host performance cannot close the Pixel claim.
- **Lightweight falsifiers:** invalid observation or offered-load shape;
  correctness/resource failure hidden by good aggregate metrics; threshold
  failure attributable to owner-inline scheduling, global lock, copy/queue
  architecture or device-state divergence; inability to construct a matched
  baseline.
- **Supported result:** the final POC route meets the bounded comparative
  feasibility envelope and device-state correctness/resource rules.
- **Non-claims:** Release performance/power budgets, battery certification,
  production constants, or a formal zero-copy investment verdict.
- **Conditional copy branch:** keep VPN-F018 paused if end-to-end gates pass.  If
  copy is newly shown material to a failed EG-17 gate, design a targeted new
  copy POC from that evidence; do not resume the old matrix automatically.
- **Interruption condition:** a valid reproducible architecture-level cliff
  contradicts the baseline, or required comparison cannot be made without
  changing the accepted product topology.

## 9. Batch-level conclusions and continuous progression

Each batch closes only when its upper-level question has a supported conclusion;
the number of constituent POCs is not the criterion.

| Batch conclusion | Continue when | Adjustment behavior |
| --- | --- | --- |
| A | UID attribution is correct/nonblocking and ownership-independent on Pixel | Cache/ABI/lifecycle corrections rerun A1/A2; ownership contamination interrupts |
| B | Full-device dual-stack TCP/UDP/DNS positive and outcome-separation cells are valid | Packet/broker/fixture corrections rerun affected B cells; fallback/second path interrupts |
| C | Real epoch and real-traffic stop/fault/restart converge with exact settlement | Local lifecycle corrections rerun C; migration/unprotected retry/generation loss interrupts |
| D | Pixel multi-owner isolation plus both admission and packet overload classes are bounded | Resource/hash/ledger corrections rerun D; global lock/spill/ownership loss interrupts |
| E | Resource trends and comparative performance/device-state gates pass | Measurement/harness corrections rerun E; valid architecture cliff may reopen architecture |

The default execution is continuous: A1→A2→B1→B2, then complete C and D in any
available order, then E1→E2 and the final audit.  A batch ending
`SUPPORTS_BASELINE` does not require approval before the next unblocked POC.

## 10. Campaign interruption conditions

Stop the remaining chain and discuss the affected route only if evidence shows:

- mutable HEV/lwIP work must execute on a paired/helper thread or under a
  process-global mutable authority/core lock;
- correct operation requires live migration, alternate-owner spill, a second
  ownership hash or second packet path;
- real routing/recovery requires an unprotected retry or implicit Direct/SOCKS
  fallback;
- original destination/provenance, exactly-once ownership, or generation/epoch
  safety cannot be preserved;
- bounded resources/nonblocking FlowOwner behavior are impossible in the target
  environment;
- a valid target-device performance/resource result exposes an architecture-
  level cliff rather than a local implementation/harness issue;
- the device safety boundary is violated, the POC premise is invalid, or new
  external authority/irreversible action is required;
- a materially superior architecture makes continuing the old route
  unreasonable.

Ordinary findings, including already familiar permission, callback, address,
endpoint readiness, FD watcher, stop race, credit, counter, hash, pacing and
buffer-settlement defects, are recorded and corrected; they are not automatic
interruption conditions.

## 11. Final Android VPN Engineering Feasibility audit

The audit consumes the final Finding Ledger, Evidence Gap Map and all batch
conclusions.  It is claim-family based, not a count of passing cells.

| Required family | Completion evidence |
| --- | --- |
| Minimum full-device dataplane | B1/B2 valid Pixel IPv4/IPv6 TCP/UDP/DNS, policy/outcome separation, original destination/provenance and TUN return |
| Application identity | A1/A2 valid async/cache/generation contract and distinct-App Pixel UID/policy matrix |
| Network and lifecycle | C1/C2 valid real underlay epoch plus stop/fault/restart/stale-event settlement on real traffic |
| Ownership and failure | D1/D2/D3 valid Pixel multi-owner isolation, tuple distribution, bounded admission and packet overload with exact settlement |
| Engineering envelope | E1/E2 valid OS/internal resource trends, device-state behavior and ADR comparative performance gates |

Final roadmap meaning:

- **`SUPPORTS_BASELINE`** -- every required family has valid evidence at its
  required Host/model/Pixel fidelity and no baseline invariant is contradicted.
  The campaign may state Android VPN Engineering Feasibility for the Pixel 6a
  scope and proceed to formal implementation planning.
- **`ADJUSTMENT_REQUIRED`** -- a real local seam/design issue is identified but
  owner-inline baseline invariants survive.  Update the Finding/Gap records,
  rerun the affected POC/family, and repeat the audit; feasibility is not yet
  complete.
- **`REOPENS_ARCHITECTURE`** -- a core baseline assumption is contradicted by
  valid higher-fidelity evidence.  Pause the chain and make an explicit route
  decision before further old-route POCs.
- **`INSUFFICIENT_EVIDENCE`** -- any required family is `INCONCLUSIVE`,
  `INVALID`, missing, or supported only by a lower-fidelity substitute.  Run the
  smallest bounded follow-up that closes that family; do not claim completion.

Out-of-scope claims remain explicit: third-party OEM compatibility, production/
release readiness, final capacity/constants, product UI/catalog/persistence,
Root/NFQUEUE revalidation and release battery certification.

## 12. Ready-for-to-tickets slices

The next `to-tickets` pass should create one independently tracked execution
slice per current POC plus the final audit, preserving the blocker DAG rather
than a simple linear list:

| Slice | Proposed execution-ticket title |
| --- | --- |
| A1 | Define and Prove the Nonblocking UID Attribution Contract |
| A2 | Close Pixel Multi-App UID Attribution and Policy Foundation |
| B1 | Close Pixel Full-device Dual-stack Direct Egress and DNS |
| B2 | Close Full-device Policy/Transport/Infrastructure Failure Semantics |
| C1 | Prove a Real Pixel Underlay Epoch Transition |
| C2 | Prove Real-traffic Stop/Fault/Bounded Restart Settlement |
| D1 | Prove Pixel Final-topology Multi-owner Isolation and Distribution |
| D2 | Prove Bounded Flow Admission and Transport-resource Exhaustion |
| D3 | Prove Bounded Packet Queue/Credit/Buffer Overload |
| E1 | Prove Repeated Real-path Lifecycle and Resource Trend |
| E2 | Close End-to-end Performance and Device-state Feasibility |
| Audit | Decide Android VPN Engineering Feasibility from the Complete Campaign |

Ticket bodies should cite this specification and the exact gap/finding IDs,
carry only true blockers from Section 3, and retain the campaign's continuous
execution and interruption rules.  They must not embed POC corrections as
production implementation requirements or create separate tickets for every
matrix cell.
