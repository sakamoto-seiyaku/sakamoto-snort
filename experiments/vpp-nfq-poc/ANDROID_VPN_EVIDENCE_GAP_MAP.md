# Android VPN Evidence Gap Map

Date: 2026-08-23  
Plane owner: SAKAMOTO-136

This map asks “what important claim is supported, at what evidence level, and
what remains to be proven?”  It is derived from the
[campaign contract](ANDROID_VPN_FEASIBILITY_CAMPAIGN.md), the
[POC Finding Ledger](POC_FINDING_LEDGER.md), and the bounded OI evidence.  An
untested claim is a gap, not an observed defect.

## Evidence status

- `SUPPORTED` -- current evidence supports the claim exactly as worded.
- `PARTIAL` -- valid evidence supports a narrower form of the claim.
- `INSUFFICIENT_EVIDENCE` -- the claim is required but lacks a decisive valid
  cell at the required fidelity.
- `INCONCLUSIVE` -- a registered investigation ran but did not meet its
  decision gates.
- `INVALIDATED_AS_SUBSTITUTE` -- the underlying evidence remains valid, but it
  cannot be used as a substitute for the broader claim.
- `OUT_OF_SCOPE` -- the campaign explicitly does not attempt the claim.

Pixel is the final environment for Android-specific claims.  Host/model cells
remain authoritative for platform-neutral state matrices, ownership tripwires,
and deterministic fault coverage.

## Claim map

| Claim | Model evidence | Host evidence | Pixel evidence | Current status | Exact boundary and non-claim | Future POC? |
| --- | --- | --- | --- | --- | --- | --- |
| **EG-01 Owner-inline scheduler/wakeup** -- bounded drive, timer/FD progress, owner-thread callbacks, stale/duplicate rejection, graph fairness | OI-1 state cells cover wake identity and terminal state | OI-1 timer/FD/packet/mixed/fairness cells PASS | Same registered OI-1 arm64 cells PASS | `SUPPORTED` | Supports the isolated scheduler seam; not full-device load or final production budgets | No standalone POC; retain as an integration regression cell |
| **EG-02 Async Android bind/protect broker** -- nonblocking owner, directional completion, exactly-once duplicate close, failures distinct from policy | OI-2 model covers success/failure/queue/tripwire/late cells | Real socket and VPP-worker cells PASS | Java `bindSocket` then `VpnService.protect` family/failure/queue/delay cells PASS | `SUPPORTED` | Supports the broker seam on the selected Pixel; not arbitrary network migration or capacity | No standalone POC; exercise it in every real-network/lifecycle batch |
| **EG-03 Controlled original-destination Direct Egress** -- TUN ingress, canonical owner, protected socket, original destination, TUN return, refusal/timeout/drop | Failure classification and generation rules enumerated | Synthetic IPv4/IPv6 matrix and real socketpair-TUN local underlay PASS | Controlled narrow-route IPv4/IPv6 TCP/UDP plus refusal/timeout/policy-drop PASS | `SUPPORTED` | Only controlled routes and loopback underlay; no external/default-route or whole-device claim | Broader claim moves to EG-04--EG-07 |
| **EG-04 Whole-device real IPv4 network** -- default/full-device VPN routing, real external IPv4 TCP and UDP, protected original destination, TUN return | Not applicable to Android network fidelity | No substitute | No current owner-inline whole-device external/default-route run | `INSUFFICIENT_EVIDENCE` | Controlled OI-3 and old mock/SOCKS evidence cannot prove real external Direct Egress | Yes, required |
| **EG-05 Whole-device real IPv6 network** -- real external IPv6 TCP and UDP through the complete owner-inline path | Not applicable to Android network fidelity | No substitute | Controlled IPv6 loopback only; old app path proves narrower IPv6 behavior | `INSUFFICIENT_EVIDENCE` | IPv6 parsing/local underlay is not Internet/real-network reachability | Yes, required |
| **EG-06 DNS remains ordinary original-destination UDP/TCP** -- IPv4/IPv6 DNS request and response without hidden redirect or resolver path | Architecture rule only | No end-to-end real DNS evidence | Domain/DNS rules and full-path DNS are untested | `INSUFFICIENT_EVIDENCE` | Current exact-IP/UID policy and synthetic UDP/TCP do not prove DNS behavior | Yes, required; include UDP and TCP fallback/large-response behavior as appropriate |
| **EG-07 Policy and transport separation on the full path** -- allow reaches transport; drop never creates broker/socket; transport/infrastructure failure never becomes policy drop | OI models cover class separation | OI-2/OI-3 controlled failure cells PASS | Controlled policy-drop PASS; older VPP UID/static-IP drop cells PASS on a different path | `PARTIAL` | Separation is proven in controlled pieces, not with real external traffic and real App UID policy in one artifact | Yes, integrate with real-network and UID batches |
| **EG-08 Distinct real App UID attribution** -- at least two real applications/UIDs, correct IPv4/IPv6 TCP/UDP ownership, cache hit and miss | A1 Host/model contract covers tuple-scoped cache identity and cross-flow isolation; Android UID result cannot be modeled | Mock resolver/tuple cache only; A1 does not provide Android API evidence | VPP-internal UID allow/drop and a one-entry cache have bounded Pixel evidence | `PARTIAL` | Does not cover distinct-app matrix, concurrent real misses, cache sizing/expiry, or refresh on Pixel | Yes, required |
| **EG-09 Nonblocking UID lifecycle** -- owner never waits for lookup; miss completion is generation-safe; network/app lifecycle refreshes cache; UID never contaminates FlowOwner key | A1 deterministic Host/model runner covers miss/completion, concurrent requests, scope refresh, expiry, rejection identity, and zero-residue teardown | A1 runs on Host but has no real Android API timing or resolver behavior | No decisive nonblocking miss/refresh/epoch evidence | `INSUFFICIENT_EVIDENCE` | A1 proves the bounded contract shape only; it does not prove Android timing, real App UID correctness, or production capacity | Yes, required and foundational for per-app policy |
| **EG-10 Real underlay/network epoch transition** -- new sockets bind/protect to a new snapshot; old TCP terminates; old UDP mapping is not reused | OI-5 enumerates epoch invalidation and stale events | Host fault/epoch/restart PASS | Controlled epoch advance PASS; old SAKAMOTO-5 covers Wi-Fi off/on on the superseded mock path | `PARTIAL` | No current owner-inline real network transition or independently changed underlay | Yes, required; exact available underlays remain evidence-guided |
| **EG-11 Full-path stop/fault/restart recovery** -- quiesce, bounded drain, exactly-once settlement, one restart, fresh real traffic, no stale revival | OI-5 complete late-event matrix PASS | Same-process normal and injected-fault restart PASS | Controlled generations 1--5 normal/fault/restart/underlay PASS | `PARTIAL` | Strong lifecycle seam evidence, but no whole-device external traffic or sustained-load stop/fault | Yes, integrate after real-network baseline |
| **EG-12 Pixel owner-inline multi-owner isolation** -- representative multiple owners, fixed shard state, no migration/spill/cross-owner mutation, independent failure | OI-4 tuple/fault/tripwire matrix PASS | Real two-pthread IPv4/IPv6 UDP/TCP owners PASS | S124 two-worker real-TUN local echo used an earlier seam; final OI-4 topology has no Pixel multi-owner run | `INSUFFICIENT_EVIDENCE` | Host/model and S124 are useful support but cannot substitute for final arm64 owner-inline topology | Yes, required |
| **EG-13 Real tuple distribution quality** -- canonical hash distributes realistic Android tuples without changing a live flow's owner | Stable-hash rules can be modeled | No target tuple population | S125 exposed even-port low-bit bias; test-only avalanche exercised both owners | `PARTIAL` | The correction is not a production hash contract and does not prove balance under real apps | Yes, include in Pixel multi-owner batch |
| **EG-14 Bounded overload behavior** -- queue/credit/pool exhaustion is explicit, nonblocking, owner-local, exactly-once, and does not rewrite policy | OI/S116 models cover selected rejection/settlement shapes | S116 bounded Host overload envelope PASS on earlier R2 seam | S124 observed 37 background drops; S125 fixed one rejection double-free; no final owner-inline pressure contract | `INSUFFICIENT_EVIDENCE` | Observed drops are a risk signal, not proof of safe or unsafe final overload semantics | Yes, required |
| **EG-15 Flow/socket/buffer/timer engineering envelope** -- bounded high-water, explicit resource cliff, no dynamic unbounded growth | Resource ledgers cover enumerated objects | S116 and OI models/runners show exact bounded cleanup | Temporary S124 pool ceilings were corrected; no final full-path Pixel envelope | `PARTIAL` | Zero residue in short cells does not establish capacity/high-water under realistic concurrent traffic | Yes, required |
| **EG-16 Repeated lifecycle resource trend** -- no increasing FD/thread/RSS trend across traffic, stop, fault and restart | Model proves exact settlement, not OS trends | Bounded repeat/restart evidence | Old path completed 50 cycles and sustained rounds; OI-5 completed five controlled generations | `PARTIAL` | Old topology and short controlled OI generations cannot prove the final real-network path's trend | Yes, required in final engineering batch |
| **EG-17 Performance has no architecture-level cliff** -- comparative throughput/latency/CPU/RSS meets ADR-0007 feasibility rule in a valid target-device campaign | No device performance substitution | Host only diagnoses components | S122--S125 show a measurable path and representative hotspots, but the registered copy investment remains inconclusive and no final whole-device comparison exists | `INCONCLUSIVE` | Small visible copy share supports keeping the baseline, not the ADR comparative feasibility verdict | Yes, required after functional/overload closure |
| **EG-18 Background/Doze behavior** -- full path retains correctness and bounded resources; latency cause and acceptable envelope are explicit | No device-state substitute | No substitute | Old path survives one 600-second Doze and sustained rounds, but TCP p95/p99 remains about four seconds | `PARTIAL` | Resource stability is not acceptable latency, power certification, or final owner-inline evidence | Yes, include in engineering envelope; release battery certification remains out of scope |
| **EG-19 Two-copy optimization investment** -- decide whether to redesign lwIP/VPP ownership for copy removal | No final decision model | No substitute for device cost | S125 registered decision remains paused `INCONCLUSIVE` | `INCONCLUSIVE` | Not a feasibility blocker while the copy-based path meets functional/resource/performance gates | No dedicated POC unless EG-17 fails or new evidence makes copy material |

## Rejected evidence substitutions

These are invalid ways to support a broader claim; they do not invalidate the
underlying narrow evidence.

| Proposed substitution | Status | Reason |
| --- | --- | --- |
| S124 local TUN echo proves original-destination Direct Egress | `INVALIDATED_AS_SUBSTITUTE` | S124 terminates at local echo and does not close protected original-destination transport; OI-3 supplies only the later controlled proof |
| Controlled OI-3 loopback proves whole-device real networking | `INVALIDATED_AS_SUBSTITUTE` | Narrow routes and loopback deliberately avoid external/default-route behavior |
| OI-4 Host two-owner run proves Pixel multi-owner isolation | `INVALIDATED_AS_SUBSTITUTE` | Android arm64 scheduling, integration and target resource behavior remain device claims |
| Old child/SOCKS lifecycle and Doze runs prove the final owner-inline engineering envelope | `INVALIDATED_AS_SUBSTITUTE` | They are valuable risk baselines but use a superseded topology and mock/local endpoints |
| Small representative copy share proves a formal `DEFER` decision | `INVALIDATED_AS_SUBSTITUTE` | The registered measurement/control/instrumentation gates were not all satisfied; status remains `INCONCLUSIVE` |

## Candidate POC Evidence Batches

These batches group related claims by upper-level question.  They intentionally
do not freeze exact cell counts, traffic parameters, durations, shard counts,
or endpoint fixtures; SAKAMOTO-137 designs those from the dependencies and
lightweight falsifiers.

### Batch A -- Application identity is safe to use as a policy foundation

- Claims: EG-08, EG-09, and the UID portion of EG-07.
- Upper-level question: can real Android App UID attribution be obtained and
  refreshed without blocking FlowOwner execution or changing canonical
  ownership?
- Pixel is decisive; Host/model may cover cache and stale-completion matrices.
- Output needed by later batches: a bounded UID attribution seam and stable
  per-flow identity/provenance contract.

### Batch B -- The owner-inline path works on a real whole-device network

- Claims: EG-03--EG-07, with EG-01/EG-02 as regression obligations.
- Upper-level question: can the complete owner-inline TUN path carry real
  IPv4/IPv6 TCP/UDP and DNS to original destinations, return packets to TUN,
  and keep policy/transport/infrastructure outcomes distinct?
- Pixel full-device routing is decisive.  Controlled routes remain useful
  diagnostic cells but cannot close the batch.

### Batch C -- Network and runtime lifecycle converge on real traffic

- Claims: EG-10, EG-11 and lifecycle parts of EG-02/EG-07.
- Upper-level question: after underlay loss/change, stop, injected fault and one
  bounded restart, do old events/state stay dead and fresh real traffic use the
  new epoch with exact settlement?
- Model/Host expand the late-event matrix; Pixel real-network transitions and
  recovery are decisive.

### Batch D -- Ownership remains correct at multiple owners and overload

- Claims: EG-12--EG-15.
- Upper-level question: under representative distribution and bounded pressure,
  do final owner-inline shards remain isolated, nonblocking and exactly-once
  without migration/spill or hidden resource cliffs?
- Host/model supply deterministic tripwires; Pixel supplies final arm64
  integration, tuple distribution, overload and high-water evidence.

### Batch E -- The selected route has a credible engineering envelope

- Claims: EG-16--EG-18; EG-19 is conditional.
- Upper-level question: across sustained mixed traffic, device state and
  repeated lifecycle, is the route resource-stable and free of an
  architecture-level performance cliff?
- Pixel is decisive for throughput/latency/CPU/RSS/thermal and OS resource
  trends.  Copy-investment work is reopened only if the end-to-end evidence
  makes it material.

## Out-of-scope claims

| Claim | Status | Boundary |
| --- | --- | --- |
| Third-party OEM compatibility | `OUT_OF_SCOPE` | Pixel 6a is the final device environment for this campaign; OEM differences are later work |
| Production/release readiness and final capacity constants | `OUT_OF_SCOPE` | Campaign ends at Android VPN Engineering Feasibility |
| Product UI, Application Catalog, persistence and policy authoring UX | `OUT_OF_SCOPE` | Only the UID/per-app policy foundation is included |
| Root/NFQUEUE revalidation | `OUT_OF_SCOPE` | Root is a separately evidenced parallel route and is not reopened |
| Formal zero-copy/lwIP memory redesign | `OUT_OF_SCOPE` unless EG-17 reopens it | Current copy-based seam is the feasibility baseline |
| Release battery certification and all-OEM background retention | `OUT_OF_SCOPE` | The engineering batch records bounded device-state/resource behavior only |

## Current campaign implication

The evidence supports retaining the owner-inline architecture baseline.  It
does not yet support Android VPN Engineering Feasibility because required Pixel
claim families remain incomplete: real whole-device networking/DNS, full UID
attribution lifecycle, real network epoch recovery, final-topology multi-owner
overload/resource behavior, and the end-to-end engineering envelope.  No
current gap by itself contradicts the baseline; ordinary findings remain POC
correction/regression inputs unless new higher-fidelity evidence crosses a
campaign interruption condition.
