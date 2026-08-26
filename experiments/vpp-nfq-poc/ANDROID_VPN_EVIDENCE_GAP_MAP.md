# Android VPN Evidence Gap Map

Date: 2026-08-23
Updated: 2026-08-26 (S149 controlled C2 lifecycle evidence; S151 C1 callback/epoch closure; S153 real-stop correction; S156 hotspot; S157 TUN re-arm closure; S158 topology implementation; S159 D3 submit hotspot; S160 overload/recovery execution and ambient-flow hotspot; S161 timed D3 recovery closure; S163 E1/E2 execution; S164 HEV external-ingress wildcard-port hotspot; S165 HEV correction; S166 UID fixture and single-owner TCP-tail corrections; S167 IPv6 UDP UID extension; S168 multi-owner teardown correction and fourth recurrence; S169 UDP lifecycle closure and F046 four-owner capacity closure; S170 post-F046 E1 resource trend; S171 bounded E2 sample and F047 TCP idle-timeout closure; S172 matched HTTP baseline comparison-APK, admission, and request-shape closure; S173 foreground HTTP staircase owner-capacity closure; S174 bounded 8-request HTTP staircase execution; S175 bounded 16-request HTTP staircase execution; S176 UDP multi-flow route-pinning closure; S177 final resource short slice and ADB harness closure; S178 final B1 dual-stack DNS dataplane/lifecycle split; S179 current-artifact controlled B2 failure-semantics regression; S180 B1 forced DNS fallback fixture; S181 real no-reply and closed TCP timeout transport fixture; S182 representative target-IP policy drop; S183 representative AppA UID drop; S184 bounded real LAN TCP RST propagation closure; S185 bind/protect/broker infrastructure failure separation; S141 B2 final closure audit; S152 A2 UID matrix design gap; S156 A2 resolver/correlation closure; S224 current F072-candidate E1 resource trend; S225--S229 E2 CPU-budget and HEV-baseline hotspot isolation; F074 Android VPP barrier-held idle CPU closure; S231--S233 post-F074 foreground CPU-budget reruns; S234--S235 post-F074 device-state count128 reruns; S236 post-F074 foreground count512 rerun)
Plane owner: SAKAMOTO-136

All follow-up POCs selected from this map must follow
[`ANDROID_VPN_POC_EXECUTION_GUARDRAILS.md`](ANDROID_VPN_POC_EXECUTION_GUARDRAILS.md)
for artifact and fixture validity, evidence joining, failure classification,
bounded retry, and hotspot stopping.

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
| **EG-03 Controlled original-destination Direct Egress** -- TUN ingress, canonical owner, protected socket, original destination, TUN return, refusal/timeout/drop | Failure classification and generation rules enumerated | Synthetic IPv4/IPv6 matrix and real socketpair-TUN local underlay PASS | Historical non-TUN controlled narrow-route IPv4/IPv6 TCP/UDP plus refusal/timeout/policy-drop cells passed; S147 current full-TUN refusal/timeout/policy-drop and IPv4/IPv6 success controls all have cell-aware outcomes and zero residue | `SUPPORTED` | Controlled routes and loopback do not prove the complete external/default-route or whole-device claim | Broader claim remains bounded by EG-04--EG-07 |
| **EG-04 Whole-device real IPv4 network** -- default/full-device VPN routing, real external IPv4 TCP and UDP, protected original destination, TUN return | Not applicable to Android network fidelity | No substitute | S148 final APK full-route AppA cells passed IPv4 UDP DNS (`46313`), IPv4 TCP DNS separate (`46314`) and coalesced (`46315`), each with valid 61-byte response, recorded non-VPN Wi-Fi handle `432902426637`, Direct/TUN return, and zero residue. S178 repeated the current S176/S177 artifact B1 dataplane with IPv4 UDP DNS (`60741`), IPv4 TCP DNS separate (`60742`) and coalesced (`60743`), all with valid 61-byte DNS responses, native direct/broker/TUN-output markers, and zero post-run `vpp`/`tun0` residue | `SUPPORTED` | Supported for the exact Pixel 6a/artifact/underlay cells. S178 strengthens current-artifact dataplane support, but the two IPv4 TCP rows had cleanup-marker gaps, so lifecycle cleanup-marker timing, repeated networks, HTTP semantics, capacity and large-response/fallback behavior remain outside this cell | Yes, required for repeated/extended coverage |
| **EG-05 Whole-device real IPv6 network** -- real external IPv6 TCP and UDP through the complete owner-inline path | Not applicable to Android network fidelity | No substitute | S148 final APK full-route AppA cells passed external IPv6 UDP DNS (`46316`) and IPv6 TCP DNS separate (`46317`), each with valid 61-byte response, direct/TUN return, and zero residue; broker selected the recorded non-VPN Wi-Fi underlay. S178 repeated the current artifact with IPv6 UDP DNS (`60744`) plus IPv6 TCP DNS separate (`60745`) and coalesced (`60746`), all with valid 61-byte DNS responses, native direct/broker/TUN-output markers, and zero post-run `vpp`/`tun0` residue | `SUPPORTED` | Supported for the exact Pixel 6a/artifact/underlay cells. S178 strengthens current-artifact dataplane support; the IPv6 TCP separate row had a cleanup-marker gap, while the coalesced row fully passed. Repeated underlays, non-DNS IPv6 services and capacity remain open | Yes, required for repeated/extended coverage |
| **EG-06 DNS remains ordinary original-destination UDP/TCP** -- IPv4/IPv6 DNS request and response without hidden redirect or resolver path | Architecture rule only | No end-to-end real DNS evidence | S148 final APK covers IPv4/IPv6 UDP and TCP DNS, separate/coalesced TCP writes, valid 61-byte responses, original port-53 destinations, Direct/TUN return, and zero residue; the Android broker log records the non-VPN underlay selection. S178 repeats the same claim on the current final artifact across six IPv4/IPv6 UDP/TCP DNS cells, including separate/coalesced TCP writes, with `appValidCount=6`, `nativeValidCount=6`, `failureCount=0`, and `PASS_DATAPLANE_WITH_CLEANUP_MARKER_GAPS`. S180 adds a real fallback operation on the current VPN artifact plus AppA fallback helper: UDP query `1234` received a fixture `TC=1` response, the same query ID was retried over TCP, AppA recorded `dns_tcp_fallback_response_received`, fixture/native evidence joined the two phases, and `failureCount=0` | `SUPPORTED` | Ordinary DNS request/response is supported for these exact cells. S180 supports one bounded IPv4 WSL2/LAN forced-TC fallback; public resolver fallback behavior, IPv6 fallback, arbitrary large DNS responses, repeated resolver behavior, and lifecycle cleanup-marker timing remain outside this evidence | Yes, required for public/IPv6 fallback and large-response extension |
| **EG-07 Policy and transport separation on the full path** -- allow reaches transport; drop never creates broker/socket; transport/infrastructure failure never becomes policy drop | OI models cover class separation | OI-2/OI-3 controlled failure cells PASS | Chrome drop remains a narrow protect-broker boundary; corrected second-UID 12629 IPv4 TCP/UDP plus IPv6 TCP/UDP allow cells reached VPP shim with explicit VPN binding; S147 current full-TUN policy-drop has broker/transport zero and refusal/no-reply have distinct expected transport outcomes with zero residue. S179 repeats the controlled B2 negative contract on the current final artifact: refused, no-reply, and policy-drop all passed with `PASS_EXPECTED_FAILURE`, `verifierRc=0`, `failureCount=0`, and zero post-run `vpp`/`tun0` residue. S181 adds a real AppA -> VpnService -> OI3 multi-owner WSL2/LAN fixture slice: positive UDP DNS passed, real UDP no-reply passed with `EXPECTED_REAL_NO_REPLY`, and an unbound TCP port was correctly reclassified as post-allow `EXPECTED_TIMEOUT` after local proxy handshake; all three cells had `failureCount=0` and zero post-run `vpp`/`tun0` residue. S182 adds representative target-IP policy drop on the same full-device OI3 multi path: positive control and `policy-drop-udp-dns` passed, the drop logged `stage=pre-owner ... no-transport=1 broker=0 socket=0`, fixture recorded no packet, and post-run `vpp`/`tun0` residue was zero. S183 adds representative AppA UID drop before OI3 broker/socket: UID contract completed to AppA UID `12630`, owner gate dropped with `lookup-attempts=2`, fixture recorded no packet, `gateDrop=2`, `gateForward=0`, and zero residue. S184 adds a controlled post-SYN `SO_LINGER(1,0)` LAN reset: one owner-local `ECONNRESET` is mapped by the narrow owner-context seam to one rewritten downstream `RST|ACK`; AppA records `dns_response_reset`; cleanup is `PASS_EXPECTED_REAL_RESET` with one transport failure, zero infrastructure failure, exact `buffers=7/7`, and zero residue. S185 adds bind/protect/broker infrastructure-failure separation: forced bind, forced protect, and broker-unavailable cells all stop before fixture query/TUN output/Direct send/transport failure, record exact broker result and phase accounting, and pass with zero residue. S141 closure audit maps Plane `SAKAMOTO-141` acceptance to these bounded slices and records the S184 stale derived-manifest caveat | `PARTIAL` | Separation is proven in controlled pieces plus bounded real WSL2/LAN no-reply, closed-port-timeout, target-IP pre-owner policy-drop, representative AppA UID-drop, post-SYN reset, and bind/protect/broker infrastructure-failure slices. B2 is closable only for this bounded POC scope. Pre-connect refusal, public Internet behavior, arbitrary teardown mapping, production timeout constants, and the complete distinct-App matrix remain unproven | Yes: continue only with separately registered remaining B2/engineering-envelope gaps |
| **EG-08 Distinct real App UID attribution** -- at least two real applications/UIDs, correct IPv4/IPv6 TCP/UDP ownership, cache hit and miss | A1 Host/model contract covers tuple-scoped cache identity and cross-flow isolation; Android UID result cannot be modeled | Mock resolver/tuple cache only; A1 does not provide Android API evidence | Chrome/Maps narrow IPv4 evidence is supplemented by corrected androidruntime UID 12629 VPN-bound IPv4 TCP/UDP plus IPv6 TCP/UDP tuples, exact UID miss→completion→cache-hit transitions, VPP shim counters, and a narrow deliberate UID-12629 owner-drop; lifecycle raw also observes refresh/unavailable intents but lacks recovered resolver completion; service-log provenance remains insufficient. S183 adds a current full-device AppA UID `12630` UDP drop cell on OI3 multi with `MISS_SUBMITTED -> COMPLETION_ACCEPTED -> CACHE_HIT` joined to a native gate drop. S152's public-endpoint/startup-stage A2 design gap is closed by S155. S156 run5 closes `VPN-F061` for the A2-1 base matrix: two real App UIDs produced all eight IPv4/IPv6 TCP/UDP tuple joins with runtime, resolver, and UID-contract verdicts all `PASS` | `PARTIAL` | A2-1 now supports the base two-App IPv4/IPv6 TCP/UDP UID-attribution matrix. EG-08 remains partial for concurrent/reverse cells, cache sizing/expiry, recovered lifecycle attribution, production UID gate design, external egress, and arbitrary OEM timing. Dependent A2 cells must inherit S156 request-correlation and TCP dynamic-port guardrails | Yes, required |
| **EG-09 Nonblocking UID lifecycle** -- owner never waits for lookup; miss completion is generation-safe; network/app lifecycle refreshes cache; UID never contaminates FlowOwner key | A1 deterministic Host/model runner covers miss/completion, concurrent requests, scope refresh, expiry, rejection identity, and zero-residue teardown | A1 runs on Host but has no real Android API timing or resolver behavior | Second-UID raw observed app/network scope refresh, provider unavailable/available intents, three miss/completion pairs, and real VPN-bound probes; recovered source port 45627 had no resolver completion and final native cache was not joined per tuple. S183 adds real Android timing on the selected full-device path: the first lookup submitted a sentinel miss, Android completion accepted UID `12630`, a cache hit returned UID `12630`, and the pre-OI3 native gate consumed that cache hit for policy. S156 fixes A2-1 resolver request-correlation for the base matrix and proves exact two-App IPv4/IPv6 TCP/UDP joins, but lifecycle recovery and provider-unavailable convergence are still separate cells | `PARTIAL` | This proves one real Android miss/completion/cache-hit consumed by a bounded pre-OI3 policy gate plus a request-correlated A2-1 base matrix. It does not prove production nonblocking/capacity design, recovered-provider attribution, complete lifecycle convergence, or arbitrary tuple timing. A2 lifecycle/native joins must reuse S156 per-request stage correlation | Yes, required and foundational for per-app policy |
| **EG-10 Real underlay/network epoch transition** -- new sockets bind/protect to a new snapshot; old TCP terminates; old UDP mapping is not reused | OI-5 enumerates epoch invalidation and stale events | Host fault/epoch/restart PASS | S151 Pixel final APK callback/owner run published loss `epoch=2 handle=-1`, owner-applied invalidation with `PASS_EXPECTED_UNDERLAY_INVALIDATION`, `buffers=6/6`, `residue=0`, and no old TCP reconnect/UDP reuse; replacement callback published a new physical handle; bounded VPN stop/start carried fresh AppA IPv4 (`vpn_network_handle=712075300877`) and IPv6 (`724960202765`) bind/protect/send cells | `SUPPORTED` | Supported for the selected Pixel 6a artifact under the explicit bounded VPN-session restart rule. Android 16 does not promise seamless in-place VPN migration or automatic session recreation; other OEM/network combinations remain open | Repeat/extend lifecycle coverage in C2 |
| **EG-11 Full-path stop/fault/restart recovery** -- quiesce, bounded drain, exactly-once settlement, one restart, fresh real traffic, no stale revival | OI-5 complete late-event matrix PASS | Same-process normal and injected-fault restart PASS | S149 controlled generations 1--5 normal/fault/restart/underlay PASS with zero residue; S153/S155 real AppA stop/fault cells settled cleanly; S157 corrected the detached-TUN lifecycle and carried same-session IPv4→IPv6 real DNS on one VPN handle, with two fresh generations, `PASS` cleanups, active-flow `PASS_EXPECTED_FAULT`, and zero residue | `PARTIAL` | S157 closes the one-flow-per-session hotspot for the registered positive-flow re-arm contract. Explicit stop/fault/underlay teardown remains bounded; seamless Android migration, arbitrary concurrency and unrestricted capacity are not claimed | Continue C2/D/E under re-arm contract |
| **EG-12 Pixel owner-inline multi-owner isolation** -- representative multiple owners, fixed shard state, no migration/spill/cross-owner mutation, independent failure | OI-4 tuple/fault/tripwire matrix PASS | Real two-pthread IPv4/IPv6 UDP/TCP owners PASS | S169/F046 four-owner Pixel UDP closed echo `127931250090287` started owners 0--3, carried four concurrent flows with `sent=3698 received=3698 errors=0`, had zero `owner-busy`/multi-admission rejects, and cleaned all four owners with `residue=0`; earlier S168/F042 heap recurrence is closed for this corrected regression | `PARTIAL` | Supports the bounded four-owner UDP closed-echo isolation envelope; does not prove independent fault injection across all owners, arbitrary protocols, soak, or production shard count | Continue D/E functional and resource cells |
| **EG-13 Real tuple distribution quality** -- canonical hash distributes realistic Android tuples without changing a live flow's owner | Stable-hash rules can be modeled | No target tuple population | S169/F046 selected `sourcePortBase=43000` so ports `43000`--`43003` mapped across all four owners and stayed stable for the run; ingress counts were owner0 `1366`, owner1 `1366`, owner2 `1372`, owner3 `1395` | `PARTIAL` | Shows stable four-owner dispatch for one chosen UDP tuple set; not a representative Android tuple population, balance proof, or migration/stickiness soak | Yes, continue in D/E |
| **EG-14 Bounded overload behavior** -- queue/credit/pool exhaustion is explicit, nonblocking, owner-local, exactly-once, and does not rewrite policy | OI/S116 models cover selected rejection/settlement shapes | S116 bounded Host overload envelope PASS on earlier R2 seam | S161 matched Pixel D3 produced four `PASS_EXPECTED_OVERLOAD` generations after 64 concurrent offers, exact credit/buffer settlement, TUN re-arm, and a valid post-pressure WSL2 DNS recovery; ambient TCP/5228 is explicitly classified | `SUPPORTED` | Supports the registered bounded UDP envelope and recovery contract; production capacity, infinite soak, and arbitrary public endpoint behavior remain non-claims | No standalone D3 rerun; extend only through E1/E2 |
| **EG-15 Flow/socket/buffer/timer engineering envelope** -- bounded high-water, explicit resource cliff, no dynamic unbounded growth | Resource ledgers cover enumerated objects | S116 and OI models/runners show exact bounded cleanup | Temporary S124 pool ceilings were corrected; S169/F046 four-owner UDP closed echo cleaned all four owners with `submit-rejects=0`, `queue-rejects=0`, and `residue=0` | `PARTIAL` | Zero residue in a short four-flow UDP cell does not establish capacity/high-water under realistic mixed traffic, lifecycle repetition, or performance load | Yes, continue in E1/E2 |
| **EG-16 Repeated lifecycle resource trend** -- no increasing FD/thread/RSS trend across traffic, stop, fault and restart | Model proves exact settlement, not OS trends | Bounded repeat/restart evidence | S170 post-F046 four-owner run completed five repeated 4-flow UDP closed-echo generations with exact app echo, fixture `12762/12762`, four clean owner teardowns per cycle, `pidof vpp` empty after cleanup, App/VPP FD counts stable at `120/41`, and RSS deltas `648/480 KiB`. S224 repeated the resource-trend shape on the current F072-candidate comparison artifact for five 4-flow cycles: every cycle passed, app/fixture counts matched from `4485/4485` through `4592/4592`, cleanup was `16/0` per cycle, App/VPP fd stayed `120/49`, threads stayed `33--34/7`, and manifest `failureCount=0` | `PARTIAL` | Supports the corrected four-owner UDP repeat/stop window on both the post-F046 and current F072-candidate artifacts; does not cover the complete E1 matrix of dual-stack TCP/UDP/DNS, epoch transition, fault/restart, Doze, CPU/power, or long soak | Yes, extend only if final audit requires broader post-F046/current-artifact E1 coverage |
| **EG-17 Performance has no architecture-level cliff** -- comparative throughput/latency/CPU/RSS meets ADR-0007 feasibility rule in a valid target-device campaign | No device performance substitution | Host only diagnoses components | S122--S125 show a measurable path and representative hotspots, but the registered copy investment remains inconclusive. S171 adds a bounded same-endpoint Direct-vs-OI3 sample after F047: UDP 64B, UDP 4x1400B and TCP 1400B all passed with `failureCount=0`. S172 adds a preflighted Direct/HEV/OI3 HTTP baseline runner, closes the comparison-APK `tun_poc` provenance gap, fixes the OI3 TCP admission-before-tombstone race, and accepts a count-bounded one-GET Direct/HEV/OI3 HTTP slice with `failureCount=0`. S173 found and closed `VPN-F050`: hash quality is now `fnv1a+mix`, busy successor SYNs are deferred on their canonical owner, stale TCP pending tail is cleared at re-arm, OI3 repeat=5 passed all five 4-request cells, and matched Direct/HEV/OI3 4-request HTTP passed with `failureCount=0`. S174 extends that construction to an unpaced 8-request HTTP staircase: OI3-only repeat=3 passed all three `8/8` cells, and matched Direct/HEV/OI3 all passed `8/8` with `failureCount=0`. S175 extends again to unpaced 16-request HTTP: OI3-only repeat=3 passed all three `16/16` cells, and matched Direct/HEV/OI3 repeat=3 passed all nine `16/16` cells with `failureCount=0`; OI3 p95 remained materially higher than controls. S176 closes UDP multi-flow primary-owner collision for the selected four-owner topology: full Direct/OI3 IPv4 UDP/TCP L4 sample passed all 12 cells with `failureCount=0`, and OI3 HTTP16 regression passed two `16/16` repeats. S177 adds a corrected final-artifact short resource slice: two four-flow UDP cycles passed with `failureCount=0`, fixture `2008/2008`, cleanup `4/0` per cycle, stable fd/thread counts, and thermal status `0`. S199--S223 then correct the matched HTTP latency cliff: connector write interest, owner/completion handoff, post-Direct-send read wake, and TCP owner lifecycle/admission were narrowed; S221 matched foreground Direct/HEV/OI3 8-request HTTP passed with `failureCount=0`, Direct p95 `59ms`, HEV p95 `11ms`, OI3 p95 `24ms`, and OI3 cleanup `12/0`; S222 screen-off passed Direct p95 `15ms`, HEV p95 `10ms`, OI3 p95 `27ms`; S223 forced-Doze passed Direct p95 `18ms`, HEV p95 `16ms`, OI3 p95 `78ms`; both device-state runs had OI3 cleanup `12/0` and `failureCount=0`. S224 adds a current-artifact five-cycle UDP resource trend with stable fd/thread/RSS and `failureCount=0`. The F074 follow-up diagnoses Android worker idle burn as repeated VPP recent-barrier holdoff, fixes the Android idle profile in `0324f92`, validates S229 barrier-fixed idle at `cpuTicksDelta=89` / `schedRuntimeNsDelta=887122393` with worker `skip_barrier_recent=0`, and passes a bounded OI3 UDP wake smoke `414/414`. S231 and S232 then rerun Direct/OI3 foreground count64/count128 without HEV: OI3 count64 passes `64/64` p95 `32ms` with `cpuTicksDelta=198` and `schedRuntimeNsDelta=1773100641`; OI3 count128 passes `128/128` p95 `28ms` with `cpuTicksDelta=302` and `schedRuntimeNsDelta=2644077026`. S233 repeats count128 three times; all OI3 repeats pass `128/128`, p99 is `33/71/68ms`, and total CPU ticks are `286/292/302`. S234/S235 extend Direct/OI3 count128 to screen-off and forced-Doze: both pass `128/128`, OI3 p95/p99 is `28/71ms` and `26/30ms`, total CPU ticks are `336` and `343`, and both manifests record `failureCount=0`. S236 extends foreground Direct/OI3 to count512 repeat=3: all cells pass `512/512`, OI3 p95 is `27--28ms`, p99 is `72/106/71ms`, total CPU ticks are `1015/1060/1028`, cleanup is `516/0`, and manifest `failureCount=0` | `INCONCLUSIVE` | S171--S177 support corrected-route, matched-baseline construction, bounded 16-request HTTP staircase viability, bounded four-owner UDP route-pinning viability, and a short foreground resource slice. S221--S223 support the corrected foreground and device-state HTTP E2 latency seams. S224 supports current-artifact repeated resource stability. F074 CPU burn is no longer an active blocker for the selected Android idle scope or the tested foreground/device-state count128 and foreground count512 Direct/OI3 shapes. These still do not prove formal p99 tail tolerance, throughput/capacity budgets beyond this bounded shape, CPU/thermal/power under broader load, long soak, HEV as a broad baseline, or the full ADR-0007 performance verdict | Yes, close remaining E2 budget/tolerance and broader gates before final import |
| **EG-18 Background/Doze behavior** -- full path retains correctness and bounded resources; latency cause and acceptable envelope are explicit | No device-state substitute | No substitute | Old path survived one 600-second Doze and sustained rounds, but TCP p95/p99 remained about four seconds. S222/S223 reran the matched HTTP device-state shape with the corrected F072 artifact: screen-off Direct/HEV/OI3 all `8/8` with OI3 p95 `27ms`; forced-Doze Direct/HEV/OI3 all `8/8` with OI3 p95 `78ms`; both OI3 cleanups `12/0`, `failureCount=0`. S234/S235 reran post-F074 Direct/OI3 count128 under screen-off and forced-Doze; both passed `128/128`, with OI3 p95/p99 `28/71ms` and `26/30ms`, cleanup `132/0`, and `failureCount=0` | `PARTIAL` | Corrected device-state HTTP cells no longer show the prior seconds-level cliff, and post-F074 Direct/OI3 count128 also stays bounded; this is still not release power certification, long background soak, or final full-budget evidence | Yes, include in engineering envelope; release battery certification remains out of scope |
| **EG-19 Two-copy optimization investment** -- decide whether to redesign lwIP/VPP ownership for copy removal | No final decision model | No substitute for device cost | S125 registered decision remains paused `INCONCLUSIVE` | `INCONCLUSIVE` | Not a feasibility blocker while the copy-based path meets functional/resource/performance gates | No dedicated POC unless EG-17 fails or new evidence makes copy material |

**EG-17 post-S224/F074 update:** S225--S229 changed the remaining E2 posture
from "missing budget evidence" to "budget evidence exposes concrete
hotspots." S227/S228 show OI3 HTTP can remain correct (`128/128` and `64/64`,
cleanups `132/0` and `68/0`) while VPP aggregate sched runtime is about `32s`
over the measured window. S229 removed HTTP and HEV from the equation: an
idle-only OI3 run reproduced the worker burn. The first Android worker-idle
fix (`ee57b9d`) did not close it, but Android-only skip counters in `b797629`
identified repeated VPP recent-barrier holdoff as the direct cause. The
accepted Android idle-profile correction (`0324f92`) lets workers sleep across
that holdoff and S229 barrier-fixed
`evidence/s229-oi3-idle-cpu-barrier-fixed-20260826/`
(`runId=20260826-083314-815885`) reduced the 10-second idle window to
`cpuTicksDelta=89` and `schedRuntimeNsDelta=887122393`, with
`skip_barrier_recent=0`; a bounded OI3 UDP wake smoke then passed `414/414`.
S231--S233 then show the foreground active-HTTP count64/count128 CPU runaway is
also gone for Direct/OI3-only reruns: OI3 `64/64` records `198` total CPU
ticks / `1773100641ns` sched runtime, and OI3 `128/128` records `302` total
CPU ticks / `2644077026ns` sched runtime; the repeat count128 run records OI3
p99 `33/71/68ms` and total CPU ticks `286/292/302`. S234--S235 extend the
Direct/OI3 count128 shape to screen-off and forced-Doze with OI3 p95/p99
`28/71ms` and `26/30ms`, total CPU ticks `336` and `343`, cleanup `132/0`,
and `failureCount=0`. S236 extends foreground Direct/OI3 to count512 repeat=3
with OI3 p95 `27--28ms`, p99 `72/106/71ms`, cleanup `516/0`, and total CPU
ticks `1015/1060/1028`. Therefore the F074 CPU hotspot is closed for the
selected Android idle scope and tested foreground/device-state count-bounded
Direct/OI3 HTTP scope through count512. EG-17 nevertheless remains
`INCONCLUSIVE`:
HEV/tun-poc still cannot serve as a broad matched baseline above the small
request-count envelope (`66/64` in S227, `64/63` in S228), and formal p99 tail
tolerance, broader OI3 throughput/capacity beyond this bounded count512 shape,
CPU/thermal/power, and long-soak evidence remain open before main-stack import.

## Rejected evidence substitutions

These are invalid ways to support a broader claim; they do not invalidate the
underlying narrow evidence.

| Proposed substitution | Status | Reason |
| --- | --- | --- |
| S124 local TUN echo proves original-destination Direct Egress | `INVALIDATED_AS_SUBSTITUTE` | S124 terminates at local echo and does not close protected original-destination transport; OI-3 supplies only the later controlled proof |
| Controlled OI-3 loopback proves whole-device real networking | `INVALIDATED_AS_SUBSTITUTE` | Narrow routes and loopback deliberately avoid external/default-route behavior |
| S140 controlled LAN plus one public IPv4 UDP DNS pass proves B1 | `INVALIDATED_AS_SUBSTITUTE` | The S140/S143 regressions validate selected IPv4 UDP/TCP/DNS seams, but they still cannot substitute for the complete IPv4 TCP/IPv6/registered B1 matrix |
| A successful `Network.bindSocket()`/`VpnService.protect()` pair proves physical egress | `INVALIDATED_AS_SUBSTITUTE` | S141 observed API success while `getActiveNetwork()` selected the UID-scoped VPN Network; Pixel wlan0 emitted no packet. Candidate/selected non-VPN Network identity is now a required run-validity gate |
| OI-4 Host two-owner run proves Pixel multi-owner isolation | `INVALIDATED_AS_SUBSTITUTE` | Android arm64 scheduling, integration and target resource behavior remain device claims |
| Old child/SOCKS lifecycle and Doze runs prove the final owner-inline engineering envelope | `INVALIDATED_AS_SUBSTITUTE` | They are valuable risk baselines but use a superseded topology and mock/local endpoints |
| Small representative copy share proves a formal `DEFER` decision | `INVALIDATED_AS_SUBSTITUTE` | The registered measurement/control/instrumentation gates were not all satisfied; status remains `INCONCLUSIVE` |
| Unbound WSL2/LAN TCP port proves real transport refusal through Android VPN/OI3 | `INVALIDATED_AS_SUBSTITUTE` | S181 proved this fixture behaves as app-facing TCP handshake followed by native/app timeout in the selected topology, not as a stable observed RST/`ECONNREFUSED`; real refusal requires a deterministic reset/refusal fixture |
| S184 bounded post-SYN `SO_LINGER(1,0)` reset proves arbitrary refusal/reset behavior | `INVALIDATED_AS_SUBSTITUTE` | The narrow owner-context correction now carries one observed `ECONNRESET` back to AppA as one rewritten `RST|ACK`, and the bounded LAN slice passes. It still cannot substitute for pre-connect `ECONNREFUSED`, public-Internet behavior, arbitrary teardown mapping, production timeout constants, Doze, or long soak |
| Android `addDisallowedApplication()` proves owner-inline policy drop | `INVALIDATED_AS_SUBSTITUTE` | Excluding AppA at the VpnService builder routes it outside the VPN and does not exercise OI3 policy; S182 uses a pre-owner OI3 dispatcher drop instead |
| First Android owner lookup `uid=-1` proves non-target UID for policy allow | `INVALIDATED_AS_SUBSTITUTE` | S183 reproduced that `uid=-1` is the async UID contract's sentinel miss, not a terminal owner fact. A policy gate must wait for completion/cache hit or use a production replacement seam before deciding UID policy |

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
- Before interpreting a timeout, seal the exact source/stage/APK/runtime member
  hashes and prove network eligibility with a direct control from the package
  UID that owns the protected socket. Shell-only reachability and a stale
  Android permission/compat state are invalid run conditions, not transport
  evidence; see VPN-F027/VPN-F028 and the S140 diagnosis.

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

The evidence supports retaining the owner-inline architecture baseline for the
validated single-owner path, the tested D3 overload/recovery envelope, the
S169 four-owner UDP correctness envelope, and the S170 bounded post-F046
resource trend, plus the S171 bounded Direct-vs-OI3 UDP/TCP sample. VPN-F042,
VPN-F046 and VPN-F047 no longer pause the bounded four-owner functional path.
The full Android VPN Engineering Feasibility claim remains open because
comparative E2 performance, matched HEV baseline coverage, broader IPv4/IPv6
TCP/UDP/DNS matrix, screen-off/Doze behavior, thermal/device-state envelope and
the final audit are incomplete. S163/S164/S165 remain the active references for
matched HEV/E2 boundaries; S170 does not turn the resource trend into a
performance verdict, and S171 does not replace the full E2 device-state and
baseline comparison.

## SAKAMOTO-139 A2 addendum (2026-08-23)

The A2 Pixel artifact and journal are now recorded at
[`uid-attribution-contract-android-a2.json`](prototypes/uid_attribution_contract/artifacts/uid-attribution-contract-android-a2.json)
and [`S136_A2_UID_POLICY_EXECUTION_JOURNAL.md`](S136_A2_UID_POLICY_EXECUTION_JOURNAL.md).
They refine, but do not replace, the claim rows above:

| Claim family | A2 evidence update | Current A2 boundary |
| --- | --- | --- |
| EG-05 whole-device real IPv6 network | `INSUFFICIENT_EVIDENCE` narrow support only | Corrected androidruntime UID 12629 IPv6 TCP and UDP probes were explicitly bound to the active VPN Network and reached VPP with tuples `[fd00:111:111::2]:45622 -> [2606:4700:4700::1111]:443` and `[fd00:111:111::2]:45623 -> [2606:4700:4700::1111]:53`; TCP timed out and UDP has no reply claim, so whole-device external IPv6 remains open. |
| EG-06 ordinary DNS | `INSUFFICIENT_EVIDENCE` narrow support only | Corrected IPv4 and IPv6 UDP port-53 tuples produced UID miss→completion→cache-hit and `shim-tx`, but no DNS response, TCP fallback, or large-response evidence was retained. |
| EG-07 policy/transport separation | `PARTIAL` narrow support | Chrome allow reached the observed VPP post-policy shim; the fresh dedicated Chrome UID-10180 drop showed `blocked=6`/`uid-block=6`, while its protect ledger recorded `requests=0 completions=0 failures=0` and HEV emitted no connect record. Corrected androidruntime UID 12629 IPv4 TCP/UDP plus IPv6 TCP/UDP allow cells also reached VPP shim after explicit VPN binding. The deliberate UID-12629 owner-drop recorded `blocked=2 bytes=94`, `shim-tx=7 bytes=446`, and only a broker-start line. This closes only narrow allow/policy-drop boundaries; per-dropped-packet broker/socket/transport-zero remains open. |
| EG-08 distinct real App UID attribution | `PARTIAL` narrow support | Chrome UID 10180 and Maps UID 10176 remain narrow real-App IPv4 evidence. Corrected androidruntime UID 12629 now adds explicit VPN-bound IPv4 TCP/UDP plus IPv6 TCP/UDP tuples, exact resolver `uid=-1 -> 12629`, owner-cache UID 12629, contract `MISS_SUBMITTED -> COMPLETION_ACCEPTED -> CACHE_HIT` cells, and a deliberate narrow owner-drop. The lifecycle raw adds refresh/unavailable observations but no recovered resolver completion; service-log allowed-package provenance remains insufficient. The complete per-App IPv4/IPv6 matrix, reverse/concurrent closure, complete drop/broker separation, and external egress remain open. |
| EG-09 nonblocking UID lifecycle | `PARTIAL` contract support | Existing Java replay plus the second-UID lifecycle raw observe app/network refresh (`app_epoch=2`, `network_epoch=2`), unavailable/available intents, and bounded miss/completion events. The recovered source port 45627 has no resolver completion and final native cache state is not joined per tuple; Android timing, convergence, flow-ID reclamation, and target-specific lifecycle acceptance remain open. |

The historical Androidruntime Wi-Fi source address (`192.168.4.151`) and
inactive RuntimeService (UID 12620) are recorded as
`VPN-F026-A2-FIXTURE-01`, an evidence fixture gap rather than an architecture
interruption. The corrected reinstall (UID 12629) explicitly binds the debug
probe to the active VPN Network and supplies narrow IPv4/IPv6 TCP/UDP boundary evidence, but its
service-log provenance remains insufficient. A2 leaves the wider campaign
status `INSUFFICIENT_EVIDENCE` and does not update Plane state.

## S151 C1 addendum (2026-08-24)

The corrected execution is recorded in
[`S151_C1_UNDERLAY_EPOCH_EXECUTION_JOURNAL.md`](S151_C1_UNDERLAY_EPOCH_EXECUTION_JOURNAL.md).
It adds the missing `NetworkCallback→JNI/CLI→FlowStackOwner` seam and keeps
the callback thread out of owner state.  A real active AppA TCP flow observed
physical underlay loss and produced one owner-side epoch invalidation with
`PASS_EXPECTED_UNDERLAY_INVALIDATION`, zero residue, and no old TCP reconnect
or UDP reuse.  Android 16 removed the old VPN Network during the physical
loss; therefore the supported recovery contract is an explicit bounded VPN
stop/start, followed by fresh IPv4 and IPv6 AppA bind/protect/send cells on
the replacement snapshot.  Seamless migration is a non-claim.  EG-10 is
`SUPPORTED` for this selected artifact/device contract; EG-11 remains
`PARTIAL` until C2 runs real B1 traffic through normal stop, injected fault,
and one bounded restart.

The original S150 record remains the historical hotspot diagnosis:
[`S150_C1_UNDERLAY_EPOCH_HOTSPOT.md`](S150_C1_UNDERLAY_EPOCH_HOTSPOT.md).

## S153 C2 normal-stop addendum (2026-08-24)

The S152 normal-stop classification hotspot is recorded in
[`S152_C2_REAL_STOP_CLASSIFICATION_HOTSPOT.md`](S152_C2_REAL_STOP_CLASSIFICATION_HOTSPOT.md)
and resolved by
[`S153_C2_REAL_STOP_CORRECTION_EXECUTION_JOURNAL.md`](S153_C2_REAL_STOP_CORRECTION_EXECUTION_JOURNAL.md).
The real AppA TCP flow was active on the final OI3 path when stop was issued;
the app socket aborted, native cleanup emitted `PASS_EXPECTED_STOP` /
`EXPECTED_STOP`, and `broker=1/1 buffers=10/10 residue=0`.  This closes the
normal-stop sub-gate only.  EG-11 remains `PARTIAL` until real fault, bounded
restart, fresh post-restart traffic, and stale-revival rejection are run.

## S156 C2 one-flow-per-VPN-session addendum (2026-08-24)

S153 and S155 both reproduced a new real-path lifecycle boundary: after the
first positive AppA flow, OI3 cleanup closes the detached TUN fd and Android
removes the `TRANSPORT_VPN` Network.  A second AppA flow in the same session
therefore records `vpn_unavailable` with no tuple attempt.  A fresh session
with IPv6 as its first flow passes (S154), so this is not an IPv6 transport
failure.  The full evidence and source cause are recorded in
[`S156_C2_ONE_FLOW_PER_VPN_SESSION_HOTSPOT.md`](S156_C2_ONE_FLOW_PER_VPN_SESSION_HOTSPOT.md).

EG-11 is reopened as `OPEN_RISK` and the remaining D/E chain is paused.  The
campaign must either register one flow per explicit VPN stop/start, including
that restart cost in every claim, or correct OI3 to retain/re-arm the detached
TUN for additional flows before continuing.

## S157 C2 TUN re-arm addendum (2026-08-24)

S157 implemented the second disposition: successful positive OI3 flows now
settle their HEV generation while retaining the detached TUN fd, watcher and
session wake pipe. A fresh packet starts a new generation; explicit
stop/fault/underlay-invalidated/negative paths still close the session. On the
final Pixel APK, AppA carried IPv4 UDP DNS and IPv6 UDP DNS in one VPN session
on the same VPN handle (`767909875725`), each with a valid 61-byte response;
native generations 1 and 2 emitted `PASS` cleanups with zero residue. A real
active TCP fault emitted `PASS_EXPECTED_FAULT` with `buffers=9/9 residue=0`.

The S156 one-flow boundary is therefore closed for this registered re-arm
contract. EG-11 is `PARTIAL`: C2/D/E may continue, while seamless Android
underlay migration, arbitrary multi-owner concurrency and production capacity
remain separate claims.

## S158 D1-D3 final-topology audit addendum (historical; superseded by S159)

The detailed audit is recorded in
[`S158_D_FINAL_TOPOLOGY_OWNER_OVERLOAD_HOTSPOT.md`](S158_D_FINAL_TOPOLOGY_OWNER_OVERLOAD_HOTSPOT.md).
The selected S157 OI3 source has one process-global `oi3_main`, one
FlowStackOwner context, one target/frame queue/TUN path, and one Android worker
(`workers 1`, `target-thread 1`). Its pending queue and credit/session limits
are per-context constants, not a multi-owner admission/overload contract.

Consequently EG-12 is still `INSUFFICIENT_EVIDENCE` with D1
`BLOCKED_BY_DESIGN`; EG-13 remains only model/Host support; EG-14 is
`INSUFFICIENT_EVIDENCE`; and EG-15 remains `PARTIAL` without a final per-owner
envelope. S129 OI-4 Host/two-pthread evidence remains useful but is explicitly
not a Pixel/four-worker/capacity substitute. D2/D3 and E1/E2 are paused until
the route is either extended to a real multi-owner topology or the campaign is
explicitly narrowed to a single-owner claim.

## S159 D3 submit/backpressure addendum (historical; superseded by S160)

The S158 single-owner audit was superseded by a working two-owner route. D1
and D2 now have bounded Pixel evidence for the tested topology. D3 was then
run once with a bounded 64-datagram same-tuple burst against the rebuilt
artifact; the HEV submit seam returned success for 15 packets and `-5` for 49.
The owner-local accounting correction settled `buffers=74/74 residue=0`, but
no reply was produced and cleanup ended `FAIL ... output=0 ...
error=tun-flow-timeout-no-reply`. See
[`S159_D3_HEV_SUBMIT_BACKPRESSURE_HOTSPOT.md`](S159_D3_HEV_SUBMIT_BACKPRESSURE_HOTSPOT.md).

Current gap disposition: see S160 below. The symbolic `-5` and fatal/no-reply
classification in this section are historical evidence, not the current
adapter behavior.

## S160 D3 overload/recovery addendum (2026-08-24)

S160 maps HEV `-5` to category-1 inflight-pbuf credit exhaustion, adds explicit
owner-local queue-drop accounting, and records three matched Pixel UDP pressure
generations with `PASS_EXPECTED_OVERLOAD`, `buffers` settled to zero residue,
and TUN re-arm. EG-14 is therefore `PARTIAL` for the tested bounded envelope.

The required post-pressure B1 recovery is not closed: a fresh no-D3 baseline
reproduced an ambient Android TCP/5228 flow that ended in
`tun-flow-output-not-a-direct-return` and stopped the owner, after which later
tuples were rejected as `owner-stopped`. This is `VPN-F038`, not an HEV credit
or ADB/UID permission failure. EG-14 recovery remains open and EG-15/E1/E2
stay paused until ambient full-route traffic is isolated or explicitly
classified. See [`S160_D3_OVERLOAD_RECOVERY_EXECUTION_JOURNAL.md`](S160_D3_OVERLOAD_RECOVERY_EXECUTION_JOURNAL.md).

## S161 D3 timed recovery addendum (2026-08-24)

S161 waited for all four concurrent AppA pressure stages to finish before
issuing B1 recovery. Four `PASS_EXPECTED_OVERLOAD` generations settled exact
credits/buffers, re-armed TUN, and produced a valid WSL2 DNS response. The
S160 timeout was therefore harness ordering, not a new runtime hotspot.
EG-14 is `SUPPORTED` for the registered UDP envelope and E1/E2 are unblocked.

## S163 E1/E2 addendum (2026-08-24)

The detailed results are in
[`S163_E1_E2_EXECUTION_JOURNAL.md`](S163_E1_E2_EXECUTION_JOURNAL.md). E1's
40/40 unique-port window, fault/recovery, epoch apply, stop/restart and
resource snapshots remain valid. Corrected OI3/HEV artifacts loaded and the
canonical APK passed controlled Direct HTTP; the incompatible loader pairs are
closed as VPN-F039 preflight defects.

For E2, controlled Direct restart samples were 364/386/585 ms, with successful
screen-off (234 ms) and forced-Doze (1352 ms) cells. The existing public HEV
loop remains 8/6/9 ms, but HEV could not use the controlled LAN endpoint while
the same-UID no-VPN control succeeded; a public repeated-flow Direct sample
also contained a remote read timeout. EG-17 therefore remains
`INCONCLUSIVE`, and EG-18 remains `PARTIAL`: correctness/state evidence is
present, but matched comparative throughput/CPU/RSS/FD/thread/thermal,
full IPv6 TCP/UDP and multi-owner load still need a valid bounded arm.

## S164 HEV external-ingress hotspot addendum (2026-08-24)

The resumed controlled HEV arm is recorded in
[`S164_HEV_EXTERNAL_INGRESS_GATEWAY_WILDCARD_PORT_HOTSPOT.md`](S164_HEV_EXTERNAL_INGRESS_GATEWAY_WILDCARD_PORT_HOTSPOT.md).
The external fd/epoll/read seam is live and TCP checksums pass, but three
valid post-fix attempts reached no TCP listener because the transparent
gateway's port-0 listener is not treated as a wildcard by the owner demux.
This was `VPN-F040`/`OPEN_RISK`, not an ADB or WSL2 endpoint failure. S165
implemented the required external-only correction and closed the hotspot for
the controlled IPv4/TCP arm.

## S165 HEV external-ingress correction addendum (2026-08-24)

The corrected owner-context HEV stage passed a fresh Pixel/WSL2 LAN cycle:
`HTTP/1.0 200 OK`, one SOCKS connect to `192.168.4.5:42083`, and zero VPP
parse/read/write/shim errors. `VPN-F040` is now
`CLOSED_FOR_CORRECTNESS_ARM`; E2 is reopened for matched performance/resource
measurements, IPv6/UDP/DNS coverage, strict-owner negative evidence,
multi-owner load and the final audit. See
[`S165_HEV_EXTERNAL_INGRESS_CORRECTION_EXECUTION.md`](S165_HEV_EXTERNAL_INGRESS_CORRECTION_EXECUTION.md)
and `evidence/s165-hev-external-ingress/`.

## S166 fixture and single-owner re-arm corrections (2026-08-24)

The legacy A2 owner-resolver one-shot runner now sends two packets on one
connected UDP socket so the normal asynchronous first `uid=-1` miss is not
misclassified as a missing completion.  The corrected device cell passed with
`PROBE_WAIT=12` (two packets, three resolver hits, two UID-block packets, zero
errors); the longer wait accounts for the app's five-second no-echo timeout per
intentionally dropped packet.  This is evidence hygiene, not a product
hotspot.  Raw evidence is in
`evidence/s166-a2-4-two-packet-uid-20260824/`.

The first formal isolated canonical OI3 HTTP cell also exposed VPN-F041: after
a successful generation re-armed the TUN, a same-tuple FIN/ACK tail entered
the single-owner reader as a new generation and emitted a secondary cleanup
`FAIL` despite zero residue.  The owner now retains a canonical TCP tombstone
until the next SYN and rejects the tail before admission.  The ARM64 regression
returned HTTP 200 with one clean `PASS` cleanup, logged
`single-admission ... reason=tcp-tail`, and produced no cleanup `FAIL`.
This closes the finding for the bounded correctness arm; E2's matched
performance/protocol/topology measurements remain open.  Evidence is in
`evidence/s166-oi3-tail-fix-20260824/`.

## S167 IPv6 UDP UID extension (2026-08-24)

The corrected owner-resolver cell now covers IPv6 UDP allow and drop.  Both
directions preserved the exact destination
`[2606:4700:4700::1111]:53`, returned resolver `queries=3 hits=3 errors=0`,
and stopped cleanly.  The allow case used nonmatching block UID `112628` and
recorded zero UID-block packets; the drop case used package UID `12628` and
recorded two blocked packets.  Raw evidence is in
`evidence/s167-ipv6-udp-uid-20260824/`.  This closes the bounded IPv6 UDP UID
protocol cell but does not close E2's matched performance or multi-owner gates.

## S168 multi-owner teardown correction (2026-08-24)

The first final-topology multi-owner UDP teardown probe exposed VPN-F042:
two valid pre-fix cells (4 flows, then the minimized 2-flow seam) reached the
same Scudo heap-corruption SIGABRT.  The defect was local to the stop seam:
the VPP worker invalidated lwIP owner pools before the queued HEV task had
drained.  The first correction performed a bounded thread-local HEV task-driver
drain after `hev_socks5_tunnel_owner_stop()` and before
`lwip_owner_context_stop()`; the follow-up expanded the bound, propagated OI3
`NOT_READY`, and guarded HEV destroy until stop was ready.

The fixed ARM64 HEV stage passed one narrow 2-flow regression.  Both owners
completed two generations with `oi3_cleanup result=PASS`, `broker=1/1`,
`direct=1`, `buffers=10/10`, `residue=0`, and zero transport or infrastructure
failures; `fatalFlows=0`, no Scudo/SIGABRT appeared in that cell, and post-stop
VPP/HEV/tun0 residue was absent.  The registered 4-flow final-topology cell
then reproduced the same owner-context Scudo `invalid chunk state`/SIGABRT
boundary on the follow-up-corrected artifact (fourth valid recurrence overall;
the reported address matched the owner-1 lwIP context).  Under the campaign
stop rule, the multi-owner pressure branch is paused; EG-12/EG-13, EG-15 and EG-18
remain `INSUFFICIENT_EVIDENCE`/`PARTIAL` rather than being promoted from the
narrow 2-flow observation.  Evidence: `evidence/s168-multi-owner-udp-teardown-20260824/`.

The late 2026-08-25 S169 follow-up closed VPN-F045 for the tested two-owner UDP
closed-echo envelope.  The source/destination return rewrite is fixed; pending
TUN packets are preserved across rearm; multi-owner UDP now defers
`reason=udp-generation-busy` after one submitted datagram; and HEV's UDP
connector stays persistent across protected responses.  Fresh Pixel evidence
passed for one flow (`runId=86632836943396`, `sent=834 received=834 errors=0`)
and for two owners (`runId=139608275148756`, `sent=1702 received=1702
errors=0`).

The remaining S169 capacity blocker, VPN-F046, is closed for the selected
bounded four-owner design.  The historical two-owner 4-flow run
`83202807976373` produced exactly 20 app timeouts and exactly 20 VPP
`owner-busy` admission rejects because the registered cell asked for four
simultaneous UDP closed-echo flows while the topology only admitted two active
UDP hashes.  The follow-up run `127931250090287` started four owners and passed
with `sent=3698 received=3698 errors=0`, zero `owner-busy`/multi-admission
rejects, and four clean owner teardowns.  EG-12/EG-13/EG-15 are promoted only to
bounded `PARTIAL`: E2 latency/stress, lifecycle trend, and production capacity
remain separate unclosed evidence gaps.

S170 then added the bounded post-F046 E1 repeat/stop resource trend: five
four-owner UDP closed-echo cycles passed with exact app echo, stable app/VPP FD
counts, bounded RSS variation, owned fixture RX/TX and no residual VPP/tun0.
S171 adds the bounded post-F047 Direct-vs-OI3 sample:
`evidence/s171-e2-oi3-direct-sample-20260825-after-fix-full/` passed UDP 64B,
UDP 4x1400B and TCP 1400B cells in both Direct and OI3 modes.  The S171 TCP
hotspot is recorded as VPN-F047 and closed by refreshing the multi-owner TCP
TUN flow deadline on activity.  EG-17 remains `INCONCLUSIVE` because this is
not a matched HEV baseline, Doze/screen-off, thermal or full comparative E2
measurement.

S172 adds the matched HTTP baseline construction preflight and accepted
count-bounded comparison run. The runner requires an explicit comparison APK
when the HEV arm is selected: OI3 plugin + owner-context HEV +
`libtun_poc_plugin.so`/`tun_poc_plugin.so`. The canonical OI3 APK fails that
preflight before ADB, with raw evidence in
`evidence/s172-e2-http-baseline-sample-20260825/run-20260825-125021-144734.log`;
this closes VPN-F048 as a runner/build-provenance hotspot. The comparison APK
then exposed VPN-F049: a FIN/ACK tail could enter OI3 before tombstone
publication, and the duration-only HTTP probe was not matched by request count.
The accepted run
`evidence/s172-e2-http-baseline-sample-20260825/cells-20260825-131542-644207.csv`
uses `MAX_REQUESTS=1`, has Direct/HEV/OI3 all `1/1`, all
`contentLengthCompletions=1`, OI3 `cleanup=5/0`, and `failureCount=0`. EG-17
remains `INCONCLUSIVE` until the full matched E2 matrix runs.

S173 records the next E2 hotspot and its bounded closure. Pre-fix evidence
included Direct/HEV `4/4` with OI3 `3/4`; hash-quality-only correction to
`fnv1a+mix` still left unpaced and 6s-paced OI3 at `3/4` with successor SYN
`owner-busy` rejects. The final OI3 design keeps a busy successor SYN on its
canonical owner through bounded deferred admission, rolls back failed admission
reservations, classifies late non-SYN tail as `tcp-non-syn-busy`, and clears
TCP pending tail at re-arm. Final plugin
`9282f8c82c5223e2c7b144f85a2533100df646ec821ff0ef91737b9ef8a85186` in APK
`441b0279e2685d0d89b6092ce00f64e49742a1fcfaaf691611c826a20fca97c4` passed
OI3 repeat=5
`evidence/s172-e2-http-baseline-sample-20260825/cells-20260825-142858-176008.csv`
with all five cells `4/4` and cleanup `8/0`. The matched Direct/HEV/OI3 run
`evidence/s172-e2-http-baseline-sample-20260825/cells-20260825-143509-282679.csv`
then passed Direct `4/4`, HEV `4/4`, and OI3 `4/4`, all `valid=1`,
`failures=0`. EG-17 remains `INCONCLUSIVE` only because broader
throughput/capacity, CPU/thermal/power, Doze, and long-soak evidence remains
open.

S174 extends the corrected HTTP staircase construction beyond S173. OI3-only
run
`evidence/s174-e2-http-8request-oi3-20260825/cells-20260825-144710-417439.csv`
ran three unpaced 8-request cells; all passed `8/8`, `errors=0`,
`contentLengthCompletions=8`, cleanup `12/0`, and manifest `failureCount=0`.
The matched Direct/HEV/OI3 run
`evidence/s174-e2-http-8request-matched-20260825/cells-20260825-145127-375231.csv`
then passed all three arms at `8/8` with `failureCount=0`; HEV recorded
`socksConnect=8`, and OI3 cleanup was `12/0`. This does not reopen F050. It
records that OI3 still has a material latency boundary in this deferred-owner
path, with p95 around 1.3--2.6 seconds versus much lower Direct/HEV controls.

S175 extends the same corrected HTTP staircase construction to sixteen unpaced
requests. OI3-only run
`evidence/s175-e2-http-16request-oi3-20260825/cells-20260825-150115-968569.csv`
ran three cells; all passed `16/16`, cleanup `20/0`, and manifest
`failureCount=0`. The matched Direct/HEV/OI3 run
`evidence/s175-e2-http-16request-matched-20260825/cells-20260825-150431-029771.csv`
ran three repeats of all three arms; all nine cells passed `16/16`,
`failureCount=0`, HEV accumulated `socksConnect=48`, and OI3 cleanup was
`20/0` in each OI3 cell. This still does not close EG-17 because the open gate
is now performance/resource/device-state breadth rather than HTTP staircase
correctness.

S176 records and closes the next E2 hotspot for concurrent UDP flow admission.
The initial final-APK L4 sample
`evidence/s176-e2-l4-udp-tcp-final-apk-20260825/cells-20260825-152536-302639.csv`
failed both OI3 UDP4 repeats with ten app errors and
`ownerBusy=11`/`multiRejectNonTail=11`, while Direct, OI3 UDP1 and OI3 TCP
passed. The corrected design keeps TCP on F050 canonical-owner deferral but
adds bounded UDP flow-route pinning to an idle owner when the primary owner is
busy. Accepted clean-ABI plugin
`5012eeecb16828edca58f3dc98ddd52330a3b09b26394a3baa94b7c39604cc72` in APK
`f4e350c6478ce9f495afa9b1b97f174c79915592a461aeb25d7e8cdd803e1541` passed
the minimal UDP4 regression, the full Direct/OI3 IPv4 UDP/TCP S176 slice
`evidence/s176-e2-l4-udp-tcp-route-pinning-cleanabi-20260825/cells-20260825-155427-072214.csv`
with all 12 cells valid, and the OI3 HTTP16 regression
`evidence/s176-s175-http16-oi3-route-pinning-cleanabi-20260825/cells-20260825-160228-023067.csv`
with both cells `16/16`. S177 then closed a harness/resource evidence blocker:
S170 provenance no longer hard-codes old artifact hashes, VPP readiness/log
capture avoids blocking log paths, and `adb_read` retries transient WSL/ADB
transport failures. The accepted short foreground final-artifact resource slice
`evidence/s177-e1-final-resource-short3-20260825/` completed two four-flow UDP
cycles with `763/763` and `784/784`, cleanup `4/0` in both cycles,
`failureCount=0`, fixture `2008/2008`, stable fd/thread counts, and thermal
status `0`. EG-17 remains `INCONCLUSIVE` because this is still bounded
correctness/resource evidence, not a matched throughput/CPU/Doze/soak verdict.
