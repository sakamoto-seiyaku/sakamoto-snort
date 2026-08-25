# Evidence-Guided Android VPN POC Campaign Specification

All delegated and main-thread executions must follow
[`ANDROID_VPN_POC_EXECUTION_GUARDRAILS.md`](ANDROID_VPN_POC_EXECUTION_GUARDRAILS.md).
That runbook defines the mandatory evidence chain, failure classification,
artifact/fixture validity gates, bounded retry rule, and hotspot stop rule.
Plane remains the source of truth for open execution work.

Date: 2026-08-23
Updated: 2026-08-25 (S140 run-validity preflight; S156 hotspot; S157 TUN re-arm correction; S158 topology implementation; S159 D3 submit hotspot; S160 overload/recovery execution and ambient-flow hotspot; S161 timed D3 recovery closure; S163 E1/E2 execution; S165 HEV external-ingress correction; S166 owner-resolver runner correction; S167 IPv6 UDP UID extension; S168 multi-owner teardown correction, fourth recurrence, WSL2 echo fixture preflight, source-port-base harness correction, preflighted UDP echo-loss finding; S169 F045/F046 closure; S170 post-F046 E1 resource trend; S171 bounded E2 sample and F047 TCP idle-timeout closure; S172 matched HTTP baseline comparison-APK, admission, and request-shape closure; S173 foreground HTTP staircase owner-capacity closure; S174 bounded 8-request HTTP staircase execution; S175 bounded 16-request HTTP staircase execution; S176 UDP multi-flow route-pinning closure; S177 final resource short slice and ADB harness closure; S178 final B1 dual-stack DNS dataplane/lifecycle split; S179 current-artifact controlled B2 failure-semantics regression; S180 B1 forced DNS fallback fixture; S181 real no-reply and closed TCP timeout fixture; S182 representative target-IP policy drop; S183 representative AppA UID drop; S184 bounded real LAN TCP RST propagation closure; S185 bind/protect/broker infrastructure failure separation; S152 A2 UID matrix design gap; S156 A2 resolver/correlation closure)
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

### Run-validity preflight for real-network cells

Before B1 and every later Pixel cell that reuses its real-network artifact,
record and pass these validity gates before interpreting a timeout or missing
return as a datapath or transport result:

1. **Transitive artifact provenance.** Join the overlay source, selected plugin,
   required HEV owner API, runtime stage, both canonical and Android
   linker-prefixed plugin spellings, APK members, installed APK, and device
   runtime with hashes. Both packaged OI3 plugin spellings must be
   source-identical to the explicitly selected `VPP_POC_PLUGIN`; a build that
   loaded a stale alias or the wrong HEV stage is `INVALID`.  As of
   2026-08-25, `build-debug-apk.sh` enforces this for OI3 APKs by requiring
   `libhev-socks5-tunnel.so` to export the owner-context symbols consumed by
   `owner_inline_oi3.c`; bypassing that guard invalidates the run.
2. **Per-UID Android network eligibility.** Record the package/UID, active
   underlay Network snapshot, relevant runtime permission grants, and compat
   overrides. For a controlled LAN fixture on Android 16, a direct socket from
   the same application UID must complete with the VPN stopped. A shell-UID
   probe is only an endpoint control and cannot substitute for this gate because
   Local Network Protection is applied per application UID.
3. **Non-VPN connector underlay identity.** For every brokered connector, record
   all candidate Network handles/capabilities and the selected handle. The
   selected network must carry `NET_CAPABILITY_NOT_VPN` and must not have
   `TRANSPORT_VPN`; a successful `Network.bindSocket()`/`VpnService.protect()`
   pair on the UID-scoped VPN network is invalid evidence. The broker must fail
   closed if no physical non-VPN underlay is available.
4. **Declared Local Network Protection state.** State whether the cell is
   intentionally testing Local Network Protection. If it is not, remove a stale
   `RESTRICT_LOCAL_NETWORK` test override, grant the POC-only temporary
   `NEARBY_WIFI_DEVICES` authority where required, and rebuild/reboot netd/BPF
   state when the platform change requires it. This POC treatment is not a
   release permission-policy decision.
5. **Fixture readiness.** Prove the endpoint, address family, response shape,
   and cleanup path independently before starting the full-path cell.  For any
   `expectEcho=true` LAN cell, the same application UID must complete a
   VPN-stopped direct echo preflight for the exact protocol, endpoint, and
   payload shape.  Host-side receive counters alone are insufficient: a WSL2
   endpoint that receives Android UDP but does not deliver echo replies back to
   the app is an `INVALID` fixture, not OI3 return-path evidence.
6. **Real-device source-port hygiene.** Multi-flow app probes must not assume a
   fixed Android UDP source-port range.  The runner must make the local source
   port base configurable, record it in the manifest, and the parser must
   validate against that manifest value.  A `BindException`/`EADDRINUSE` on the
   probe source ports is a harness collision with ambient Android traffic, not
   datapath evidence.

A failed preflight is an environment, permission, fixture, or artifact finding.
Correct it and rerun the same cell; do not classify it as transport timeout,
OI3 return failure, heap-regression evidence, or B1 counter-evidence. The motivating failure and corrected
evidence are recorded in
[`S140_B1_RETURN_HOTSPOT_DIAGNOSIS.md`](S140_B1_RETURN_HOTSPOT_DIAGNOSIS.md) and
[`S141_B1_TCP_UNDERLAY_NETWORK_HOTSPOT.md`](S141_B1_TCP_UNDERLAY_NETWORK_HOTSPOT.md).
The later stream interruption is recorded in
[`S142_B1_TCP_STREAM_FRAMING_HOTSPOT.md`](S142_B1_TCP_STREAM_FRAMING_HOTSPOT.md)
and its short-segment owner-drive seam and closure are recorded in
[`S143_B1_SHORT_SEGMENT_ACK_HOTSPOT.md`](S143_B1_SHORT_SEGMENT_ACK_HOTSPOT.md).
S143 confirmed that the owner-context `tcp_output_ctx()` lacked an ACK-only
packet path when a delayed-ACK PCB had no unsent segment; the owner-local
ACK-only correction was rebuilt and the separate/coalesced IPv4 DNS-over-TCP
pair passed with exact TUN return and zero residue.  The hotspot is closed for
the registered Pixel artifact; the broader B1 matrix remains open.

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
  TUN return, app result and exact cleanup/resource ledger.  Also retain the
  broker candidate/selected non-VPN Network handle.  Seal the run-validity
  preflight receipt once for the exact artifact/device state and repeat its
  per-UID/selected-underlay network parts whenever the package,
  permission/compat state, underlay, runtime stage, or endpoint fixture
  changes.
- **Host/model support:** Endpoint fixtures, packet parsing, DNS response shape,
  checksum/provenance replay and deterministic failure setup.  Host never closes
  the real-network claim.
- **Lightweight falsifiers:** narrow/loopback route substituted for final cell;
  missing external IPv6; unprotected or fallback socket; SOCKS/second datapath;
  original destination lost; DNS redirect/resolver path introduced; return
  packet loops back to Flow Stack; competing TUN reader; shell-only LAN control
  substituted for the protected-socket package UID; or a staged/APK plugin alias
  whose hash does not match the registered source artifact.
- **Stream gate:** DNS-over-TCP must exercise both coalesced and separate
  application writes.  A connector that settles after the first short segment,
  drops the remaining length/body bytes, or cannot preserve the protected
  original-destination flow is a campaign interruption, even if one-write HTTP
  and UDP DNS cells pass.  SAKAMOTO-142 records this boundary.
- **Current execution evidence:** S148 reran the final APK on Pixel with
  full-route AppA IPv4/IPv6 UDP/TCP DNS, separate/coalesced TCP writes, a
  recorded non-VPN Wi-Fi underlay, valid 61-byte responses, direct/TUN return,
  and zero residue for every cell. S178 reran the current S176/S177 final
  artifact across IPv4 UDP DNS, IPv4 TCP DNS separate/coalesced, IPv6 UDP DNS,
  and IPv6 TCP DNS separate/coalesced. Accepted run `20260825-170934-541913`
  recorded `cellsRecorded=6`, `appValidCount=6`, `nativeValidCount=6`,
  `failureCount=0`, valid 61-byte DNS responses in all cells, and zero
  post-run `vpp`/`tun0` residue. Its status is
  `PASS_DATAPLANE_WITH_CLEANUP_MARKER_GAPS`: three rows are full `PASS`, and
  three TCP rows are dataplane-valid but missing late cleanup markers. S180
  adds one bounded IPv4 forced-fallback cell using a WSL2/LAN DNS fixture:
  UDP query `1234` received `TC=1`, AppA retried the same query ID over TCP in
  the same B1 operation, TCP returned a valid 45-byte DNS response, native
  evidence had `brokerSuccess=2`, and `failureCount=0`.
- **Supported result:** one exact Pixel artifact proves the minimum full-device
  positive dataplane for all required address-family/protocol/DNS cells; S178
  reconfirms that dataplane on the current final artifact while keeping
  cleanup-marker timing as a separate lifecycle non-claim. S180 supports the
  forced UDP-to-TCP fallback seam for one IPv4 WSL2/LAN fixture cell.
- **Non-claims:** Throughput/capacity, network handover, long lifecycle, release
  safety, or third-party OEM behavior.
- **Interruption condition:** real external routing requires an unprotected
  fallback, second packet path, mutable global authority, or a violation of the
  dedicated-device safety/cleanup boundary; or the TCP stream cannot carry
  multiple application writes with exact Direct/TUN settlement.

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
- **Current execution gate:** S146 found the deterministic negative-result
  contract defect; S147 corrected it and reran refused, no-reply, policy-drop,
  and dual-stack success controls. All now have durable cell-aware outcomes
  and zero residue. S179 reran the refused, no-reply, and policy-drop subset
  on the current S176/S178 final artifact with run `20260825-172718-237536`;
  all three cells passed with `PASS_EXPECTED_FAILURE`, `verifierRc=0`,
  `failureCount=0`, and zero post-run `vpp`/`tun0` residue. S181-S183 then
  close the selected real WSL2/LAN no-reply/timeout, target-IP policy-drop,
  and representative AppA UID-drop slices. S184 then closes the bounded real
  post-SYN reset slice: an exact owner-local `ECONNRESET` is mapped by the
  narrow owner-context primitive to one rewritten downstream `RST|ACK`, AppA
  observes `dns_response_reset`, and cleanup settles exactly. The old wrapper
  failure was a corrected double-count of mirrored logs, not a target failure.
  The S184 hotspot stop is lifted; separately registered B2 gaps may proceed.
- **Interruption condition:** correctness requires implicit fallback, cannot
  separate policy from transport/infrastructure state, or the negative result
  contract cannot distinguish an expected refusal/timeout/drop from an actual
  POC failure.

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
- **Current execution gate:** S151 revises and executes the missing
  `NetworkCallback→JNI/CLI→FlowStackOwner` epoch seam.  A real active AppA TCP
  flow observed Wi-Fi loss, the owner emitted one
  `PASS_EXPECTED_UNDERLAY_INVALIDATION` settlement with zero residue, and the
  callback observed the replacement physical handle.  Android 16 removed the
  old VPN Network during the loss, so the selected supported recovery path is
  one bounded explicit VPN stop/start; fresh AppA IPv4 and IPv6 traffic then
  bound/protected on the replacement snapshot.  S148 remains the separate
  full-route B1 dual-stack response control.  C1 is closed for the selected
  Pixel artifact under this bounded-restart contract; seamless migration and
  automatic session recreation remain non-claims.  C2 still requires the
  real-B1 stop/fault/restart sequence.

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
- **Current execution evidence:** S149 passes the controlled OI5 lifecycle
  sequence on the current APK: normal no-reply completion, explicit fault,
  restart TCP4, old UDP/new TCP sequencing, four epoch transitions, and zero
  residue.  Its runner correction is recorded (natural no-reply DONE is valid;
  fault emits `PASS_EXPECTED_FAULT`).  This is controlled loopback/no-AppA
  injection evidence, not the minimum complete real-B1-traffic C2 claim.  S151
  resolves the C1 underlay seam.  S152 found the missing normal-stop
  classifier; S153 corrected it and reran a real AppA TCP stop cell with
  `PASS_EXPECTED_STOP outcome=EXPECTED_STOP`, `broker=1/1`,
  `buffers=10/10`, and `residue=0`.  S155 then proved a formal explicit
  stop/start can carry one fresh IPv4 flow, but a second IPv6 flow in that same
  session saw `vpn_unavailable` after OI3 closed the detached TUN.  S156
  recorded the hotspot; S157 implemented the TUN re-arm correction and reran
  real same-session IPv4→IPv6 DNS on one VPN handle with two fresh generations,
  zero residue and an active-flow `PASS_EXPECTED_FAULT`.  C2/D/E continue under
  the corrected per-flow-generation/re-armed-session contract; arbitrary
  concurrency and seamless Android migration remain non-claims.

## D-batch execution gate (S158 historical; superseded by S159)

Before running D1/D2/D3, the selected artifact must expose the final
multi-owner topology that those POCs name. S158's static audit found that the
S157 OI3 artifact still has one global `oi3_main`, one FlowStackOwner context,
one target/frame queue/TUN path, and an Android startup fixed to
`workers 1`/`target-thread 1`. The per-context queue and credit constants are
not a multi-owner admission or overload contract. Therefore D1 is
`BLOCKED_BY_DESIGN`, D2/D3 are `BLOCKED_BY_D1`, and E1/E2 are paused; see
[`S158_D_FINAL_TOPOLOGY_OWNER_OVERLOAD_HOTSPOT.md`](S158_D_FINAL_TOPOLOGY_OWNER_OVERLOAD_HOTSPOT.md).
Host OI-4 evidence remains a supported lower-fidelity reference only. The
multi-owner route is now implemented, so the historical `BLOCKED_BY_DESIGN`
disposition is closed for D1/D2. D3 is governed by the S159 runtime gate below.

## S159 D3 execution gate (historical; superseded by S160)

S158's topology decision has been implemented: the selected Android artifact
now instantiates two owner contexts and D1/D2 have bounded Pixel evidence.
However, the one corrected D3 burst rerun reached the HEV submit credit
boundary (`15` successful submits, then `49` returns of `-5`) without a reply;
cleanup settled `buffers=74/74 residue=0` but ended with
`tun-flow-timeout-no-reply`. The detailed record is
[`S159_D3_HEV_SUBMIT_BACKPRESSURE_HOTSPOT.md`](S159_D3_HEV_SUBMIT_BACKPRESSURE_HOTSPOT.md).

D3 was `PAUSED_BY_RUNTIME_HOTSPOT`; the detailed current disposition is in
S160 below.

## S160 D3 overload/recovery execution gate (2026-08-24)

The matched Pixel artifact now maps HEV submit `-5` to category-1 inflight-pbuf
credit exhaustion and treats current-packet owner-local UDP queue/credit
exhaustion as an explicit overload drop. Three bounded generations produced
`PASS_EXPECTED_OVERLOAD`, exact settlement and TUN re-arm. This closes the
credit-accounting correction for the tested envelope but does not close D3.

The post-pressure recovery assertion and a fresh no-D3 baseline were both
contaminated by a reproducible ambient Android TCP/5228 flow in full-route
multi mode: it ended `tun-flow-output-not-a-direct-return`, stopped its owner,
and caused later tuples to be rejected as `owner-stopped`. This is recorded as
VPN-F038 and is separate from HEV credit, ADB, UID and permission validity.
D3 is `PAUSED_BY_AMBIENT_FLOW_HOTSPOT`; E1/E2 remain paused. Before resuming,
isolate/classify ambient full-route traffic or use a controlled no-ambient route,
then rerun one clean D3-to-B1 recovery assertion. Do not report D3 as `PASS`.

## S161 D3 timed recovery closure (2026-08-24)

The S160 recovery attempt was invalid as a gate because the probe was launched
while the four `repeat=16` pressure stages were still emitting. S161 adds a
completion barrier, offers all 64 packets concurrently, waits for the final
repeat, and then runs the controlled WSL2 DNS recovery probe. Four generations
are `PASS_EXPECTED_OVERLOAD` with exact settlement and re-arm; the post-pressure
B1 receives a valid DNS response and generation 6 is `PASS` with `direct=1`,
`rewritten=1`, and `residue=0`. See
[`S161_D3_TIMED_RECOVERY_EXECUTION_JOURNAL.md`](S161_D3_TIMED_RECOVERY_EXECUTION_JOURNAL.md).

The D3 disposition is now `SUPPORTED_FOR_TESTED_UDP_ENVELOPE`. The ambient
TCP/5228 outcome is classified as an expected no-reply run-validity case and
does not pause the shared owner. E1/E2 are unblocked; their resource trend and
comparative performance/device-state gates remain open.

## S163 E1/E2 execution gate (2026-08-24)

The detailed run is recorded in
[`S163_E1_E2_EXECUTION_JOURNAL.md`](S163_E1_E2_EXECUTION_JOURNAL.md). E1's
40/40 unique-port window, fault/recovery, epoch apply, stop/restart and
resource snapshots pass for the registered bounded envelope. The OI3 plugin
and owner-context HEV were rebuilt from one clean source/stage identity after
two deterministic loader mismatches; the final canonical APK excludes the
temporary `tun_poc` plugin and passed a controlled HTTP smoke.

E2 has valid Direct/device-state samples (controlled restart latencies
364/386/585 ms, screen-off 234 ms, forced-Doze 1352 ms), but remains
`INCONCLUSIVE` for ADR-0007 because the matched HEV performance/resource matrix
is incomplete. The public repeated-flow Direct arm also contained a remote
read timeout. S164's three valid failures isolated a design hotspot: the
external fd was read and the TCP SYN checksum passed, but the transparent
gateway's port-0 listener did not match the destination port. S165 implemented
the external-only wildcard correction and returned controlled HTTP 200, so the
HEV arm is reopened for the remaining traffic/protocol/resource gates; see
[`S164_HEV_EXTERNAL_INGRESS_GATEWAY_WILDCARD_PORT_HOTSPOT.md`](S164_HEV_EXTERNAL_INGRESS_GATEWAY_WILDCARD_PORT_HOTSPOT.md).

## S165 HEV external-ingress correction gate (2026-08-24)

S165 implemented the explicit external-only wildcard demux mode and rebuilt
the owner-context HEV stage.  The first valid Pixel/WSL2 LAN regression
returned `HTTP/1.0 200 OK` in 8 ms, with one SOCKS connect to
`192.168.4.5:42083` and clean VPP parse/read/write counters.  A follow-up
owner-resolver lifecycle run completed `50/50 PASS` with constant fd counts
and bounded HEV RSS (`62104..62324 KiB`).  The S164 design hotspot is therefore
closed for controlled IPv4/TCP correctness and the HEV arm is reopened.  E2
remains `INCONCLUSIVE`: matched Direct/HEV throughput, IPv6/UDP/DNS coverage,
strict-owner negatives, multi-owner load and the final audit are still
required.  See
[`S165_HEV_EXTERNAL_INGRESS_CORRECTION_EXECUTION.md`](S165_HEV_EXTERNAL_INGRESS_CORRECTION_EXECUTION.md)
and the compact evidence under `evidence/s165-hev-external-ingress/`.

## S166 owner-resolver runner correction (2026-08-24)

The legacy owner-resolver UDP runner's one-shot default treated the normal
asynchronous first `uid=-1` miss as a missing UID completion.  This is a
fixture/verdict boundary, not a new datapath hotspot.  Its default now sends
two packets on one connected UDP socket; `UDP_COUNT=1` remains an explicit
raw-miss mode.  The corrected device cell passed with `PROBE_WAIT=12` (two
packets, three resolver hits, two UID-block packets, zero errors); the longer
wait accounts for the app's five-second no-echo timeout per dropped packet.
Evidence is under `evidence/s166-a2-4-two-packet-uid-20260824/`.  The full E2
gate remains open.  The same S166 follow-up also corrected a
single-owner OI3 re-arm boundary: a FIN/ACK tail after a successful TCP
generation was being admitted as a new generation and could emit a secondary
`oi3_cleanup result=FAIL`.  The owner now retains a canonical TCP tombstone
until the next SYN and rejects that tail before admission; the ARM64 canonical
regression logged `single-admission ... reason=tcp-tail`, one generation-1
cleanup `PASS` (`direct=3`, `broker=1/1`, `residue=0`), and no cleanup `FAIL`.
This is VPN-F041, a corrected POC admission finding rather than a new
three-attempt hotspot.  Evidence is under
`evidence/s166-oi3-tail-fix-20260824/`; E2's matched matrix remains open.

## S167 IPv6 UDP UID extension (2026-08-24)

The corrected two-packet owner-resolver cell now covers IPv6 UDP.  Against
`2606:4700:4700::1111:53`, both allow (block UID `112628`) and drop (block UID
`12628`) passed with exact tuple preservation, resolver `queries=3 hits=3
errors=0`, and clean stop.  The allow cell recorded zero UID-block packets;
the drop cell recorded two.  Raw evidence is under
`evidence/s167-ipv6-udp-uid-20260824/`.  This extends protocol/UID evidence;
the matched E2 performance and final-topology gates remain open.

## S168 multi-owner teardown correction (2026-08-24)

The first final-topology UDP teardown cell exposed a real local lifecycle
defect, VPN-F042.  A 4-flow cell and the minimized 2-flow cell both reached
the same Scudo heap-corruption SIGABRT while one VPP owner still had queued
HEV work.  The stop path signalled HEV, then invalidated lwIP pools before the
later OI3 scheduler drain could finish those tasks.

The first correction drained the thread-local HEV task driver in bounded
quanta on the non-HEV VPP worker path before invalidating the lwIP owner
context.  A follow-up correction expanded that drain to 64 calls of 1024
quanta, made OI3 retry `NOT_READY` without destroying a live context, and
guarded the HEV destroy path.  The canonical VPP/OI3 artifact and the
no-`tun_poc` packaging boundary remain unchanged.  One fixed 2-flow
Pixel/WSL2 regression completed with `fatalFlows=0`; both owners produced two
clean `oi3_cleanup result=PASS` generations (`broker=1/1`, `direct=1`,
`buffers=10/10`, `residue=0`) and no Scudo/SIGABRT.  Normal stop left no
VPP/HEV process or `tun0`.

The registered fixed-artifact 4-flow cell then reproduced the same owner
context Scudo `invalid chunk state`/SIGABRT boundary while another owner had
already cleaned up; the reported address matched the owner-1 lwIP context.
This is the fourth valid recurrence of VPN-F042, including after both local
lifecycle corrections.  Under the campaign stop rule, the multi-owner
pressure branch and dependent E2 resource/performance matrix are paused; no
further blind retry is allowed.  The 2-flow PASS remains a narrow regression
observation, not a capacity claim.  Evidence is under
`evidence/s168-multi-owner-udp-teardown-20260824/`, including
`fourth-failure-summary.txt`.

Follow-up diagnosis refined the POC design defect: owner finish/destroy is
owner-thread-affine.  The multi-owner worker tail previously finished any
`active && finish_requested && residue==0` owner from the current VPP worker.
Because `oi3_finish_for()` stops/destroys the owner Flow Stack and drains HEV
tasks through thread-local scheduler state, a foreign worker could invalidate
another owner's lwIP/HEV context.  The corrected POC re-enqueues foreign-owner
finish to the owner `target_thread` and keeps destroy guarded until stop is
ready.  Static regressions cover the owner-thread lifecycle and foreign-owner
tail deferral.

A separate Android preflight pitfall was also corrected before retrying
pressure: the debug APK must package one matching VPP runtime/plugin build
closure.  Mixing the default runtime stage with an OI3 plugin from another VPP
build produced a live VPP process whose `show plugins` was empty and whose OI3
CLI commands were `unknown input`.  The APK now emits a startup config that
loads from the APK native library directory with `name-filter
libhev_external_driver_poc_plugin.so`, and the stage guard scans only the
selected plugin closure instead of unrelated historical P6 plugin source.  The
current Pixel preflight starts with `mode=vpp-oi3-multi`, `vppMode=27`,
`rc=0`, lists `libhev_external_driver_poc_plugin.so` in `show plugins`, accepts
`sakamoto-oi3 underlay`, and runs `sakamoto-oi3 multi tun fd 3
target-thread-a 1 target-thread-b 2`.

The approved 2026-08-25 rerun did not reproduce the Scudo/SIGABRT heap
boundary in two 4-flow attempts or a minimized 1-flow probe, but it is not a
valid echo regression.  The WSL2 UDP fixture received packets from the Pixel
while the app received zero echo replies; the same zero-reply result reproduced
with the VPN stopped and no VPP process running, and a WSL2 TCP echo fixture
timed out before connect.  This creates VPN-F043: WSL2 LAN echo endpoints
require same-package, VPN-stopped bidirectional preflight before
`expectEcho=true` cells are accepted.  At that point S168 was fixture-blocked
rather than closed or heap-failed; the follow-up below supersedes that fixture
blocker.

The current fixture is now preflighted.  Disabling the stale
`RESTRICT_LOCAL_NETWORK` compat override for `com.sakamoto.snort.vpnlite`
allowed same-package, VPN-stopped direct controls to pass against
`192.168.4.5`: UDP `42185` returned `bytes=192 packets=3 received=3`, and TCP
`42186` returned `sent=1 received=1`.  The next 4-flow retry found and fixed a
separate harness defect: UDP source ports `40000`--`40003` can collide with
ambient Android sockets (`EADDRINUSE`).  The app now accepts and logs
`sourcePortBase`; the formal runner defaults to UDP `43000` and TCP `44000`;
manifests record `sourcePortBase`; and the parser validates UDP ports from the
manifest.

With `sourcePortBase=43000` and the endpoint preflight passing, the valid
endpoint 4-flow UDP closed run `56779517593894` did not reproduce the
Scudo/SIGABRT heap boundary.  VPP pid `11048` survived and OI3 multi reported
two active owners with zero residue.  The app result was still not a closed
echo pass, which created VPN-F045.  Subsequent minimization fixed the return
tuple rewrite, pending queue preservation, and same-generation UDP inflight
guard.

S169 then closed VPN-F045 for the tested two-owner UDP envelope.  The remaining
HEV-side defect was that the UDP connector session returned terminal status
after one protected response, leaving OI3 to wake a connector with no runnable
task.  The HEV patch now keeps UDP no-frame polls non-terminal and returns a
positive per-datagram completion after protected response output.  Rebuilt
artifact hashes were APK
`c15604413b3cb234a958b42d5c23892228fb4cd2f761af8ce2790e3ce1e48a61`, HEV
`37481673d6547c5f2a178de04bf4c4b5f60ba6ce1bed7c7cba1cd22b606ac96d`, and OI3
plugin `60243ba744dee0201e99b1d350cde7cfea807dad7933e76f180bffcbac7423ff`.
The 1-flow run `86632836943396` passed (`sent=834 received=834 errors=0`), and
the 2-flow run `139608275148756` passed (`sent=1702 received=1702 errors=0`).

The next 4-flow run `83202807976373` did not reproduce heap corruption or the
old UDP lifecycle loss.  It exposed VPN-F046: the previous OI4 final topology
was two owners with one active UDP hash per owner.  Ports `43100` and `43103`
passed, while ports `43101` and `43102` produced exactly 20 app timeouts
matching 20 VPP `oi4 multi-admission result=REJECT ... reason=owner-busy`
records.  F046 was then corrected by expanding OI4 to four owner contexts and
starting Android `vpp-oi3-multi` with `target-thread-a/b/c/d`.  The follow-up
4-flow run `127931250090287` passed with `sent=3698 received=3698 errors=0`,
four active owner ingress ledgers, zero `owner-busy`/multi-admission rejects,
and four clean `oi3_cleanup result=PASS residue=0` teardowns.  S168/F042 is
now closed for the corrected four-owner UDP regression; E2 performance and the
broader engineering envelope still require their own registered cells.

S170 then ran the bounded post-F046 E1 repeat window on the same corrected APK.
Five repeated four-owner UDP closed-echo cycles passed with exact app echo,
owned fixture RX/TX `12762/12762`, four clean owner teardowns per cycle,
`pidof vpp` empty after cleanup, app/VPP FD counts stable at `120/41`, and RSS
variation bounded to `648/480 KiB`.  This supports the corrected four-owner
UDP repeat/stop resource window, not E2 performance, Doze, thermal behavior or
production capacity.

S171 then added the bounded direct-vs-final-topology E2 sample.  The first
corrected-artifact run exposed VPN-F047: multi-owner TCP used a five-second
absolute generation lifetime instead of an idle timeout, so `tcp:1:1400
steady=6` consistently failed with `sent=N received=N-1` and only `tcp-tail`
rejects; increasing app read timeout to 15 seconds did not help.  OI3 now
refreshes the TUN flow deadline on TCP activity and treats FIN/RST as terminal.
The rebuilt APK
`3ba6f24260e2e2dc417e3f150f04ad7a67e6458c26e630e369e623e0dc8f14e4` passed the
targeted 3-repeat TCP regression and the full S171 sample
`20260825-122707-906865`: Direct and OI3 cells for UDP 64B, UDP 4x1400B and TCP
1400B were all valid, with OI3 TCP `sent=612 received=612` and zero TCP tail
rejects.  This closes the bounded S171 sample, not matched HEV baseline
performance, Doze, thermal or final audit coverage.

S172 then corrected the next E2 construction hotspots before a long matched
run. The canonical OI3 APK is valid for OI3 evidence but intentionally lacks
`libtun_poc_plugin.so`/`tun_poc_plugin.so`, while the legacy `vpp-hev` baseline
is a tun-poc mode; S172 records that comparison-APK provenance boundary as
VPN-F048. The first comparison runs then exposed VPN-F049: OI3 multi-owner TCP
could admit a FIN/ACK tail before publishing the completed tuple tombstone, and
the duration-only HTTP probe was a throughput/capacity shape rather than a
matched request-count baseline. OI3 now closes owner-local admission during
teardown and reopens it after tombstone publication; the app HTTP probe is
Content-Length aware and S172 defaults to `MAX_REQUESTS=1`. Accepted run
`20260825-131542-644207` passed Direct/HEV/OI3 with `failureCount=0` on
comparison APK
`67f16c3a045c0a786e49ecb1f99a7a6496080ea0761404447c04434617880a94`. This
closes the bounded matched HTTP baseline construction slice only; it does not
close full E2.

## 7. Batch D -- Multi-owner ownership and overload

### POC D1 -- Pixel final-topology multi-owner isolation and distribution

- **Question / gaps:** EG-12/EG-13 and VPN-F010/VPN-F014/VPN-F015.  Does the
  final owner-inline artifact replicate into independent Pixel shards with a
  realistic tuple distribution?
- **S158 disposition (historical):** `BLOCKED_BY_DESIGN`. The selected S157
  artifact exposed one global owner/context/queue/TUN and no owner registry or
  tuple-to-shard dispatch. The route has since been implemented; D1 is now
  `PASS_FOR_TESTED_ENVELOPE` for the exercised two-owner Pixel matrix.
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
- **S158 disposition (historical):** `BLOCKED_BY_D1`. The current artifact now
  exposes per-owner admission; D2 is `PASS_FOR_TESTED_ENVELOPE` for the
  concurrent owner-busy case, while broader resource exhaustion remains a
  claim gap.
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
- **S158/S159 disposition (historical):** `BLOCKED_BY_D1`, then
  `PAUSED_BY_RUNTIME_HOTSPOT`. S160 maps HEV `-5` to category-1 inflight-pbuf
  credit exhaustion and records three bounded Pixel UDP generations with
  explicit overload drops, exact settlement and TUN re-arm.
- **Current disposition:** `SUPPORTED_FOR_TESTED_UDP_ENVELOPE`. S161's timed
  rerun proves post-pressure recovery on the controlled WSL2 DNS endpoint;
  see [`S161_D3_TIMED_RECOVERY_EXECUTION_JOURNAL.md`](S161_D3_TIMED_RECOVERY_EXECUTION_JOURNAL.md).
  Production capacity, infinite soak, and arbitrary public endpoint behavior
  remain non-claims.
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
- **S170 post-F046 status:** `PASS_FOR_BOUNDED_POST_F046_E1_WINDOW` for five
  repeated four-owner UDP closed-echo cycles with stable FD/thread counts,
  bounded RSS variation, owned fixture evidence and exact per-cycle cleanup.
  It is narrower than the full E1 matrix because it does not rerun dual-stack
  TCP/UDP/DNS, epoch transition, or fault/restart on the F046 artifact.
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
- **S171 bounded sample status:** `PASS_FOR_BOUNDED_DIRECT_VS_OI3_SAMPLE`.
  The corrected APK
  `3ba6f24260e2e2dc417e3f150f04ad7a67e6458c26e630e369e623e0dc8f14e4`
  passed Direct/OI3 UDP 64B, UDP 4x1400B and TCP 1400B cells with
  `failureCount=0` in
  `evidence/s171-e2-oi3-direct-sample-20260825-after-fix-full/`.  This also
  closes VPN-F047, the TCP absolute-timeout/tombstone hotspot, for this bounded
  sample.
- **S172 matched-baseline construction status:** `BOUNDED_HTTP_BASELINE_SLICE_PASS`.
  S172 first stopped before ADB when the HEV arm was requested but the APK
  lacked `libtun_poc_plugin.so`/`tun_poc_plugin.so`, as recorded in
  `evidence/s172-e2-http-baseline-sample-20260825/run-20260825-125021-144734.log`
  and VPN-F048. The accepted comparison APK then passed a count-bounded
  Direct/HEV/OI3 HTTP baseline in run `20260825-131542-644207`:
  Direct `1/1`, HEV `1/1`, OI3 `1/1`, all with
  `contentLengthCompletions=1`, OI3 `cleanup=5/0`, and `failureCount=0`.
  The run records APK hash
  `67f16c3a045c0a786e49ecb1f99a7a6496080ea0761404447c04434617880a94`, OI3
  plugin
  `96e0e9f4cbf61fa2216c2ecff2e0ed568a98f966f0ef3b9f647cc74c92381806`,
  tun-poc
  `4f5608a631215a622b60bb72026edb6a8743011ed2c7d5ede9e1243a3844b0cd`, and
  HEV owner-context library
  `37481673d6547c5f2a178de04bf4c4b5f60ba6ce1bed7c7cba1cd22b606ac96d`. The
  slice is still only a bounded E2 construction sample, not the full ADR-0007
  verdict.
- **S173 foreground HTTP staircase status:** `CLOSED_FOR_BOUNDED_HTTP_STAIRCASE_SLICE`.
  The 4-request OI3 cliff was a real deterministic-owner/single-active TCP
  successor-SYN admission defect, not ADB/APK/fixture noise. Hash quality was
  first corrected from raw FNV to `fnv1a+mix`, then OI3 was changed to keep a
  busy successor SYN on its canonical owner via bounded owner-local deferred
  admission (`OI3_TUN_DEFERRED_KIND`, `multi_deferred[]`,
  `owner-busy-deferred`). A repeat-run sub-defect where stale TCP pending tail
  entered the next deferred generation was fixed by clearing TCP pending at
  re-arm (`tcp-rearm-stale-tail`). Final plugin
  `9282f8c82c5223e2c7b144f85a2533100df646ec821ff0ef91737b9ef8a85186` in APK
  `441b0279e2685d0d89b6092ce00f64e49742a1fcfaaf691611c826a20fca97c4`
  passed OI3 repeat=5
  `evidence/s172-e2-http-baseline-sample-20260825/cells-20260825-142858-176008.csv`
  with all five cells `4/4`, cleanup `8/0`, `valid=1`, and deferred successor
  SYN promotions present. The matched Direct/HEV/OI3 run
  `evidence/s172-e2-http-baseline-sample-20260825/cells-20260825-143509-282679.csv`
  then passed Direct `4/4`, HEV `4/4`, and OI3 `4/4`, all `valid=1`,
  `failures=0`. This restores the bounded S173 staircase as an E2 construction
  slice, but it is not a general TCP concurrency/throughput/thermal proof.
- **S174 8-request HTTP staircase status:** `PASS_FOR_BOUNDED_8REQUEST_HTTP_STAIRCASE_SLICE`.
  S174 reused the final S173 APK
  `441b0279e2685d0d89b6092ce00f64e49742a1fcfaaf691611c826a20fca97c4`
  and OI3 plugin
  `9282f8c82c5223e2c7b144f85a2533100df646ec821ff0ef91737b9ef8a85186`.
  OI3-only run
  `evidence/s174-e2-http-8request-oi3-20260825/cells-20260825-144710-417439.csv`
  ran three unpaced 8-request cells; all passed `8/8`, `errors=0`, cleanup
  `12/0`, and manifest `failureCount=0`. The matched Direct/HEV/OI3 run
  `evidence/s174-e2-http-8request-matched-20260825/cells-20260825-145127-375231.csv`
  then passed Direct `8/8`, HEV `8/8`, and OI3 `8/8`, all `valid=1`,
  `failureCount=0`; HEV recorded `socksConnect=8`, and OI3 cleanup was
  `12/0`. OI3 p95 stayed around 1.3--2.6 seconds across the OI3 cells, so this
  strengthens correctness construction but leaves the performance envelope
  open.
- **S175 16-request HTTP staircase status:** `PASS_FOR_BOUNDED_16REQUEST_HTTP_STAIRCASE_SLICE`.
  S175 reused the same final S173 artifact and doubled the request-count ladder
  again. OI3-only run
  `evidence/s175-e2-http-16request-oi3-20260825/cells-20260825-150115-968569.csv`
  ran three unpaced 16-request OI3 cells; all passed `16/16`, `errors=0`,
  cleanup `20/0`, and manifest `failureCount=0`. The matched Direct/HEV/OI3
  run
  `evidence/s175-e2-http-16request-matched-20260825/cells-20260825-150431-029771.csv`
  ran three repeats of all three arms; all nine cells passed `16/16` with
  `failureCount=0`, HEV accumulated `socksConnect=48`, and every OI3 cell
  cleaned at `20/0`. OI3 p95 remained about 1.3--2.6 seconds while Direct/HEV
  stayed below 100 ms p95, so correctness construction strengthened again but
  EG-17 remains open for performance/resource/device-state breadth. Continue
  remaining E2 work.
- **S176 UDP multi-flow route-pinning status:** `CLOSED_FOR_BOUNDED_UDP_MULTI_FLOW_ROUTE_PINNING_SLICE`.
  The next L4 E2 sample found a separate UDP admission cliff in the S175
  artifact: OI3 four-flow UDP failed twice with ten missing replies and
  `ownerBusy=11`, while Direct, OI3 single-flow UDP and OI3 TCP passed. The
  correction adds UDP-only bounded flow-route pinning so a UDP flow whose
  primary owner is busy can be pinned to an idle owner; TCP stays on the
  S173/F050 canonical-owner deferred-admission path. Clean-ABI APK
  `f4e350c6478ce9f495afa9b1b97f174c79915592a461aeb25d7e8cdd803e1541` with OI3
  plugin
  `5012eeecb16828edca58f3dc98ddd52330a3b09b26394a3baa94b7c39604cc72`
  passed minimal UDP4 route-pinning, full Direct/OI3 IPv4 UDP/TCP S176
  (`failureCount=0`, all 12 cells valid), and OI3 HTTP16 regression
  (`16/16` twice, cleanup `20/0`). Continue remaining E2 work; do not convert
  this bounded four-owner route-pinning result into arbitrary UDP capacity or
  performance claims.
- **S177 final resource short status:** `PASS_FOR_BOUNDED_FINAL_RESOURCE_SHORT_SLICE`.
  The S170/S177 runner first hit a harness hotspot: stale hard-coded expected
  hashes, blocking VPP log reads, and transient WSL/ADB transport failures
  produced incomplete resource evidence before any valid verdict. The corrected
  runner uses current-artifact provenance by default, regular-file bounded log
  reads, and bounded `adb_read` retry. Accepted run
  `evidence/s177-e1-final-resource-short3-20260825/` completed two foreground
  four-flow UDP cycles on the S176 artifact, with `763/763` and `784/784`,
  cleanup `4/0` per cycle, fixture `2008/2008`, stable fd/thread counts,
  thermal status `0`, and manifest `failureCount=0`. Continue remaining E2/E1
  work; do not treat this short foreground resource slice as Doze, long-soak,
  or matched performance closure.
- **S178 final B1 dual-stack DNS status:** `PASS_DATAPLANE_WITH_CLEANUP_MARKER_GAPS`.
  The S178 runner first hit a POC verdict-design hotspot: `tun0` exit-code
  false positives, late cleanup-marker timing, and fixed TCP source-port reuse
  were being conflated with dataplane failure. The corrected runner checks
  captured `tun0` output, waits a bounded native settle window, tails regular
  log files for cleanup markers, and uses a dynamic default source-port base.
  Accepted run
  `evidence/s178-b1-final-dualstack-dns-20260825/` completed six current-
  artifact IPv4/IPv6 UDP/TCP DNS cells with valid 61-byte DNS responses,
  native direct/broker/TUN-output markers, `appValidCount=6`,
  `nativeValidCount=6`, zero post-run `vpp`/`tun0` residue, and
  `failureCount=0`. Continue B1/B2/E work; do not treat the three TCP
  cleanup-marker gaps as a DNS dataplane failure, and do not treat S178 as
  large-response fallback, lifecycle, soak, or performance closure.
- **S179 final controlled B2 failure-semantics status:** `PASS`.
  The current AppA B1 helper does not implement a UDP-to-TCP resolver fallback
  state machine, so forced large-response DNS fallback remains a design/test
  gap rather than a completed B1 claim. The next executable bounded slice was
  the controlled B2 negative contract. Accepted run
  `evidence/s179-b2-final-controlled-failure-20260825/` passed refused,
  no-reply, and policy-drop on the current final VPN APK with native
  `PASS_EXPECTED_FAILURE`, `verifierRc=0`, `failureCount=0`, and zero post-run
  `vpp`/`tun0` residue. Continue full B2 with real external/default-route
  AppA allow/drop, refusal/no-reply, bind/protect and infrastructure-failure
  cells; do not treat S179 as complete B2 closure.
- **S180 B1 DNS fallback status:** `PASS`.
  S180 corrects the B1 fallback POC design: independent UDP and TCP requests
  are not valid fallback evidence. AppA now exposes
  `b1FallbackTcpOnTruncated`, and the runner starts a WSL2/LAN DNS fixture
  that returns UDP `TC=1` and TCP full response for the same query ID.
  Accepted run `evidence/s180-b1-dns-fallback-20260825/` /
  `20260825-173925-730529` recorded AppA
  `fallback_attempted=true`, `fallback_reason=udp_tc`,
  `return_outcome=dns_tcp_fallback_response_received`, fixture UDP/TCP
  query-id `1234`, native `brokerSuccess=2`, cleanup `1/0`, zero post-run
  `vpp`/`tun0`, and `failureCount=0`. Continue public/IPv6 fallback and
  broader B2/E work; do not treat S180 as public resolver, IPv6 fallback,
  arbitrary large DNS, lifecycle, soak, or performance closure.
- **S181 B2 full-device transport fixture status:** `PASS`.
  S181 corrects the B2 real-transport POC design: an unbound WSL2/LAN TCP port
  behind Android VPN/OI3 is not a stable native real-refusal fixture. The valid
  cell is a post-allow TCP timeout after the app-facing proxy handshake.
  Accepted run
  `evidence/s181-b2-full-device-transport-explore-20260825/` /
  `20260825-183033-563849` passed positive UDP DNS, real UDP no-reply
  (`PASS_EXPECTED_REAL_NO_REPLY` / `EXPECTED_REAL_NO_REPLY`), and
  `closed-tcp-timeout`
  (`PASS_EXPECTED_AMBIENT_TIMEOUT` / `EXPECTED_TIMEOUT`) with
  `pass_count=3`, `failure_count=0`, no design gaps, and zero post-run
  `vpp`/`tun0`. S184 later superseded the old “continue all B2 cells together”
  posture with a bounded dedicated reset slice, which is now closed. Do not
  treat S181 as policy-drop, bind/protect, public-Internet, or production
  timeout evidence.
- **S182 B2 representative policy-drop status:** `PASS`.
  S182 corrects the real policy-drop POC seam: Android
  `addDisallowedApplication()` is not valid evidence because it routes AppA
  outside the VPN, and a pre-owner policy drop has no owner cleanup generation.
  The selected seam is OI3 multi dispatcher target-IP drop via
  `blockIp4Dst` -> `SAKAMOTO_OI3_POLICY_DROP_IP4`. Accepted run
  `evidence/s182-b2-real-policy-drop-20260825/` /
  `20260825-190147-303631` passed positive UDP DNS and
  `policy-drop-udp-dns` with `pass_count=2`, `failure_count=0`, no design
  gaps, and zero post-run `vpp`/`tun0`.  Native logged
  `stage=pre-owner ... no-transport=1 broker=0 socket=0`; the fixture observer
  on `53544` recorded no packet. S184 later isolated and closed a separate
  real-RST propagation hotspot; per-App UID drop remains closed by S183.
  Do not treat S182 as bind/protect failure,
  infrastructure failure, public-Internet, or production timeout evidence.
- **S183 B2 representative AppA UID-drop status:** `PASS`.
  S183 corrects the UID-drop POC seam for OI3 multi: the native gate was
  present, but the first Android owner lookup returns the async contract's
  `uid=-1` sentinel and cannot be treated as terminal.  The fix reuses the
  native TUN gate for `vpp-oi3-multi + blockOwnerUid>=0` and adds a bounded
  completion/cache barrier before deciding UID policy. Accepted run
  `evidence/s183-b2-real-uid-drop-20260825/` /
  `20260825-192207-202830` passed positive UDP DNS and `uid-drop-udp-dns` with
  `pass_count=2`, `failure_count=0`, no design gaps, and zero post-run
  `vpp`/`tun0`.  The UID contract recorded
  `MISS_SUBMITTED -> COMPLETION_ACCEPTED uid=12630 -> CACHE_HIT uid=12630`;
  native logged `gate drop ... ownerUid=12630 ... lookup-attempts=2`; the
  fixture observer on `53545` recorded no packet. S184 later isolated and
  closed a separate real-RST propagation hotspot. Do not treat S183 as
  VPP-internal UID policy, production
  nonblocking design, complete UID lifecycle/capacity, bind/protect failure,
  infrastructure failure, public-Internet, or production timeout evidence.
- **S184 B2 real LAN TCP RST status:** `CLOSED_FOR_BOUNDED_REAL_RST_SLICE`.
  S184 replaced S181's unbound-port timeout with a WSL2/LAN listener that
  accepts AppA's TCP connection and closes with `SO_LINGER(1, 0)`.  Accepted
  run `evidence/s184-b2-real-rst-20260825/` /
  `20260825-193618-437793` passed the positive UDP DNS control and proved the
  reset fixture was reached (`tcp_rst_connection` and `tcp_rst_sent`), but the
  owner initially published no error. The bounded correction rerun
  `evidence/s184-b2-real-rst-owner-event-20260825/` /
  `20260825-203915-342533` then published exactly one owner-local
  `READ_ERROR errno=104`, with `transport-failures=1`, `reset-observed=1`, no
  infrastructure failure, and exact settlement. That rerun isolated the
  downstream seam: owner-context `tcp_abort_ctx()` silently purged the PCB.
  The narrow `tcp_send_reset_ctx()` correction maps only exact owner-observed
  `ECONNRESET` to one owner-local downstream `RST|ACK`. Accepted closure run
  `evidence/s184-b2-real-rst-downstream-reset-20260825/` /
  `20260825-210129-290257` records one upstream reset, one rewritten downstream
  reset, AppA `tcp_payload_sent/dns_response_reset`,
  `PASS_EXPECTED_REAL_RESET`, one transport failure, zero infrastructure
  failure, `buffers=7/7 residue=0`, and zero VPP/tun0 residue. The old wrapper
  returned `1` only because its summarizer counted the same event in both a
  combined log and its embedded source; the parser is corrected without a
  second device run. This is not a UID-drop regression, policy drop,
  bind/protect failure, or infrastructure failure. Pre-connect refusal,
  public-Internet behavior, arbitrary teardown mapping, and production timeout
  constants remain non-claims unless registered later.
- **S185 B2 infrastructure-failure status:** `PASS`.
  S185 closes the bounded bind/protect/broker failure-separation slice on the
  same full-device AppA -> VpnService -> OI3 multi path.  The hotspot was the
  oracle: bind failure, protect failure, and broker unavailable cannot share a
  single “broker failed” counter.  The corrected contract requires exact
  broker result and phase accounting: bind failure is `BIND_FAILURE` with
  bind/protect `1/0`, protect failure is `PROTECT_FAILURE` with `1/1`, and
  broker unavailable is `BROKER_UNAVAILABLE` with `0/0`. Accepted run
  `evidence/s185-b2-infrastructure-failures-20260825-run1/` /
  `20260825-213903-524622` passed positive UDP DNS plus
  `bind-failure-udp-dns`, `protect-failure-udp-dns`, and
  `broker-unavailable-udp-dns` with `pass_count=4`, `failure_count=0`, no
  design gaps, and zero post-run `vpp`/`tun0` residue.  All failure cells
  stopped before fixture query, TUN output, Direct send, policy drop, and
  transport failure.  Do not treat S185 as post-connect transport failure,
  pre-connect `ECONNREFUSED`, public-Internet behavior, production capacity,
  or production timeout evidence.
- **S152 residual A2 UID lifecycle status:** `INCONCLUSIVE_DESIGN_GAP`.
  S152 cannot proceed on the current A2-1 design.  The accepted diagnostic
  evidence directory
  `evidence/s152-a2-1-two-app-20260825-dualplugin-rerun1/` had valid
  artifact/device/dual-UID setup and cleanup, but only 5/8 registered tuples
  joined to native resolver evidence.  The failing TCP tuples used public
  `1.1.1.1` / Cloudflare IPv6 endpoints and failed in the App socket layer
  (`Address not available` or `ECONNREFUSED`) before producing resolver rows.
  Native/Java UID contract rows were also labelled `A2-4/startup` because the
  runner did not pass an A2-1 stage contract.  Revise S152 around controlled
  WSL2/LAN fixtures and stage-specific UID contract logging before any rerun.
- **S156 A2-1 fixture/stage repair status:** `PASS_BASE_MATRIX`.
  S155 performed the S152 controlled-fixture/stage correction and closed the old
  public-endpoint/startup-stage oracle defect.  S156 then closed successor
  `VPN-F061`: run5 `evidence/s156-a2-1-correlation-20260825-run5/` passed all
  eight registered two-App IPv4/IPv6 TCP/UDP tuples with exact runtime,
  resolver, and UID-contract joins.  A2-2/A2-4/A2-5 may continue only with the
  S156 guardrails: resolver request correlation, APK artifact gates, TCP
  dynamic source ports, TCP repeat `4`, and decisive repeat selection.
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
S146/S147 temporarily blocked and then unblocked B2.  S150 diagnosed the real
underlay epoch hotspot; S151 closes C1 for the selected Pixel artifact under
bounded explicit VPN-session restart.  S152 diagnosed the C2 normal-stop
classification gap; S153 corrected and reran that sub-gate with
`PASS_EXPECTED_STOP`.  Controlled S149 C2 evidence and the S153 normal-stop
cell remain regression inputs, while S157 supplies the real same-session
 re-arm/fault evidence. S158's historical topology interruption was resolved by
 the two-owner route; S161 closed the timed D3 recovery gate. The chain was
 paused at the S164 HEV external-ingress design boundary. S165 implemented and
 regressed the external-only wildcard demux correction against the controlled
 WSL2 endpoint (`HTTP/1.0 200 OK`, one cycle), so the HEV arm is reopened.
 S163's registered comparative performance/device-state gates and final audit
 remain open.

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
- a valid full-route TCP flow settles after the first short application segment
  or loses subsequent stream bytes (the SAKAMOTO-142/S143 condition) and the
  owner-local ACK/timer correction cannot restore progress;
- a full-TUN negative cell meets its expected native refusal/timeout/drop
  invariant but the durable cleanup or app outcome contract reports it as an
  ordinary failure/ambiguous success (the S146 condition);
- a real Android underlay handle is lost/replaced while the VPN remains alive,
  but no callback-driven owner epoch is published and old-flow/stale-event
  invalidation cannot be demonstrated (the resolved S150/VPN-F033 condition);
- a positive real OI3 flow closes the detached VPN TUN and a subsequent
  registered flow in the same session cannot find a `TRANSPORT_VPN` Network
  (the S156 one-flow-per-VPN-session condition); S157 corrected this condition
  for the registered positive-flow re-arm contract, so future interruption
  requires a regression of that correction rather than the historical finding;
- the registered D1 question requires at least two final-topology owners but
  the selected artifact exposes only one global owner/context/queue/TUN and no
 tuple-to-shard dispatch (S158); continuing D1/D2/D3 would exercise a
 different claim or mislabel a single-owner ceiling as multi-owner evidence;
- the final-topology multi-owner teardown reproduces the same owner-context
  heap corruption/SIGABRT four valid times, including after two local
  lifecycle corrections (S168/VPN-F042); pause the pressure and dependent E2
  branches until an explicit redesign or disposition is approved;
- a registered `expectEcho=true` cell asks for more simultaneous UDP flows than
  the selected bounded topology admits; historical instance VPN-F046 is closed
  for four concurrent UDP canonical flows by the four-owner correction, but a
  higher-flow or different-protocol recurrence must be treated as a new
  capacity design mismatch rather than silently folded into E2;
- a registered concurrent UDP cell fits the selected owner count but still
  reproduces primary-owner collision after S176 route pinning; treat that as a
  new route-table/admission design defect rather than reopening TCP F050;
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
