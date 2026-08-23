# Android VPN POC Finding Ledger

Date: 2026-08-23  
Plane owner: SAKAMOTO-135

This is the single problem-centric engineering ledger for the Android VPN
Direct Egress evolution.  It consolidates duplicate symptoms by root cause
from:

- [S132_PRE_OWNER_INLINE_FINDINGS.md](S132_PRE_OWNER_INLINE_FINDINGS.md)
- [S133_EXTERNAL_DRIVER_FINDINGS.md](S133_EXTERNAL_DRIVER_FINDINGS.md)
- [S134_OWNER_INLINE_FINDINGS.md](S134_OWNER_INLINE_FINDINGS.md)

It is not an open-work backlog.  `POC Correction` records how a throwaway proof
was made valid; formal implementation must independently implement and regress
the invariant.  Experimental work still needed is selected in the Evidence Gap
Map rather than encoded as TODOs here.

## Status vocabulary

- `CLOSED` -- the root cause is understood and the corrected bounded evidence
  passed.  Production implementation is not implied.
- `OPEN_RISK` -- observed evidence remains unexplained or the formal engineering
  envelope still lacks a bounded answer.
- `SUPERSEDED` -- the affected experimental topology is no longer the selected
  baseline; its transferable invariant remains recorded.
- `INCONCLUSIVE` -- a registered investigation did not satisfy its decision
  gates.  This is neither PASS nor FAIL.

## Index

| Finding | Name | Status | Primary environment |
| --- | --- | --- | --- |
| VPN-F001 | Historical child-path allocator/teardown anomaly | `SUPERSEDED` | Host |
| VPN-F002 | Explicit mutable-state context required | `CLOSED` | Host |
| VPN-F003 | Bounded event-driven owner scheduling required | `CLOSED` | Host + Pixel |
| VPN-F004 | Synchronous Android platform brokerage blocks FlowOwner | `CLOSED` | Pixel |
| VPN-F005 | Bidirectional broker channel confused request/completion ownership | `CLOSED` | Host + Pixel |
| VPN-F006 | Broker stop/disconnect lifecycle was non-monotonic | `CLOSED` | Host + Pixel |
| VPN-F007 | Terminal broker accounting ignored admitted inflight work | `CLOSED` | Host + Pixel |
| VPN-F008 | Android broker artifact lacked required manifest authority | `CLOSED` | Pixel |
| VPN-F009 | Nested packet lifetime exceeded one pbuf credit | `CLOSED` | Host |
| VPN-F010 | Foreign-thread HEV access violated owner affinity | `CLOSED` | Pixel + Host model |
| VPN-F011 | Packet fixtures could pass invalid protocol arithmetic | `CLOSED` | Pixel |
| VPN-F012 | Hidden fixture/pool ceilings mimicked target capacity | `OPEN_RISK` | Pixel |
| VPN-F013 | Queue pressure lacks a proven overload contract | `OPEN_RISK` | Pixel |
| VPN-F014 | Shared diagnostic counters raced across owners | `CLOSED` | Pixel |
| VPN-F015 | Low-bit tuple hash biased real Android flow distribution | `OPEN_RISK` | Pixel |
| VPN-F016 | Handoff rejection double-freed a VPP buffer | `CLOSED` | Pixel |
| VPN-F017 | Offered-load and diagnostics contaminated measurements | `CLOSED` | Pixel |
| VPN-F018 | Two-copy investment decision remains unproven | `INCONCLUSIVE` | Pixel |
| VPN-F019 | TUN connector callbacks were uninitialized | `CLOSED` | Host + Pixel |
| VPN-F020 | Listener normalization destroyed original-destination semantics | `CLOSED` | Host + Pixel |
| VPN-F021 | Endpoint readiness made failure classification nondeterministic | `CLOSED` | Host + Pixel |
| VPN-F022 | A diagnostic TUN reader consumed datapath ingress | `CLOSED` | Pixel |
| VPN-F023 | Completion watcher teardown closed inherited broker infrastructure | `CLOSED` | Host + Pixel |
| VPN-F024 | Stop raced the first owner execution token | `CLOSED` | Host + Pixel |
| VPN-F025 | Screen-off TCP latency remained near four seconds | `OPEN_RISK` | Pixel |
| VPN-F026 | UID attribution was not stable across a flow | `OPEN_RISK` | Pixel |

## Findings

### VPN-F001 -- Historical child-path allocator/teardown anomaly

- **First observation:** Linux POC-C3 completed a curl/TUN/VPP/HEV/SOCKS HTTP
  flow, then HEV emitted `free(): invalid size`.
- **Evidence:** S132 F132-01; `ANDROID_VPN_EXPERIMENT_PLAN.md` and the C3 section
  of `ANDROID_VPN_EXPERIMENT_LOG.md`.
- **Environment:** Host Linux/Docker; later Android lifecycle probes did not
  reproduce the signal.
- **Root-cause confidence:** LOW; the exact allocator owner was not isolated.
- **POC Correction:** Split Android packaging/lifecycle validation from full
  datapath validation and retain stderr/process-residue evidence.
- **Post-correction evidence:** Later Android lifecycle probes were clean, but
  no root-cause-specific rerun exists.
- **Supported claim:** The early full Host datapath was viable but its teardown
  evidence was not clean.
- **Non-claim:** The allocator defect is fixed or the child/SOCKS topology is
  production-safe.
- **Formal invariant:** Packet success never overrides allocator/fd/task/residue
  failure; each Flow Stack generation has exact ownership and teardown ledgers.
- **Status:** `SUPERSEDED`; the child/SOCKS topology is outside the selected
  owner-inline baseline.

### VPN-F002 -- Explicit mutable-state context required

- **First observation:** S114 mechanical TLS surgery failed at TCP listen,
  active and TIME_WAIT PCB lists and their static/runtime initialization.
- **Evidence:** S132 F132-07; authoritative S114 and S118 Plane comments with
  pinned-source, patch, raw-log and resource-ledger hashes.
- **Environment:** Host, exact pinned HEV/lwIP.
- **Root-cause confidence:** HIGH for the rejected TLS-only approach.
- **POC Correction:** S118 introduced explicit context-addressed ownership for
  PCB lists, allocators/pools, config, DNS/session/task/stop, netif/IP/timers
  and credits.
- **Post-correction evidence:** Same-process, same-link-image protected
  IPv4/IPv6 TCP/UDP, peer-continuity/fault, repeat lifecycle and zero-residue
  Host cells passed.
- **Supported claim:** Independent mutable HEV/lwIP owner contexts are feasible
  in the pinned source.
- **Non-claim:** Android TUN, production state layout, shard count, or execution
  topology.
- **Formal invariant:** Every shard owns an explicit mutable transport domain;
  ordinary isolation uses neither calling-thread TLS guesses, global core lock,
  duplicate image, nor external process.
- **Status:** `CLOSED`.

### VPN-F003 -- Bounded event-driven owner scheduling required

- **First observation:** S117/S119 `hev_task_system_run()` held the caller until
  task-system return; S120's bounded step still unconditionally requeued and
  did not schedule from `next_timeout_ms`; OI-1 rearm initially retained a stale
  cancel byte and missed an FD wake.
- **Evidence:** S132 F132-06, S133 F133-01, S134 F134-01; S117 Plane comment and
  S119/S120/S126 journals.
- **Environment:** Host and Pixel 6a arm64.
- **Root-cause confidence:** HIGH.
- **POC Correction:** Introduce bounded `drive` results, return `WAITING`, use a
  wait-only helper for fd/timer readiness, drain cancel state, and reject
  stale/duplicate wakes.
- **Post-correction evidence:** OI-1 Host and Pixel timer-only, FD-only, packet,
  mixed, fairness and stale-wake cells passed with owner-thread callbacks and
  zero residue.
- **Supported claim:** Owner-inline scheduling is viable without HEV takeover,
  busy polling, or mutable callbacks on a helper.
- **Non-claim:** The temporary S119/S120 APIs are production interfaces or that
  paired-thread is selected.
- **Formal invariant:** `drive(shard, wake, quantum, wall_deadline)` is bounded;
  `WAITING` only rearms from matching packet/fd/timer/control wakes and cannot
  starve the VPP graph.
- **Status:** `CLOSED`.

### VPN-F004 -- Synchronous Android platform brokerage blocks FlowOwner

- **First observation:** The early Pixel protect POC sent a descriptor duplicate
  to the app and synchronously waited for `VpnService.protect()` before
  bind/connect.
- **Evidence:** S132 F132-02; SAKAMOTO-3 result and historical
  `android/vpn-lite/native/vpn_fd_probe.c` path.
- **Environment:** Pixel 6a.
- **Root-cause confidence:** HIGH.
- **POC Correction:** OI-2 made owner submission nonblocking and moved Android
  bind/protect to a separate Java/native broker.
- **Post-correction evidence:** Host and Pixel family/failure/delay/queue/
  tripwire cells passed while the owner sentinel progressed.
- **Supported claim:** Android-only socket preparation can occur asynchronously
  before owner connect/send.
- **Non-claim:** The old one-request-at-a-time protocol can run on FlowOwner or
  proves broker capacity.
- **Formal invariant:** FlowOwner never waits in JNI, `poll`, `recv`, bind/
  protect, connect, or send while Android platform work is pending.
- **Status:** `CLOSED`.

### VPN-F005 -- Bidirectional broker channel confused request/completion ownership

- **First observation:** The first OI-2 broker read its own completion as a new
  request and stranded the final family/type operation.
- **Evidence:** S134 F134-02 and S127 journal.
- **Environment:** Host probe; corrected contract also ran on Pixel.
- **Root-cause confidence:** HIGH.
- **POC Correction:** Use separate bounded request and completion channels.
- **Post-correction evidence:** Host, VPP-worker and Pixel matrices completed
  all accepted work with exact duplicate closes.
- **Supported claim:** Directional asynchronous brokerage is viable.
- **Non-claim:** A single bidirectional endpoint is safe because messages have
  different structs or timing.
- **Formal invariant:** Request and completion directions have distinct channel
  ownership and versioned message roles.
- **Status:** `CLOSED`.

### VPN-F006 -- Broker stop/disconnect lifecycle was non-monotonic

- **First observation:** `stop_broker()` could precede publication of
  `broker_running`, after which the thread cleared stop intent and polled
  forever; child disconnect after stop could also cause repeated receive
  errors.
- **Evidence:** S134 F134-03/F134-06 and S127 journal.
- **Environment:** Host and Pixel.
- **Root-cause confidence:** HIGH.
- **POC Correction:** Independent atomic stop intent; treat post-stop channel
  disconnect as terminal and log it once.
- **Post-correction evidence:** Delayed-stop and final Pixel service-stop cells
  terminate with no VPP process or buffer residue.
- **Supported claim:** The bounded broker lifecycle can preserve late-
  completion rejection without spinning.
- **Non-claim:** Production Android service/process death, reboot, or restart
  policy.
- **Formal invariant:** Stop intent is monotonic/publish-before-use; channel
  disconnect terminates that broker generation and join has a deadline.
- **Status:** `CLOSED`.

### VPN-F007 -- Terminal broker accounting ignored admitted inflight work

- **First observation:** In OI-2 queue-full, `completed + rejected` reached the
  planned count while one accepted request remained inflight; its completion
  was then falsely stale.
- **Evidence:** S134 F134-04 and S127 VPP integration gate.
- **Environment:** Host; corrected queue cell repeated on Pixel.
- **Root-cause confidence:** HIGH.
- **POC Correction:** Require `inflight == 0` before terminal state.
- **Post-correction evidence:** Accepted and rejected sockets settle exactly
  once, with clean queue/full and delayed-stop cells.
- **Supported claim:** Bounded rejection can coexist with correct admitted work.
- **Non-claim:** Production queue size or overload policy.
- **Formal invariant:** Terminal generation state requires exactly one outcome
  for every admitted/rejected descriptor and zero admitted work inflight.
- **Status:** `CLOSED`.

### VPN-F008 -- Android broker artifact lacked required manifest authority

- **First observation:** Pixel OI-2 raised `SecurityException` from
  `getActiveNetwork()` because `ACCESS_NETWORK_STATE` was absent.
- **Evidence:** S134 F134-05 and S127 Android gate.
- **Environment:** Pixel 6a Android 16.
- **Root-cause confidence:** HIGH.
- **POC Correction:** Declare permission and rebuild the exact APK.
- **Post-correction evidence:** IPv4/IPv6 TCP/UDP Java `bindSocket` then
  `VpnService.protect` cells passed.
- **Supported claim:** The failure was packaging authority, not owner/broker
  architecture.
- **Non-claim:** Other Android/OEM permissions or release policy.
- **Formal invariant:** Manifest/runtime authority and packaged member hashes
  are preflight gates before network failures are interpreted.
- **Status:** `CLOSED`.

### VPN-F009 -- Nested packet lifetime exceeded one pbuf credit

- **First observation:** S121 synchronous echo held ingress while allocating
  output, causing `FLOW_STACK_OWNER_PBUF_LIMIT` with credit one.
- **Evidence:** S133 F133-02 and S121 raw credit-1 failure/credit-2 rerun.
- **Environment:** Host real VPP-worker packet seam.
- **Root-cause confidence:** HIGH.
- **POC Correction:** Use a bounded test credit of two.
- **Post-correction evidence:** One 33-byte UDP echo closed ingress/egress
  buffers and copy bytes exactly.
- **Supported claim:** Explicit bounded credits can support the copy-based seam.
- **Non-claim:** Production credit size or pressure behavior.
- **Formal invariant:** Credit accounting covers simultaneously held ingress,
  protocol and output objects and has exact failure settlement.
- **Status:** `CLOSED`.

### VPN-F010 -- Foreign-thread HEV access violated owner affinity

- **First observation:** Pixel S122 crashed after `hev_task_self()` was called
  from a foreign VPP worker at netif output.
- **Evidence:** S133 F133-03 plus S122 journal/Plane comment; OI-1/OI-4 later
  provide foreign/wrong-owner tripwires.
- **Environment:** Pixel first observation; Host/model/Pixel corroboration.
- **Root-cause confidence:** HIGH.
- **POC Correction:** Remove foreign current-task/TLS lookup, carry explicit
  context, assert owner identity, and reject wrong-owner events without mutation.
- **Post-correction evidence:** S122 final UDP/TCP matrices and OI-1/OI-4
  affinity/tripwire cells passed.
- **Supported claim:** Packet callbacks are safe when all mutable HEV/lwIP work
  remains on the canonical owner.
- **Non-claim:** Arbitrary cross-thread HEV APIs or process-global transport
  authority.
- **Formal invariant:** Only the canonical owner executes mutable stack
  callbacks; foreign submit/output/completion/callback attempts are rejected
  before mutation.
- **Status:** `CLOSED`.

### VPN-F011 -- Packet fixtures could pass invalid protocol arithmetic

- **First observation:** S122/S123 exposed wrong UDP port byte order, TCP
  sequence/window advancement, missing MSS/count enforcement, and an integer-
  promotion-sensitive checksum replacement.
- **Evidence:** S133 F133-04, S122 journal/Plane comment, S123 journal.
- **Environment:** Pixel 6a.
- **Root-cause confidence:** HIGH.
- **POC Correction:** Correct byte order/checksum, advance both TCP sequence
  spaces, advertise MSS 1460, and invalidate any count mismatch.
- **Post-correction evidence:** S122 32/32 final cells and S123 288/288 formal
  measurement files passed.
- **Supported claim:** Corrected fixtures can measure the registered packet seam.
- **Non-claim:** General segmentation/chained-pbuf behavior or metrics from
  discarded cells.
- **Formal invariant:** Protocol, checksum, handshake, packet-count and byte
  ledgers pass for the exact artifact before any performance sample is admitted.
- **Status:** `CLOSED`.

### VPN-F012 -- Hidden fixture/pool ceilings mimicked target capacity

- **First observation:** The 50-cycle lifecycle fixture stopped at a mock
  32-accept ceiling; S124 later failed UDP 32-flow/TCP four-flow at eight
  session slots and two TCP PCBs per owner.
- **Evidence:** S132 F132-03 and S133 F133-05; SAKAMOTO-4 and S124 memo/journal.
- **Environment:** Pixel 6a.
- **Root-cause confidence:** HIGH for both observed ceilings.
- **POC Correction:** Remove the mock accept limit; expand explicitly test-only
  owner pools and rerun from scratch.
- **Post-correction evidence:** 50 lifecycle cycles, UDP 32/32, and TCP 8/8 plus
  32/32 passed in their bounded fixtures.
- **Supported claim:** Those failures were fixture/resource configuration, not
  evidence against VPP ownership or sharding.
- **Non-claim:** A production pool size, capacity, soak, or absence of a cliff.
- **Formal invariant:** Every fixture and target pool has named limits/high-water
  counters; exhaustion names its resource and cannot masquerade as routing or
  architecture failure.
- **Status:** `OPEN_RISK` because the formal capacity envelope is unmeasured.

### VPN-F013 -- Queue pressure lacks a proven overload contract

- **First observation:** S124 background traffic produced 37 handoff congestion
  drops while controlled app-only cells produced zero.
- **Evidence:** S133 F133-06 and S124 memo.
- **Environment:** Pixel 6a.
- **Root-cause confidence:** MEDIUM; pressure is observed but arrival mix and
  intended overload policy were not isolated.
- **POC Correction:** Preserve the pressure signal and isolate correctness cells;
  no overload correction was claimed.
- **Post-correction evidence:** Controlled cells are clean; overload remains
  deliberately unclosed.
- **Supported claim:** Pressure can reach the owner handoff boundary.
- **Non-claim:** Safe overload, capacity, or an architecture reversal.
- **Formal invariant:** Owner queues have bounded capacity, explicit admission/
  overload outcomes, occupancy/drop counters, and exact ownership settlement.
- **Status:** `OPEN_RISK`.

### VPN-F014 -- Shared diagnostic counters raced across owners

- **First observation:** S125 two-worker UDP output bytes diverged because
  process-wide u64 counters were updated concurrently.
- **Evidence:** S133 F133-07 and S125 journal.
- **Environment:** Pixel 6a.
- **Root-cause confidence:** HIGH.
- **POC Correction:** Make test aggregation atomic.
- **Post-correction evidence:** Both owners ran and pbuf/write byte ledgers
  closed exactly.
- **Supported claim:** The mismatch was diagnostic state, not lost output bytes.
- **Non-claim:** A production telemetry layout or global mutable stack state.
- **Formal invariant:** Mutable accounting is owner-local; cross-owner
  aggregation is race-safe and never controls datapath behavior.
- **Status:** `CLOSED`.

### VPN-F015 -- Low-bit tuple hash biased real Android flow distribution

- **First observation:** S125 Android even ephemeral ports caused the original
  FNV low bit to map all TCP flows to one owner.
- **Evidence:** S133 F133-08 and S125 journal/memo.
- **Environment:** Pixel 6a.
- **Root-cause confidence:** HIGH for the fixture distribution.
- **POC Correction:** Add a test-only final avalanche so both owners were
  exercised.
- **Post-correction evidence:** TCP 8-flow short check split owner packets and
  closed output/copy ledgers.
- **Supported claim:** Independent owners work when tuples are actually
  distributed.
- **Non-claim:** The avalanche, shard count, or balance is a production contract.
- **Formal invariant:** Canonical hash quality is evaluated against real Android
  tuple populations; bias is distinguished from affinity/capacity failure.
- **Status:** `OPEN_RISK`.

### VPN-F016 -- Handoff rejection double-freed a VPP buffer

- **First observation:** In S125 control pressure,
  `vlib_buffer_enqueue_to_thread(..., drop_on_congestion=1)` had already freed
  a rejected buffer; the plugin freed it again and VPP crashed.
- **Evidence:** S133 F133-09 and S125 raw failure/correction journal.
- **Environment:** Pixel 6a.
- **Root-cause confidence:** HIGH.
- **POC Correction:** Remove the caller-side second free and invalidate the
  failed measurements.
- **Post-correction evidence:** Repaired control smokes remained crash-free.
- **Supported claim:** The crash was an exactly-once ownership violation.
- **Non-claim:** All overload/drop paths are audited or queue pressure solved.
- **Formal invariant:** Each enqueue outcome names exactly one buffer owner and
  one terminal settlement; helper ownership transfer is part of the C contract.
- **Status:** `CLOSED`.

### VPN-F017 -- Offered-load and diagnostics contaminated measurements

- **First observation:** S125 slept after whole 32-packet batches, creating
  microbursts despite a low average rate; full `show s124-vpn-tun` invoked stack
  diagnostics and sometimes delayed 20--30 seconds.
- **Evidence:** S133 F133-10 and S125 journal/memo.
- **Environment:** Pixel 6a.
- **Root-cause confidence:** HIGH.
- **POC Correction:** Inter-packet pacing, invalid-cell exclusion, and a
  read-only lightweight snapshot.
- **Post-correction evidence:** Repaired control smokes had zero enqueue drops;
  the lightweight snapshot removed one known observer effect.
- **Supported claim:** The identified harness defects are controlled.
- **Non-claim:** The registered instrumentation gate or final performance
  decision passed.
- **Formal invariant:** Offered-load shape and observation cost are explicit;
  diagnostics cannot mutate/lock the measured datapath or redefine the cell.
- **Status:** `CLOSED`.

### VPN-F018 -- Two-copy investment decision remains unproven

- **First observation:** S122--S125 measured the two explicit boundary copies,
  but matched controls, instrumentation deltas, thermal recovery and the full
  registered matrix were not all valid or completed.
- **Evidence:** S133 F133-11; S122 Plane continuation comment; S125 decision memo.
- **Environment:** Pixel 6a.
- **Root-cause confidence:** Not applicable; evidence-decision state.
- **POC Correction:** Correct known instrumentation defects, preserve invalid
  cells, and pause remaining work without changing thresholds.
- **Post-correction evidence:** Representative copy shares remain small and
  reproducible enough for direction, but not for a formal investment verdict.
- **Supported claim:** Keep the copy-based architecture as the feasibility
  baseline; copy is not currently the first optimization target.
- **Non-claim:** `DEFER`, `TARGETED`, `MUST_INVEST`, zero-copy, or lwIP memory-
  model decision.
- **Formal invariant:** Copy/ownership redesign requires all registered
  correctness, control, resource, instrumentation and profile gates on matched
  artifacts.
- **Status:** `INCONCLUSIVE` and paused.

### VPN-F019 -- TUN connector callbacks were uninitialized

- **First observation:** OI-3 broker submission succeeded but no owner socket
  could be created because TUN TCP/UDP callback structs were unset.
- **Evidence:** S134 F134-07 and S128 journal.
- **Environment:** Host/Pixel integration seam.
- **Root-cause confidence:** HIGH.
- **POC Correction:** Initialize connector capability/callback tables.
- **Post-correction evidence:** Host and controlled Pixel matrix show owner-local
  socket creation, Direct send/receive and cleanup.
- **Supported claim:** The omission did not contradict the module boundary.
- **Non-claim:** Broker success alone proves Direct Egress.
- **Formal invariant:** A shard admits no transport until protocol capabilities
  and callbacks are initialized and artifact-gated.
- **Status:** `CLOSED`.

### VPN-F020 -- Listener normalization destroyed original-destination semantics

- **First observation:** OI-3 conflated the raw TUN destination with the
  canonical HEV listener address.
- **Evidence:** S134 F134-08, S128 Host real-TUN and controlled Pixel raw ledgers.
- **Environment:** Host and Pixel.
- **Root-cause confidence:** HIGH.
- **POC Correction:** Retain immutable original destination for connect, normalize
  only the HEV packet copy, and rewrite owner output to the original endpoint.
- **Post-correction evidence:** Host and Pixel IPv4/IPv6 TCP/UDP paths close raw
  provenance/byte ledgers with zero residue.
- **Supported claim:** Owner-inline Direct Egress can preserve original
  destination without SOCKS or a second packet path.
- **Non-claim:** External/default-route, NAT, or arbitrary redirection safety.
- **Formal invariant:** Listener address, underlay target, original destination
  and return rewrite are distinct typed values; normalization is non-destructive.
- **Status:** `CLOSED`.

### VPN-F021 -- Endpoint readiness made failure classification nondeterministic

- **First observation:** OI-3 owner sometimes ran before its controlled endpoint
  fixture was ready, changing expected timeout/refusal into a race diagnostic.
- **Evidence:** S134 F134-09 and S128 journal.
- **Environment:** Host and controlled Pixel.
- **Root-cause confidence:** HIGH.
- **POC Correction:** Explicit endpoint-ready latch and bounded 512-step ceiling.
- **Post-correction evidence:** Registered refusal/no-reply/policy-drop cells
  reach distinct outcomes with zero residue.
- **Supported claim:** Failure classes can remain distinct in bounded fixtures.
- **Non-claim:** Arbitrary external RST/`SO_ERROR` behavior or production timeout.
- **Formal invariant:** Readiness is a prerequisite; all transport waits have a
  deadline and stable transport/infrastructure/policy classification.
- **Status:** `CLOSED` for the bounded fixture.

### VPN-F022 -- A diagnostic TUN reader consumed datapath ingress

- **First observation:** A Pixel OI-3 sidecar sharing the TUN fd could race VPP
  and steal the app packet.
- **Evidence:** S134 F134-10 and S128 controlled-run record.
- **Environment:** Pixel 6a.
- **Root-cause confidence:** HIGH.
- **POC Correction:** VPP becomes the sole TUN reader and authoritative packet
  ledger; sidecar remains `observer-read=0`.
- **Post-correction evidence:** Final seven-cell Pixel matrix has raw VPP
  ingress/output evidence and clean app results.
- **Supported claim:** Packet provenance belongs to the VPP reader.
- **Non-claim:** Duplicating a TUN fd creates a safe observer.
- **Formal invariant:** Exactly one component reads each TUN generation;
  diagnostics are emitted by that owner or non-consuming metadata hooks.
- **Status:** `CLOSED`.

### VPN-F023 -- Completion watcher teardown closed inherited broker infrastructure

- **First observation:** `clib_file_del_by_index()` closes its registered fd;
  directly registering the inherited Android completion endpoint would destroy
  infrastructure at generation teardown.
- **Evidence:** S134 F134-11, explicit source correction in
  `owner_inline_oi3.c`, and S130 generation ledgers.
- **Environment:** Host and Pixel same-process generation work.
- **Root-cause confidence:** HIGH.
- **POC Correction:** Register a per-generation `dup()` as the watcher.
- **Post-correction evidence:** Pixel generations 1--5 recreate watchers while
  inherited broker fds stay stable and no completion `EPIPE` occurs.
- **Supported claim:** Broker infrastructure can outlive a Flow Stack generation.
- **Non-claim:** Generation-local readiness state can be shared or leaked.
- **Formal invariant:** Registration APIs declare descriptor ownership; a
  generation closes only its watcher duplicate.
- **Status:** `CLOSED`.

### VPN-F024 -- Stop raced the first owner execution token

- **First observation:** A stop before the initial owner token was consumed
  could otherwise allow that queued token to create context after stop intent.
- **Evidence:** S134 F134-12, source ordering comment, and S130 Host/Pixel
  generation/fault/restart ledgers.
- **Environment:** Host and controlled Pixel.
- **Root-cause confidence:** HIGH.
- **POC Correction:** Publish `finish_requested` before queueing stop and defer
  final destruction until owner token/buffer residue is reclaimed.
- **Post-correction evidence:** Every enumerated generation settles with zero
  residue and old TCP reconnect/UDP reuse zero.
- **Supported claim:** Bounded admission/quiesce ordering works in the tested
  lifecycle sequence.
- **Non-claim:** Unbounded soak, service death, or production restart policy.
- **Formal invariant:** Admission closes before quiesce; no queued start crosses
  generation, and destruction waits for all obligated tokens/buffers.
- **Status:** `CLOSED`.

### VPN-F025 -- Screen-off TCP latency remained near four seconds

- **First observation:** SAKAMOTO-7 kept app/VPP/HEV alive under 300-second
  screen-off rounds, but TCP p95/p99 stayed around 4.05/4.06 seconds.
- **Evidence:** S132 F132-04 and `POC_STATUS.md`.
- **Environment:** Pixel 6a with simulated battery unplug/Doze.
- **Root-cause confidence:** LOW; Android scheduling, service state, endpoint,
  VPP and HEV costs were not separated.
- **POC Correction:** None; retain resource GO and latency HOLD separately.
- **Post-correction evidence:** None that attributes or removes the latency.
- **Supported claim:** One bounded device-state window had stable processes and
  resources.
- **Non-claim:** Acceptable background latency, battery certification, or layer
  attribution.
- **Formal invariant:** Resource health and latency are separate gates with a
  foreground/local-path control before attribution.
- **Status:** `OPEN_RISK`.

### VPN-F026 -- UID attribution was not stable across a flow

- **First observation:** Android owner lookup returned a UID for early TCP
  packets and `-1` for later packets on the same tuple.
- **Evidence:** S132 F132-05 and `POC_STATUS.md` owner cache/UID findings.
- **Environment:** Pixel 6a.
- **Root-cause confidence:** MEDIUM; volatility is observed but Android API
  timing/cause is not isolated.
- **POC Correction:** Minimal one-active-tuple VPP cache; a short UDP burst then
  used one resolver query.
- **Post-correction evidence:** Tested VPP-internal IPv4/IPv6 TCP/UDP UID
  allow/drop and short cache cells passed.
- **Supported claim:** Sticky cached UID attribution is feasible for bounded
  flows.
- **Non-claim:** Cache size, expiry, reverse-flow semantics, concurrency,
  nonblocking miss, or epoch refresh.
- **Formal invariant:** Attribution resolves outside the owner hot path, is
  cached by canonical tuple/provenance and cannot change an existing flow's
  owner/shard key.
- **Status:** `OPEN_RISK`.

## Consolidation audit

- All 30 source findings map to one of `VPN-F001`--`VPN-F026`.
- Duplicate scheduler symptoms map to VPN-F003; synchronous broker blocking and
  channel direction confusion remain separate VPN-F004/VPN-F005 causes.
- Harness accept limits and temporary HEV pools merge into VPN-F012 because
  both are undeclared fixture/resource ceilings; queue overload and hash bias
  remain separate VPN-F013/VPN-F015 causes.
- Callback initialization and destination normalization remain separate
  VPN-F019/VPN-F020 causes even though both initially looked like “no Direct
  socket.”
- Descriptor-watcher ownership and start/stop token ordering remain separate
  VPN-F023/VPN-F024 lifecycle causes.
- Untested external/default-route, Pixel multi-owner, capacity, overload,
  lifecycle/engineering envelope and UID cells are claims for the Evidence Gap
  Map.  They are not silently converted into observed defects here.

| Source inventory | Source finding | Consolidated finding |
| --- | --- | --- |
| S132 | F132-01 | VPN-F001 |
| S132 | F132-02 | VPN-F004 |
| S132 | F132-03 | VPN-F012 |
| S132 | F132-04 | VPN-F025 |
| S132 | F132-05 | VPN-F026 |
| S132 | F132-06 | VPN-F003 |
| S132 | F132-07 | VPN-F002 |
| S133 | F133-01 | VPN-F003 |
| S133 | F133-02 | VPN-F009 |
| S133 | F133-03 | VPN-F010 |
| S133 | F133-04 | VPN-F011 |
| S133 | F133-05 | VPN-F012 |
| S133 | F133-06 | VPN-F013 |
| S133 | F133-07 | VPN-F014 |
| S133 | F133-08 | VPN-F015 |
| S133 | F133-09 | VPN-F016 |
| S133 | F133-10 | VPN-F017 |
| S133 | F133-11 | VPN-F018 |
| S134 | F134-01 | VPN-F003 |
| S134 | F134-02 | VPN-F005 |
| S134 | F134-03 | VPN-F006 |
| S134 | F134-04 | VPN-F007 |
| S134 | F134-05 | VPN-F008 |
| S134 | F134-06 | VPN-F006 |
| S134 | F134-07 | VPN-F019 |
| S134 | F134-08 | VPN-F020 |
| S134 | F134-09 | VPN-F021 |
| S134 | F134-10 | VPN-F022 |
| S134 | F134-11 | VPN-F023 |
| S134 | F134-12 | VPN-F024 |
