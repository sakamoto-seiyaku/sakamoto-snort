# Android VPN POC Finding Ledger

Date: 2026-08-26
Plane owner: SAKAMOTO-135

Finding diagnosis, delegated execution, and hotspot retry must follow
[`ANDROID_VPN_POC_EXECUTION_GUARDRAILS.md`](ANDROID_VPN_POC_EXECUTION_GUARDRAILS.md).
The runbook was derived from the recurring evidence and harness errors in this
ledger; it does not replace the finding history or Plane work items.

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
| VPN-F027 | Stale linker-prefixed plugin alias broke APK provenance | `CLOSED` | Host packaging + Pixel |
| VPN-F028 | Android 16 per-UID Local Network Protection hid LAN replies | `CLOSED_FOR_POC` | Pixel |
| VPN-F029 | UID-scoped active network selected the VPN as connector underlay | `CLOSED_FOR_POC` | Pixel Android 16 |
| VPN-F030 | OI3 settled a multi-write TCP stream after the first short segment | `CLOSED_FOR_POC` | Pixel Android 16 |
| VPN-F031 | OI3 short TCP segment lacked owner ACK/timer progress | `CLOSED_FOR_POC` | Pixel Android 16 |
| VPN-F032 | OI3 TUN negative cells are forced to a positive-path cleanup failure | `CLOSED_FOR_POC` | Pixel Android 16 |
| VPN-F033 | Real underlay handle changes are not propagated into the OI3 epoch | `CLOSED_FOR_POC` | Pixel Android 16 |
| VPN-F034 | Explicit real-flow stop has no distinct terminal classification | `CLOSED_FOR_POC` | Pixel Android 16 |
| VPN-F035 | Positive OI3 completion closed the detached VPN TUN after one real flow | `CLOSED_FOR_POC` | Pixel Android 16 |
| VPN-F036 | Final OI3 artifact has no multi-owner/shard admission path | `CLOSED_FOR_D1_D2` | Pixel topology + source audit |
| VPN-F037 | HEV submit backpressure has no bounded recovery contract | `CLOSED_FOR_TESTED_UDP_ENVELOPE` | Pixel Android 16 |
| VPN-F038 | Full-route multi-owner ambient TCP can stop the test owner | `CLOSED_AS_CLASSIFIED_RUN_VALIDITY_HOTSPOT` | Pixel Android 16 |
| VPN-F039 | OI3/HEV APK members can be built from incompatible source stages | `CLOSED_FOR_POC` | Build provenance + Pixel Android 16 |
| VPN-F040 | HEV external-ingress gateway port-0 listener never matches original destination | `CLOSED_FOR_CORRECTNESS_ARM` | Pixel Android 16 + WSL2 LAN |
| VPN-F041 | Single-owner TCP re-arm admits same-tuple FIN/ACK tail as a new generation | `CLOSED_FOR_CORRECTNESS_ARM` | Pixel Android 16 + WSL2 LAN |
| VPN-F042 | Multi-owner stop invalidates lwIP pools before queued HEV tasks drain | `CLOSED_FOR_CORRECTED_FOUR_OWNER_UDP_REGRESSION` | Pixel Android 16 + WSL2 LAN |
| VPN-F043 | WSL2 LAN endpoint failed same-UID bidirectional echo preflight | `CLOSED_AS_RUN_VALIDITY_HOTSPOT` | Pixel Android 16 + WSL2 LAN |
| VPN-F044 | L4 stress fixed UDP source-port base collided with ambient Android sockets | `CLOSED_FOR_POC_HARNESS` | Pixel Android 16 |
| VPN-F045 | OI3 UDP per-datagram owner generation cannot satisfy closed echo | `CLOSED_FOR_TWO_OWNER_UDP_CLOSED_ECHO` | Pixel Android 16 + WSL2 LAN |
| VPN-F046 | Registered 4-flow closed echo exceeded the two-owner/single-active-flow topology | `CLOSED_FOR_FOUR_OWNER_UDP_CLOSED_ECHO` | Pixel Android 16 + WSL2 LAN |
| VPN-F047 | OI3 multi TCP flow timeout was absolute rather than idle | `CLOSED_FOR_BOUNDED_E2_SAMPLE` | Pixel Android 16 + WSL2 LAN |
| VPN-F048 | Matched HEV E2 baseline requires an explicit comparison APK with tun-poc | `CLOSED_AS_PREFLIGHT_AND_RUNNER_FIX` | Build provenance + Pixel Android 16 |
| VPN-F049 | S172 duration-only HTTP baseline exposed OI3 TCP admission-before-tombstone and owner-busy limits | `CLOSED_FOR_MATCHED_HTTP_BASELINE_SLICE` | Pixel Android 16 + WSL2 LAN |
| VPN-F050 | S173 foreground HTTP staircase exposed OI3 deterministic-owner single-active TCP successor-SYN capacity cliff | `CLOSED_FOR_BOUNDED_HTTP_STAIRCASE_SLICE` | Pixel Android 16 + WSL2 LAN |
| VPN-F051 | S176 concurrent UDP flows collided on a busy deterministic primary owner despite idle capacity | `CLOSED_FOR_BOUNDED_UDP_MULTI_FLOW_ROUTE_PINNING_SLICE` | Pixel Android 16 + WSL2 LAN |
| VPN-F052 | S177 resource runner treated transient WSL/ADB transport and blocking log reads as target evidence | `CLOSED_FOR_HARNESS_RETRY_AND_NONBLOCKING_LOG_READ` | WSL2 + Pixel Android 16 |
| VPN-F053 | S178 B1 runner conflated dataplane proof with lifecycle cleanup-marker timing | `CLOSED_FOR_DATAPLANE_LIFECYCLE_SPLIT` | Pixel Android 16 + WSL2/ADB harness |
| VPN-F054 | S180 B1 fallback could not be proven by independent UDP and TCP DNS probes | `CLOSED_FOR_REAL_FALLBACK_HELPER_AND_FIXTURE` | Pixel Android 16 + WSL2 LAN fixture |
| VPN-F055 | S181 WSL2 closed TCP port was not a stable real-refusal fixture through Android VPN/OI3 | `CLOSED_FOR_REAL_TCP_TIMEOUT_DESIGN_CORRECTION` | Pixel Android 16 + WSL2 LAN fixture |
| VPN-F056 | S182 representative real policy drop needs an OI3 dispatcher seam, not Android app exclusion | `CLOSED_FOR_PRE_OWNER_POLICY_DROP_SLICE` | Pixel Android 16 + WSL2 LAN fixture |
| VPN-F057 | S183 OI3 UID gate treated async owner-lookup sentinel as terminal | `CLOSED_FOR_BOUNDED_UID_GATE_SLICE` | Pixel Android 16 + WSL2 LAN fixture |
| VPN-F058 | S184 owner-observed real LAN TCP RST required a narrow downstream reset propagation seam | `CLOSED_FOR_BOUNDED_REAL_RST_SLICE` | Pixel Android 16 + WSL2 LAN fixture |
| VPN-F059 | S185 bind/protect/broker infrastructure failures require phase-specific broker accounting | `CLOSED_FOR_BOUNDED_INFRA_FAILURE_SLICE` | Pixel Android 16 + WSL2 LAN fixture |
| VPN-F060 | S152 residual A2 UID matrix used public endpoints and startup-labelled resolver rows as oracle | `CLOSED_AS_POC_DESIGN_FIX` | Pixel Android 16 + WSL2 LAN fixture |
| VPN-F061 | S155 controlled A2-1 matrix exposed TCP owner-lookup and per-flow stage-correlation gap | `CLOSED_FOR_S156_A2_1_BASE_MATRIX` | Pixel Android 16 + WSL2 LAN fixture |
| VPN-F062 | S156-guarded A2-2 rerun needed explicit owner-completion delay to prove pending overlap | `CLOSED_FOR_S186_A2_2_CONCURRENCY` | Pixel Android 16 + WSL2 LAN fixture |
| VPN-F063 | Remaining A2 historical PASS bundles lack S156 guardrail provenance | `CLOSED_FOR_S190_A2_AGGREGATE` | Pixel Android 16 + WSL2 LAN fixture |
| VPN-F064 | S187 A2-3 current refresh needed explicit OI3 cleanup control before product stop | `CLOSED_FOR_S191_A2_3_CLEANUP_CONTROL` | Pixel Android 16 + WSL2 LAN fixture |
| VPN-F065 | S188 A2-4 Android overlay dropped S156 resolver correlation from the product runtime | `CLOSED_FOR_S188_A2_4_OVERLAY_CORRELATION` | Android VPP runtime overlay + Pixel Android 16 |
| VPN-F066 | S153/S170 resource runner waited for cleanup markers without driving OI3 cleanup control | `CLOSED_FOR_S153_CLEANUP_SMOKE` | Pixel Android 16 + WSL2 LAN fixture |
| VPN-F067 | S153 foreground resource trend over-bound E1 resource settlement to UDP exact closed-echo losslessness | `CLOSED_FOR_S153_FIRE_AND_COUNT_RESOURCE_DRIVER` | Pixel Android 16 + WSL2 LAN fixture |
| VPN-F068 | S153 epoch lifecycle runner over-bound underlay replacement to TCP exact transition and byte-exact wlan rules | `CLOSED_FOR_S153_EPOCH_FIRE_AND_COUNT_DRIVER` | Pixel Android 16 + WSL2 LAN fixture |
| VPN-F069 | E2 matched HTTP/device-state latency exceeds ADR-0007 comparative threshold | `OPEN_RISK` | Pixel Android 16 + WSL2 LAN fixture |
| VPN-F070 | OI3 connector poll missed protected write interest after TCP payload submit | `CLOSED_FOR_S200_S202_WRITE_INTEREST_SLICE` | Pixel Android 16 + WSL2 LAN fixture |
| VPN-F071 | OI3 multi dispatcher-to-owner handoff and post-send read wake path caused the first residual tail | `CLOSED_FOR_S205_S211_HANDOFF_POST_SEND_SLICE` | Pixel Android 16 + WSL2 LAN fixture |
| VPN-F072 | OI3 first HTTP payload submit can wait for app retransmission before Direct send | `OPEN_RISK` | Pixel Android 16 + WSL2 LAN fixture |

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
  allow/drop and short cache cells passed.  SAKAMOTO-138's deterministic
  Host/model artifact (`S135_A1_UID_ATTRIBUTION_EXECUTION_JOURNAL.md` and
  `prototypes/uid_attribution_contract/artifacts/uid-attribution-contract-host-model.json`)
  then passed six cells covering miss/completion/hit, reverse lookup,
  concurrent misses, expiry and app/network/generation refresh, completion
  identity rejection, unavailable/queue-full, bounded accounting, and zero
  residue.
- **Supported claim:** Sticky cached UID attribution is feasible for bounded
  flows, and a separate asynchronous request/cache/generation contract can
  preserve owner progress and reject invalid completions in deterministic
  Host/model evidence.
- **Non-claim:** Real Android UID correctness or timing, distinct-App Pixel
  behavior, production cache size, expiry policy, reverse-flow semantics under
  Android lookup, or device/network epoch behavior.
- **Formal invariant:** Attribution resolves outside the owner hot path, is
  cached by canonical tuple/provenance and cannot change an existing flow's
  owner/shard key.
- **Status:** `OPEN_RISK`.

### VPN-F027 -- Stale linker-prefixed plugin alias broke APK provenance

- **First observation:** A rebuilt B1 APK still emitted the temporary native
  debug tag even though the selected overlay source and freshly built canonical
  plugin no longer contained it.
- **Evidence:**
  [`S140_B1_RETURN_HOTSPOT_DIAGNOSIS.md`](S140_B1_RETURN_HOTSPOT_DIAGNOSIS.md),
  including the source/plugin/HEV/APK hashes and extracted APK-member comparison.
- **Environment:** Host APK staging/packaging and Pixel 6a runtime.
- **Root-cause confidence:** HIGH.
- **POC Correction:** When `VPP_POC_PLUGIN` is supplied, update both
  `hev_external_driver_poc_plugin.so` and the linker-prefixed
  `libhev_external_driver_poc_plugin.so`; after staging, fail the build unless
  both packaged members hash-match the explicit input plugin. Select the HEV
  owner stage explicitly and reject a runtime missing the required owner API.
- **Post-correction evidence:** The two extracted plugin members hash-match the
  registered input, the device-tested and post-assertion APK member trees are
  byte-identical, tagged instrumentation is absent at runtime, and the same
  controlled return cell passes with zero residue.
- **Supported claim:** The observed stale runtime was an artifact-provenance
  defect, not evidence that the rebuilt OI3 source ignored its return logic.
- **Non-claim:** Outer APK hash equality alone proves transitive source/runtime
  identity, or all future runtime dependencies are provenance-gated.
- **Formal invariant:** Real-network evidence joins overlay source, explicit
  plugin input, every stage alias, APK members, installed APK and device runtime;
  any overwrite-capable alias must be hash-identical before the cell is valid.
- **Status:** `CLOSED` for the current OI3 packaging path.

### VPN-F028 -- Android 16 per-UID Local Network Protection hid LAN replies

- **First observation:** The controlled WSL2 server received and replied to the
  B1 UDP tuple, and a checksum-valid reply entered Pixel `wlan0`, but both the
  protected OI3 socket and an ordinary VpnLite-UID socket timed out while a
  shell-UID LAN control passed.
- **Evidence:**
  [`S140_B1_RETURN_HOTSPOT_DIAGNOSIS.md`](S140_B1_RETURN_HOTSPOT_DIAGNOSIS.md):
  exact socket `Recv-Q=0`, one kernel drop, Local Network Protection netd/BPF
  maps, before/after same-UID control, controlled full-path return, and public
  IPv4 UDP DNS regression.
- **Environment:** Pixel 6a, Android 16, VpnLite test package, Wi-Fi LAN fixture.
- **Root-cause confidence:** HIGH for this device and test state.
- **POC Correction:** Declare and grant the POC-only temporary
  `NEARBY_WIFI_DEVICES` permission, disable the stale
  `RESTRICT_LOCAL_NETWORK` compatibility override when Local Network Protection
  is not the test subject, and reboot so netd/BPF state is rebuilt.
- **Post-correction evidence:** The direct VpnLite-UID UDP control changed from
  `5009 ms / received=0` to `25 ms / received=1`; the controlled owner-inline
  return and the original public IPv4 UDP DNS trigger both passed with exact
  cleanup and zero residue.
- **Supported claim:** The missing LAN return was Android per-UID platform
  eligibility, not an HEV/OI3 readiness or protected-socket demultiplexing bug.
- **Non-claim:** The release product must request this permission, Local Network
  Protection is irrelevant to product design, or the remaining B1 matrix is
  complete.
- **Formal invariant:** Before interpreting a controlled LAN timeout, record the
  package permission/compat state and pass a direct socket control from the same
  application UID with VPN stopped; shell UID reachability is insufficient.
- **Status:** `CLOSED_FOR_POC`; release/OEM permission policy remains outside
  this finding.

### VPN-F029 -- UID-scoped active network selected the VPN as connector underlay

- **First observation:** The first minimal real IPv4/TCP B1 cell reached OI3
  `direct-send` but the WSL2 server saw no connection.  A shell-UID TCP control
  to the same endpoint passed, while a Pixel `wlan0` capture contained no OI3
  packet.
- **Evidence:**
  [`S141_B1_TCP_UNDERLAY_NETWORK_HOTSPOT.md`](S141_B1_TCP_UNDERLAY_NETWORK_HOTSPOT.md),
  including the exact TUN/OI3 timeout, broker `bindSocket/protect` success,
  active-network dump showing Wi-Fi network 100 plus VPN network 107 with
  underlying `[100]`, and the zero-packet wlan0 capture.
- **Environment:** Pixel 6a, Android 16, VpnLite UID 12628, default-route OI3
  VPN, WSL2 endpoint `192.168.4.5:38080`.
- **Root-cause confidence:** HIGH for the observed Android API behavior; the
  old implementation used `ConnectivityManager.getActiveNetwork()` after the
  VPN was established, so the UID-scoped result could be the VPN itself.
- **POC Correction:** Enumerate all networks, reject VPN/`!NOT_VPN` candidates,
  prefer validated Internet/Wi-Fi, log candidate/selected handles, and fail
  closed when no non-VPN underlay exists.
- **Post-correction evidence:** The rebuilt APK (SHA-256
  `9b52fdc62c2fd335897d7f3e40e03140cc2f22cdfc736827f10c346388df3996`) selected
  non-VPN Wi-Fi handle `432902426637` while the UID-scoped VPN active handle was
  `467262165005`; `Network.bindSocket=true` and `VpnService.protect=true` were
  recorded.  The WSL2 fixed-response server received
  `RX ('192.168.4.151', 43336) 78`, the app received 88 response bytes in
  `2604 ms`, and OI3 recorded `direct-recv length=88`, `rewritten=2`,
  `buffers=149/149`, `residue=0`, cleanup `PASS`.  The bounded wlan0 capture
  process did not flush packet text, so server receipt plus the selected Wi-Fi
  route is the physical-egress observation for this run.
- **Supported claim:** A successful Android bind/protect API return is not
  sufficient evidence of physical underlay egress; the selected Network must
  be non-VPN and joined to the connector fd.
- **Non-claim:** This source correction alone closes B1 or proves every OEM's
  network enumeration behavior; the remaining B1 matrix and other POCs still
  require execution.
- **Formal invariant:** Every protected connector socket binds to a recorded
  non-VPN underlay Network before protect/connect; a UID-scoped VPN Network is
  never accepted as an egress candidate.
- **Status:** `CLOSED_FOR_POC`; repeat on additional OEM/network states remains
  an evidence-gap item, not an unresolved hotspot in this Pixel cell.

### VPN-F030 -- OI3 settled a multi-write TCP stream after the first short segment

- **First observation:** The independent AppA full-route DNS-over-TCP cell
  connected to `1.1.1.1:53`, but the resolver received only the first byte of
  the two-byte DNS length prefix.  The same cell reproduced across fresh VPN
  sessions; public IPv4 UDP DNS and one-write HTTP controls passed.
- **Evidence:**
  [`S142_B1_TCP_STREAM_FRAMING_HOTSPOT.md`](S142_B1_TCP_STREAM_FRAMING_HOTSPOT.md),
  including the durable App record (`bind_result=bound`, App UID 12630), the
  Pixel `wlan0` SYN/ACK plus one-byte PSH capture, and OI3
  `direct-send length=1`, `connector-wake cause=2`, and cleanup `FAIL` with
  `direct=0`, `rewritten=1`, `residue=0`.
- **Environment:** Pixel 6a, Android 16, VpnLite UID 12628, AppA UID 12630,
  full-route `vpp-oi3`, public resolver `1.1.1.1:53`.
- **Root-cause confidence:** HIGH for the observed stream boundary.  The
  Traffic Adapter writes the DNS-TCP length prefix and body in separate
  writes.  The first queue correction preserves the TUN segments, but the
  separate arm still does not carry the remaining stream bytes through the
  protected connector; see VPN-F031 for the narrower owner-drive symptom.
- **Excluded causes:** selected underlay was recorded as non-VPN Wi-Fi;
  port-53 TCP handshake controls succeeded; UDP DNS on the same artifact
  returned a valid 61-byte response and exact cleanup.
- **Required correction:** keep a TCP flow alive across multiple TUN ingress
  segments, add separate-write and coalesced-write controls, and require full
  prefix/body capture, DNS response, `direct-recv`, and zero-residue cleanup.
  Packing the fixture into one write alone is not sufficient.
- **Closure:** S143's owner-context ACK-only output correction carried the
  remaining separate-write bytes through the same protected connector.  Fresh
  source ports `46309`/`46310` both returned the valid 61-byte DNS response and
  ended with zero buffer residue.
- **Non-claim:** This does not close the broader whole-device IPv6, failure,
  lifecycle, overload, or engineering-envelope claims.
- **Formal invariant:** A TCP connector may not settle after the first short
  application write while bytes remain in the flow; all subsequent segments
  must preserve the original destination and protected socket identity.
- **Status:** `CLOSED_FOR_POC`; the exact separate/coalesced regression passed;
  continue with the remaining B1/B2 cells.

### VPN-F031 -- OI3 short TCP segment lacked owner ACK/timer progress

- **First observation:** After the VPN-F030 queue correction, the paired Pixel
  regression passed the coalesced DNS-over-TCP arm but the separate-write arm
  still emitted only `direct-send length=1` and timed out.
- **Evidence:** [`S143_B1_SHORT_SEGMENT_ACK_HOTSPOT.md`](S143_B1_SHORT_SEGMENT_ACK_HOTSPOT.md)
  records the fixed plugin/APK hashes, durable AppA records, ordered
  `tun-submit` sequences 1--6, the separate `cleanup=FAIL`, and the control
  `direct-send length=31`/`direct-recv length=63`/`cleanup=PASS` result.
- **Environment:** Pixel 6a Android 16, VpnLite UID 12628, AppA UID 12630,
  full-route `vpp-oi3`, protected Wi-Fi underlay, `1.1.1.1:53`.
- **Root-cause confidence:** HIGH.  `tcp_input_ctx()` set `TF_ACK_DELAY` and
  `lwip_owner_context_tcp_tmr()` promoted it to `TF_ACK_NOW`, but the owner
  `tcp_output_ctx()` returned when `pcb->unsent` was empty and could not emit
  an ACK-only packet.  The timer therefore advanced without a peer ACK.
- **Excluded causes:** the coalesced control uses the same APK, UID, underlay,
  broker, destination, and cleanup path and returns a valid 61-byte DNS
  response; the queue logs show no pending-slot overwrite.
- **Required correction:** add an owner-local ACK-only output path, keep short
  TCP writes non-terminal, and drive the lwIP ACK/timer path until the next
  stream segment can be submitted; preserve protected original-destination
  identity and exact settlement. **Met:** the corrected separate arm emitted a
  40-byte ACK-only TUN packet, then the remaining 30-byte send and 63-byte
  direct response.
- **Non-claim:** This does not reopen S140/S141 permission or underlay fixes and
  does not establish a general HEV defect outside this POC seam.
- **Formal invariant:** Every accepted TCP segment, including a one-byte
  segment, must eventually produce the peer ACK/next owner progress or a
  classified transport failure; a quiet connector watcher alone cannot settle
  the flow while bytes remain expected.
- **Status:** `CLOSED_FOR_POC`; corrected HEV/plugin/APK rebuilt and the paired
  separate/coalesced Pixel regression passed with allocated/freed buffers
  equal and `residue=0` (the exact counts are recorded in S143).

### VPN-F032 -- OI3 TUN negative cells are forced to a positive-path cleanup failure

- **First observation:** The first post-S143 B2 full-TUN refusal cell recorded
  the expected native transport failure, but durable cleanup emitted
  `result=FAIL`.
- **Evidence:** [`S146_B2_FAILURE_SEMANTICS_HOTSPOT.md`](S146_B2_FAILURE_SEMANTICS_HOTSPOT.md),
  Pixel run `vpp-oi3-controlled-refused`, with
  `outcome=EXPECTED_TRANSPORT_REFUSAL`, `transport-failures=1`,
  `broker=1/1`, `direct=0`, and `buffers=5/5 residue=0`.
- **Root-cause confidence:** HIGH. TUN mode skips the cell-specific
  `oi3_classify_result()` and unconditionally applies positive-path
  `output_direct`/`return_rewritten` requirements. The refusal and no-reply
  cells necessarily have zero direct output; policy drop has zero output by
  design. The app probe also records `result=OK` for a connected socket with
  zero response bytes.
- **Supported claim:** None for B2 negative semantics until the cleanup and
  app outcome contract is corrected and rerun.
- **Required correction:** Use a cell-aware negative verdict, emit one durable
  expected-failure outcome, distinguish refusal/timeout/drop in the app probe,
  and verify the joined stage/tuple plus zero residue.
- **Non-claim:** This does not invalidate the corrected B1 positive cells or
  reopen VPN-F030/VPN-F031.
- **Post-correction evidence:** S147 reran refused, no-reply, policy-drop and
  IPv4/IPv6 success controls on the final APK. All negative cells emitted
  `PASS_EXPECTED_FAILURE`; all rows had exact broker/endpoint semantics and
  zero residue.
- **Status:** `CLOSED_FOR_POC`; the local negative-result contract was corrected
  and B2 is unblocked. Whole-device failure coverage remains an open claim
  boundary.

### VPN-F033 -- Real underlay handle changes are not propagated into the OI3 epoch

- **First observation:** S150 toggled the Pixel's real Wi-Fi off and on while
  a full-route AppA TCP flow was active. Android removed the physical Network,
  left the VPN with `UnderlyingNetworks=[]`, then created a replacement handle;
  OI3 remained on `generation=1 epoch=1` and emitted no transition/rejection
  ledger.
- **Evidence:** [`S150_C1_UNDERLAY_EPOCH_HOTSPOT.md`](S150_C1_UNDERLAY_EPOCH_HOTSPOT.md),
  AppA `C1-active-transition` source port `46404`, native
  `connector-wake cause=2 generation=1`, and the before/after Android
  `NetworkAgentInfo` handles.
- **Root-cause confidence:** HIGH. `SnortVpnService` only enumerates a
  non-VPN Network in `bindAndProtectSocketForNative()`; it registers no
  `ConnectivityManager.NetworkCallback` and has no Java→native epoch control
  seam. OI3's epoch is therefore flow/run-local rather than tied to the real
  physical Network identity.
- **Supported claim:** The Android platform can remove and replace the real
  Wi-Fi underlay while keeping the VPN object alive; request-time broker
  selection can find the replacement on a later flow.
- **Non-claim:** Old-flow invalidation, stale broker/wake/output rejection, or
  real C1/C2 lifecycle correctness across that transition.
- **Required correction:** Add callback-driven handle/epoch publication,
  owner-thread admission close/invalidation, stale-event rejection, and
  current-snapshot broker provenance; rerun active AppA TCP/UDP transition
  cells before continuing D/E.
- **Post-correction evidence:** S151 registers the real
  `ConnectivityManager.NetworkCallback`, publishes an epoch/physical-handle
  snapshot through JNI/CLI, and applies it only on the FlowStackOwner. The
  active AppA TCP transition produced `epoch-invalidated` followed by
  `PASS_EXPECTED_UNDERLAY_INVALIDATION`, with `buffers=6/6`, `residue=0`, and
  no old TCP reconnect or UDP reuse. The final APK also proved loss→replacement
  callback publication and a bounded VPN stop/start carrying fresh IPv4 and
  IPv6 AppA traffic on the replacement snapshot. Android 16 removes the old
  VPN Network during physical Wi-Fi loss; seamless in-place migration and
  automatic session recreation are explicitly not claimed.
- **Status:** `CLOSED_FOR_POC`; C1 is unblocked under the bounded explicit
  VPN-session restart rule. C2 remains a separate real-traffic lifecycle gate.

### VPN-F034 -- Explicit real-flow stop has no distinct terminal classification

- **First observation:** S152 ran a real AppA B1 TCP flow to a waiting LAN
  fixture, then issued the bounded `sakamoto-oi3 stop` control while the flow
  was active.  The AppA socket was aborted as expected and native resources
  settled, but the terminal ledger emitted `result=FAIL`
  `outcome=EXPECTED_DIRECT_REPLY`.
- **Evidence:** [`S152_C2_REAL_STOP_CLASSIFICATION_HOTSPOT.md`](S152_C2_REAL_STOP_CLASSIFICATION_HOTSPOT.md),
  AppA stage `C2-real-normal-tcp-active` source port `46421`, and native
  `buffers=5/5 residue=0 broker=1/1` cleanup output.  The APK, plugin, and
  native log hashes are recorded in S152.
- **Root-cause confidence:** HIGH.  `sakamoto-oi3 stop` sets
  `finish_requested`, but `oi3_finish()` only has explicit fault,
  underlay-invalidation, negative-cell, and positive direct-reply result
  classes.  A requested normal stop is therefore evaluated as a missing reply.
- **Supported claim:** The stop control reaches the owner and the observed
  real flow tears down without buffer residue in this cell.
- **Non-claim:** C2 normal-stop/fault/restart settlement is not closed; a
  resource-clean run with a `FAIL` terminal verdict cannot be promoted as a
  passing lifecycle result.
- **Required correction:** Add an immutable normal-stop reason and distinct
  `EXPECTED_STOP` / `PASS_EXPECTED_STOP` terminal outcome; retain separate
  fault, underlay, transport, and direct-reply classifiers; add a regression
  test and rerun the real AppA cell before fault/restart.
- **Post-correction evidence:** S153 rebuilt the plugin/APK and reran the same
  real AppA stop cell.  The active socket was aborted, native cleanup emitted
  `PASS_EXPECTED_STOP outcome=EXPECTED_STOP`, and the ledger closed
  `broker=1/1 buffers=10/10 residue=0 duplicate-close=0 infrastructure-failures=0`.
- **Status:** `CLOSED_FOR_POC`; only the normal-stop contract is closed.  The
  remaining real fault/restart C2 gate is still open.  This was a local POC
  contract correction, not an architecture reopening.

### VPN-F035 -- Positive OI3 completion closed the detached VPN TUN after one real flow

- **First observation:** S153 ran a real post-restart IPv4 DNS flow and then
  an IPv6 DNS flow in the same full-route VPN session.  IPv4 returned a valid
  response; IPv6 waited for a VPN Network and recorded
  `vpn_unavailable`/`tuple_attempted=false`.  S155 repeated the formal
  explicit stop/start recovery and reproduced the same IPv4→IPv6 failure.
- **Evidence:** [`S156_C2_ONE_FLOW_PER_VPN_SESSION_HOTSPOT.md`](S156_C2_ONE_FLOW_PER_VPN_SESSION_HOTSPOT.md),
  S155 AppA JSONL hash
  `141f3f29119b36a1d5127fe747e5c0daf352bdb2c0c122ba90af23a8b6bde6e9`,
  native `oi3_cleanup result=PASS ... buffers=4/4 residue=0`, and
  Connectivity output with physical Wi-Fi but no `TRANSPORT_VPN` Network.
  S154's fresh-session IPv6-first cell passed, excluding an IPv6 underlay
  defect. S157 then rebuilt the final plugin/APK and carried real AppA IPv4
  UDP DNS followed by IPv6 UDP DNS in one session on VPN handle
  `767909875725`; both generations returned valid 61-byte DNS responses and
  emitted `PASS` cleanups with zero residue. The post-fix active TCP fault
  emitted `PASS_EXPECTED_FAULT` with `buffers=9/9 residue=0`.
- **Root-cause confidence:** HIGH. `oi3_finish()` closes the detached
  `tm->tun_fd` at `owner_inline_oi3.c:1845` after the first positive flow;
  closing that fd removes the Android VPN Network.  The AppA adapter's bounded
  `TRANSPORT_VPN` lookup is behaving as designed.
- **Supported claim:** Successful positive real flows now settle their own HEV
  generation while the VPN TUN remains armed for a fresh next generation;
  explicit stop/fault/underlay-invalidated/negative paths still close the
  session. S157 proves same-session IPv4→IPv6 sequencing for the registered
  cell and bounded active-fault teardown.
- **Non-claim:** Seamless Android underlay migration, arbitrary concurrent
  multi-owner capacity, production resource/performance limits, or a second
  packet/ownership path.
- **Required follow-up:** Continue C2/D/E under the re-arm contract and retain
  the S156 reproduction as a regression test; reopen only if a subsequent
  run loses `TRANSPORT_VPN`, revives stale generation state, or leaves residue.
- **Status:** `CLOSED_FOR_POC`; this was a lifecycle contract correction, not an
  architecture replacement.

### VPN-F036 -- Final OI3 artifact has no multi-owner/shard admission path

- **First observation:** S158's pre-D audit found that the final OI3 artifact
  used for S157 C2 is still a single-owner implementation. The D1 contract
  requires at least two final-topology Pixel owners, but the selected artifact
  has no executable second-owner path.
- **Evidence:** canonical/generated OI3 source contains one global
  `static oi3_main_t oi3_main` with one FlowStackOwner context, target thread,
  frame queue, TUN fd and per-context pending queue. The Android launcher emits
  `sakamoto-oi3 tun ... target-thread 1` and `cpu { workers 1 }`; no owner
  registry, tuple-to-shard dispatcher, or per-owner resource ledger exists.
  The detailed record is [`S158_D_FINAL_TOPOLOGY_OWNER_OVERLOAD_HOTSPOT.md`](S158_D_FINAL_TOPOLOGY_OWNER_OVERLOAD_HOTSPOT.md).
- **Root-cause confidence:** HIGH. This is directly visible in the selected
  source/startup topology, not inferred from a timeout or fixture result.
- **Supported claim:** S157 proves a corrected single-owner, re-armed-TUN
  lifecycle contract with real same-session IPv4→IPv6 traffic and bounded
  fault cleanup.
- **Non-claim:** Pixel multi-owner isolation/distribution, per-owner flow
  admission, packet/credit/buffer overload, capacity, or the dependent E
  engineering envelope. S129 OI-4 Host/two-pthread evidence cannot substitute
  for these final-topology Pixel claims.
- **Required follow-up:** The final owner registry/hash/dispatch and
  independent owner/resource contracts were added and D1/D2 were rerun. D3
  remains separately paused by `VPN-F037`; do not use this historical finding
  to describe the current multi-owner artifact.
- **Status:** `CLOSED_FOR_D1_D2`; the original design interruption is resolved
  for the tested owner topology. D3/E remain gated by the runtime submit
  contract below.

### VPN-F037 -- HEV submit backpressure has no bounded recovery contract

- **First observation:** S159's single corrected D3 rerun offered 64 same-tuple
  IPv4/UDP datagrams to the final two-owner Pixel artifact. The first 15 HEV
  `flow_stack_owner_submit()` calls returned success; the next 49 returned
  `-5`. The new owner-local rejection accounting settled every VPP buffer but
  the accepted flow produced no reply and timed out.
- **Evidence:** [`S159_D3_HEV_SUBMIT_BACKPRESSURE_HOTSPOT.md`](S159_D3_HEV_SUBMIT_BACKPRESSURE_HOTSPOT.md),
  native cleanup `FAIL ... output=0 ... submit-rejects=49 ...
  buffers=74/74 residue=0 error=tun-flow-timeout-no-reply`, and the captured
  AppA JSONL showing 64 bound sends on VPN handle `815154515981`.
- **Root-cause confidence:** HIGH. S160 arm64 disassembly maps `-5` to
  category-1 inflight-pbuf credit exhaustion; it is not an Android permission,
  UID, LAN, broker, or buffer-lifetime failure.
- **Supported claim:** The adapter now settles the rejected packet exactly
  once, records the credit ledger, and three bounded UDP generations completed
  with `PASS_EXPECTED_OVERLOAD`, zero residue, and TUN re-arm. Owner-local queue
  exhaustion is also classified as a current-packet drop for multi-owner UDP.
- **Non-claim:** Production capacity, infinite soak, four-worker Android
  scaling, and arbitrary public endpoint availability remain unproven.
- **Post-correction evidence:** S161's timed rerun offered four concurrent
  `repeat=16` stages, waited for all 64 packets to finish, then obtained a
  valid WSL2 DNS recovery reply after four `PASS_EXPECTED_OVERLOAD`
  generations; every generation re-armed with residue `0`.
- **Status:** `CLOSED_FOR_TESTED_UDP_ENVELOPE`; the HEV credit accounting and
  owner-local packet-overload contract are supported for this bounded cell.

### VPN-F038 -- Full-route multi-owner ambient TCP can stop the test owner

- **First observation:** S160 fresh `vpp-oi3-multi` starts received an Android
  ambient IPv4/TCP flow to port `5228` before the AppA recovery probe. The flow
  reached `output=1`/`handshake=1` but never reached `direct`, then ended with
  `tun-flow-output-not-a-direct-return`; subsequent tuples were rejected as
  `owner-stopped`.
- **Reproduction:** The same startup/ambient sequence reproduced in more than
  one fresh multi-owner run, including a no-D3 B1 baseline. HEV credit ledgers
  were zero after cleanup and VPP buffers settled exactly, so this is not the
  D3 `-5` credit condition.
- **Evidence:** [`S160_D3_OVERLOAD_RECOVERY_EXECUTION_JOURNAL.md`](S160_D3_OVERLOAD_RECOVERY_EXECUTION_JOURNAL.md),
  [`evidence/s160-ambient-full-route-hotspot/vpp-baseline-ambient.log`](evidence/s160-ambient-full-route-hotspot/vpp-baseline-ambient.log).
- **Root-cause confidence:** HIGH for the lifecycle contamination; exact
  Android source/endpoint semantics for port 5228 remain to be mapped.
- **Impact:** The original source behavior could let unrelated ambient traffic
  consume a generation, but the corrected adapter now classifies the observed
  TCP/5228 no-reply shape as an expected ambient timeout and keeps the shared
  TUN/owner armed. S161 recorded the classification and completed D3 recovery.
- **Status:** `CLOSED_AS_CLASSIFIED_RUN_VALIDITY_HOTSPOT`; this is not a claim
  that arbitrary ambient Android traffic has an application-level reply.

### VPN-F039 -- OI3/HEV APK members can be built from incompatible source stages

- **First observation:** S163 attempted to load an OI3 plugin built from the
  dirty conditional-wake worktree into the clean product VPP core. Android
  rejected it because `vlib_frame_queue_wakeup_mode` was absent. After that
  pair was corrected, the default HEV stage rejected the owner-resolver symbol
  `hev_socks5_owner_config_default`.
- **Evidence:** [`S163_E1_E2_EXECUTION_JOURNAL.md`](S163_E1_E2_EXECUTION_JOURNAL.md),
  [`evidence/s163-e1-e2/s163-plugin-load.txt`](evidence/s163-e1-e2/s163-plugin-load.txt),
  and the corrected canonical VPP/plugin/HEV hashes recorded in that journal.
- **Root-cause confidence:** HIGH. The failures are deterministic dynamic
  linker/`dlsym` mismatches between source/stage members, not network or UID
  behavior.
- **POC Correction:** Rebuild the OI3 plugin from the exact clean product source
  revision, select the owner-context HEV stage explicitly, seal both hashes in
  the APK provenance, and omit the temporary `tun_poc` member from the final
  canonical APK.
- **2026-08-25 hardening:** During the S168 rerun, rebuilding the debug APK
  without an explicit `HEV_STAGE_DIR` again selected the legacy
  `work/android-hev-stage` member.  VPP started but OI3 multi failed at
  `dlsym(hev_socks5_owner_config_default)` and reported `active=0 owners=0`.
  `build-debug-apk.sh` now refuses any APK that carries the OI3 plugin unless
  `libhev-socks5-tunnel.so` exports the full owner-context API used by
  `owner_inline_oi3.c`.  The corrected APK was rebuilt with
  `work/android-hev-poc7-stage`; Pixel startup then reported
  `success=true rc=0 vppMode=27`, `hev-loaded`, `oi4 multi enabled owners=2`,
  and `oi4 multi active=1 owners=2`.
- **Post-correction evidence:** The paired artifact loaded, returned valid
  IPv4 DNS and Direct HTTP, and the restored canonical APK passed the controlled
  HTTP smoke with `PASS` cleanup and zero residue.
- **Non-claim:** This closes packaging validity only; it does not close E2's
  comparative performance gate or certify arbitrary external endpoints.
- **Status:** `CLOSED_FOR_POC`; treat source→stage→APK identity as a preflight
  validity gate, not as a runtime hotspot.

### VPN-F040 -- HEV external-ingress gateway port-0 listener never matches original destination

- **First observation:** S164 resumed the owner-context HEV external-fd path
  against the controlled WSL2 endpoint. The fd was a live `SOCK_SEQPACKET`,
  epoll woke, 14 packets were read, and the IPv4 TCP SYN checksum passed, but
  the HTTP probe timed out.
- **Evidence:** [`S164_HEV_EXTERNAL_INGRESS_GATEWAY_WILDCARD_PORT_HOTSPOT.md`](S164_HEV_EXTERNAL_INGRESS_GATEWAY_WILDCARD_PORT_HOTSPOT.md).
  Three valid post-fix attempts reached the same boundary: the trace reports
  `dport=42083`, `checksum=0`, and `tcp-listen-match lpcb=0x0`; no TCP accept,
  HEV session or connector event followed. The device and endpoint controls
  were valid and clean.
- **Environment:** Pixel 6a Android 16, owner-context HEV stage, external fd
  shim and temporary WSL2 HTTP endpoint.
- **Root-cause confidence:** HIGH. `gateway_init()` intentionally creates
  `IPADDR_TYPE_ANY` TCP/UDP listeners and binds port `0`, while the owner TCP
  demux requires an exact incoming destination port. The equivalent UDP path
  has the same exact-port boundary. The earlier synthetic-address filter is a
  separate prerequisite and was isolated by the external-only
  `accept_nonlocal` diagnostic flag.
- **POC Correction:** S165 applied the repository
  `hev-owner-context-external-ingress.patch`. External gateway initialization
  now enables an opt-in wildcard mode; TCP preserves the incoming destination
  port on accepted PCBs, while UDP marks the external listener explicitly and
  carries the synchronous original destination address/port into the SOCKS5
  frame. Ordinary owner contexts retain strict exact-port/address demux, and
  reset/teardown clears the marker.
- **Post-correction evidence:** The first valid Pixel/WSL2 regression returned
  `HTTP/1.0 200 OK` in 8 ms, recorded `socks_connect_count=1`, emitted
  `socks5 client tcp -> [192.168.4.5]:42083`, and passed the loop cleanup. VPP
  reported zero parse/read/write/shim errors. See
  [`S165_HEV_EXTERNAL_INGRESS_CORRECTION_EXECUTION.md`](S165_HEV_EXTERNAL_INGRESS_CORRECTION_EXECUTION.md)
  and [`evidence/s165-hev-external-ingress/s165-http-loop-summary.txt`](evidence/s165-hev-external-ingress/s165-http-loop-summary.txt).
- **Supported claim:** The external IPv4/TCP correctness arm is now supported
  for this controlled endpoint. This closes the design hotspot but does not
  establish IPv6/UDP coverage or E2 comparative performance.
- **Non-claim:** ADB, WSL2 reachability, and SOCKS protect brokerage were not
  the root cause. E2 remains open until matched traffic/resource measurements
  and the remaining protocol/topology cells are completed.
- **Formal invariant:** External original-destination packets may enter an
  explicit transparent gateway wildcard only in the external-ingress owner
  context; ordinary owner contexts must retain strict address and exact-port
  demux, and every accepted flow must preserve its original destination.
- **Status:** `CLOSED_FOR_CORRECTNESS_ARM`; E2 is reopened for the remaining
  matched matrix and resource gates.

### VPN-F041 -- Single-owner TCP re-arm admits same-tuple FIN/ACK tail as a new generation

- **First observation:** The first formal isolated canonical OI3 HTTP cell
  returned HTTP 200 and a clean generation-1 direct reply, then the re-armed
  single-owner reader admitted the same tuple's FIN/ACK tail as generation 2.
  Generation 2 emitted `oi3_cleanup result=FAIL outcome=EXPECTED_DIRECT_REPLY`
  with `direct=0`, but `residue=0`; the primary flow itself was successful.
- **Evidence:** [`S166_A2_OWNER_RESOLVER_ONE_SHOT_FIX.md`](S166_A2_OWNER_RESOLVER_ONE_SHOT_FIX.md)
  and [`evidence/s166-oi3-canonical-http-20260824/vpp-stdout.log`](evidence/s166-oi3-canonical-http-20260824/vpp-stdout.log).
  The clean generation-1 line had `direct=3`, `broker=1/1`, and zero residue;
  the next ingress was a same-tuple FIN/ACK tail.
- **Root-cause confidence:** HIGH. The multi-owner dispatcher already kept a
  canonical TCP tombstone, but single-owner ingress never populated the active
  hash or applied the wait-for-SYN gate after `oi3_rearm_tun_flow()`.
- **POC Correction:** Single-owner ingress now records the canonical TCP hash
  on the first packet, rejects non-SYN packets while waiting for the next SYN,
  and clears the tombstone only when a new SYN arrives. The HTTP runner checks
  cleanup after stop and validates required fields independently of log order.
- **Post-correction evidence:** The ARM64 canonical plugin hash is
  `8e127fbb28fe9612e08d966cc19ba95eff273db030546bc4cb20e46dcff561a9`; the APK
  contains no `tun_poc`. The same Pixel/WSL2 cell returned HTTP 200 with 135
  bytes in 1410 ms, logged
  `oi3 single-admission result=REJECT reason=tcp-tail`, emitted one generation-1
  cleanup `PASS` (`direct=3`, `broker=1/1`, `residue=0`), and emitted no cleanup
  `FAIL`. Raw evidence is under
  [`evidence/s166-oi3-tail-fix-20260824/`](evidence/s166-oi3-tail-fix-20260824/).
- **Non-claim:** This closes the bounded single-owner TCP correctness seam;
  it does not close E2's matched performance, full protocol, or multi-owner
  resource gates. Ambient-flow isolation remains required.
- **Status:** `CLOSED_FOR_CORRECTNESS_ARM`; no three-attempt stop-rule escalation
  was needed after the root cause was isolated and the bounded regression passed.

### VPN-F042 -- Multi-owner stop invalidates lwIP pools before queued HEV tasks drain

- **First observation:** The first final-topology UDP teardown probe reached the
  same Scudo heap-corruption signature in two valid pre-fix cells: a 4-flow
  cell and a minimized 2-flow cell.  The 2-flow run admitted both owners and
  completed broker/direct output, but one owner stopped while the other still
  had queued HEV work; Scudo reported `invalid chunk state` and
  `corrupted chunk header`, followed by VPP SIGABRT.
- **Evidence:** [`pre-fix-summary.txt`](evidence/s168-multi-owner-udp-teardown-20260824/pre-fix-summary.txt)
  and the fixed regression summary
  [`post-fix-summary.txt`](evidence/s168-multi-owner-udp-teardown-20260824/post-fix-summary.txt).
  The failing owner addresses correlate with the HEV/lwIP context identities;
  single-owner control passed without the failure.
- **Root-cause confidence:** HIGH. `flow_stack_owner_stop()` signalled
  `hev_socks5_tunnel_owner_stop()` and immediately invalidated the lwIP pools,
  while OI3's later `task_step` drain could still execute queued HEV tasks on
  the VPP worker.  The HEV scheduler context is thread-local, so the seam is
  local to each non-HEV worker rather than a requirement for a process-global
  lock or a second ownership model.
- **POC Correction:** The first correction added a bounded
  `hev_task_system_driver_step()` drain after HEV owner stop and before
  `lwip_owner_context_stop()` on the external-worker path.  The follow-up
  correction expanded the drain to 64 calls of 1024 quanta, made OI3 propagate
  and retry `NOT_READY`, and guarded HEV destroy until stop was ready.  The
  build script applies and verifies both source patches before packaging.
- **Post-correction evidence:** The first fixed ARM64 HEV member hash was
  `6fcdba38c6cbdc49c08196074586522d0fe43e2199ec07035dc4d9c3f37d8e20`; the
  follow-up HEV member is
  `33dd3ae879cea83c0ab440c23cf93df7fdad9e96351aad2616397dd6a55c39b5`, the
  OI3 plugin is
  `91fbb0a5bc6c003262cca7d9547cf5ca6d2d76a6e08dc7c0dd42aab21f1f6236`, and
  the APK is `0aa8c066eaec2166db88b5b3d46f1f8d47195b3d5f389bace3e5d1eeee15afb1`.
  The fixed 2-flow Pixel/WSL2 regression completed with `fatalFlows=0`; both
  owners emitted two `oi3_cleanup result=PASS` generations with `broker=1/1`,
  `direct=1`, `buffers=10/10`, `residue=0`, and zero transport/infrastructure
  failures.  The follow-up-corrected registered 4-flow cell (run
  `62691387993824`, VPP pid `10355`) still emitted Scudo `invalid chunk state`
  at `0x200006d9ad4e340`, matching the owner-1 lwIP context, followed by
  SIGABRT; post-stop process/tun0 residue was nevertheless absent.
- **Follow-up root cause / design adjustment (2026-08-24):** The fourth
  recurrence narrowed the defect to OI3 owner teardown affinity.  The
  multi-owner `oi3_worker_node` tail could call `oi3_finish_for()` for any
  `active && finish_requested && residue==0` owner, without first proving that
  the current VPP thread was that owner's `target_thread`.  `oi3_finish_for()`
  stops/destroys the owner Flow Stack and drains the HEV scheduler through
  thread-local state; running that path from a foreign worker can therefore
  invalidate/free another owner's lwIP/HEV context.  The POC design is now:
  owner finish is owner-thread-affine; foreign workers only re-enqueue a finish
  token to the target owner thread, and destroy remains guarded until owner
  stop is ready.
- **Follow-up preflight evidence:** Static regressions now cover owner-thread
  teardown, foreign-owner tail deferral, Android foreground-service relaunch,
  and APK plugin loading configuration
  (`test_verify_s168_owner_teardown_lifecycle.py`,
  `test_verify_vpn_lite_legacy_start.py`,
  `test_verify_vpn_lite_plugin_staging.py`,
  `test_verify_android_stage_vpp_core.py`).  The current APK was rebuilt from a
  single Android VPP runtime/plugin closure, installed on Pixel, and started
  with `mode=vpp-oi3-multi`, `vppMode=27`, `rc=0`.  The generated
  `startup.conf` loads plugins from the APK native library directory with
  `name-filter libhev_external_driver_poc_plugin.so`; `show plugins` lists
  `libhev_external_driver_poc_plugin.so`, `sakamoto-oi3 underlay` succeeds, and
  `startup.exec` contains `sakamoto-oi3 multi tun fd 3 target-thread-a 1
  target-thread-b 2`.
- **Authorized 4-flow rerun status (2026-08-25):** The explicitly approved
  fixed-artifact Pixel rerun did not reproduce the Scudo/SIGABRT heap boundary:
  VPP remained alive after two 4-flow attempts and a minimized 1-flow probe.
  However the run is `INVALID` as an echo correctness regression.  The app
  stress logs still reported `received=0`; the VPP owner emitted
  `direct-send` but no `direct-recv`/`tun-output`; and a VPN-stopped,
  same-package direct app UDP control to `192.168.4.5:42085` also sent three
  packets and received zero echo replies while the WSL2 fixture logged all
  three inbound packets from `192.168.4.151`.  A VPN-stopped TCP control to
  `192.168.4.5:42086` timed out before connect.  This separates the original
  heap hotspot from a new fixture-validity hotspot, VPN-F043.
- **Preflighted follow-up status (2026-08-25):** The fixture hotspot was
  corrected for the current LAN endpoint by disabling the stale
  `RESTRICT_LOCAL_NETWORK` compat override for
  `com.sakamoto.snort.vpnlite` and proving same-package, VPN-stopped direct
  echo to `192.168.4.5`: UDP `42185` passed with `bytes=192 packets=3
  received=3`, and TCP `42186` passed with `sent=1 received=1`.  The next
  4-flow attempt exposed a separate app-harness defect: fixed UDP source ports
  `40000`--`40003` can collide with ambient Android sockets
  (`EADDRINUSE`; one observed socket used `192.168.4.151:40003` to remote
  QUIC/443).  VPN-F044 corrects that by making `sourcePortBase` runner
  configurable and recorded.
- **Valid endpoint 4-flow result (2026-08-25):** With
  `sourcePortBase=43000`, exact same-UID direct preflight passing, and
  `mode=vpp-oi3-multi` active, the UDP closed 4-flow run
  `runId=56779517593894` did not reproduce Scudo/SIGABRT.  VPP pid `11048`
  survived; app summary was `sent=287 received=180 errors=107
  mismatches=0 unexpected=5 fatalFlows=0 executorTimeout=false`; host fixture
  counters were symmetric (`udp_rx=283 udp_tx=283`); and `show sakamoto-oi3
  multi` reported `active=1 owners=2`, owner residues `0`, and no owner error
  string.  This is not a heap-boundary recurrence, but it is not a passing
  closed echo regression.  VPN-F045 now owns the remaining echo-loss/timeout
  disposition.
- **Monitor correction:** The native VPP monitor was also found to hard-code
  historical `show tun-poc`/`show s124-vpn-tun` probes after OI3 startup.  The
  OI3 APK intentionally stages only `libhev_external_driver_poc_plugin.so`, so
  `show tun-poc` produced persistent false CLI noise.  The monitor now selects
  a mode-specific show command (`show sakamoto-oi3 multi`, `show
  sakamoto-oi3`, `show sakamoto-oi2`, `show s124-vpn-tun`, or `show tun-poc`)
  and static tests cover the branch.
- **Late S169 status (2026-08-25):** VPN-F045 is closed for the two-owner UDP
  closed-echo envelope by the persistent HEV UDP connector and OI3
  per-datagram inflight correction. A fresh 1-flow run
  (`runId=86632836943396`) passed with `sent=834 received=834 errors=0`, and a
  fresh 2-flow run (`runId=139608275148756`) passed with
  `sent=1702 received=1702 errors=0`. The 4-flow rerun did not reproduce
  Scudo/SIGABRT; its remaining errors are exactly accounted for by VPN-F046
  owner-busy capacity rejects.
- **Four-owner closure evidence (2026-08-25):** F046's selected correction
  expanded OI4 to four owner contexts while preserving one active UDP canonical
  hash per owner. The rebuilt APK
  `96726fa8e56d74e731105c71568735af338f74fcb06cc067eff00b7525b07179` and OI3
  plugin `b97c57a853a31e0bd7451dd4216519553091954ba45412b3b3def0825dda5951`
  ran the registered 4-flow UDP closed echo as `runId=127931250090287`.
  Startup logged `owners=4 target-a=1 target-b=2 target-c=3 target-d=4`; the
  app reported `sent=3698 received=3698 errors=0 mismatches=0 fatalFlows=0`;
  VPP recorded ingress on owners 0/1/2/3 (`1366`/`1366`/`1372`/`1395`) and four
  clean `oi3_cleanup result=PASS` records with `submit-rejects=0`,
  `queue-rejects=0`, and `residue=0`. There were zero `owner-busy` and zero
  `multi-admission result=REJECT` records.
- **Post-F046 resource trend evidence (S170, 2026-08-25):** The same corrected
  artifact ran five repeated four-owner UDP closed-echo cycles in
  `runId=20260825-112255-922529`. All cycles passed exact app echo and emitted
  four clean owner teardowns; the owned WSL2 fixture recorded
  `fixtureRx=12762 fixtureTx=12762`; `pidof vpp` was empty and UDP `42185` had
  no listener after cleanup. App/VPP FD counts stayed `120/41`, and RSS
  variation was bounded to `648/480 KiB`.
- **Non-claim:** The S169/F046 evidence closes the bounded four-owner UDP
  closed-echo regression. It does not establish arbitrary concurrency,
  production capacity constants, soak behavior, or E2 performance.
- **Status:** `CLOSED_FOR_CORRECTED_FOUR_OWNER_UDP_REGRESSION`; the original
  heap boundary did not recur after the owner lifecycle corrections and the
  F046 capacity correction under the registered 4-flow UDP closed-echo shape.

### VPN-F043 -- WSL2 LAN endpoint failed same-UID bidirectional echo preflight

- **First observation:** During the authorized S168 4-flow retry, the WSL2 UDP
  fixture at `192.168.4.5:42085` received packets from the Pixel
  (`192.168.4.151`), but the Android app received no echo replies.  The same
  failure reproduced with the VPN stopped and no VPP process running: the
  ordinary app UDP control sent three packets and received zero replies, while
  the WSL2 server logged all three inbound datagrams.  A WSL2 TCP echo fixture
  on `192.168.4.5:42086` also failed the VPN-stopped app control at connect
  timeout.
- **Interpretation:** This is a fixture/run-validity failure, not evidence that
  OI3 failed to read a protected socket reply.  Android-to-WSL UDP ingress is
  insufficient evidence for `expectEcho=true`; bidirectional same-UID echo must
  be proven before the VPN datapath is interpreted.
- **POC Correction:** Echo-bearing cells must run a VPN-stopped same-package
  direct preflight for the exact protocol, endpoint, and payload shape.  If the
  preflight fails, mark the full-path cell `INVALID` and either switch to an
  egress-only `expectEcho=false` design with host receive counts, or choose a
  different bidirectional LAN endpoint.  Do not classify missing echo as OI3
  transport timeout, owner output failure, or heap-regression evidence.
- **Post-correction evidence (2026-08-25):** On the current Pixel/WSL2 LAN, the
  stale `RESTRICT_LOCAL_NETWORK` compat override was disabled and the POC app's
  `NEARBY_WIFI_DEVICES` grant was present.  Same-package, VPN-stopped direct
  controls against `192.168.4.5` then passed for UDP `42185`
  (`bytes=192 packets=3 received=3`) and TCP `42186` (`sent=1 received=1`).
  F043 therefore no longer blocks interpretation of later VPN results. The
  subsequent blockers were in the OI3/HEV POC itself: VPN-F045, now closed for
  the two-owner UDP envelope, and VPN-F046, the four-flow capacity/design
  mismatch now closed by the four-owner correction.
- **Status:** `CLOSED_AS_RUN_VALIDITY_HOTSPOT`; the root cause is outside the
  selected datapath and the campaign rules now require direct app echo preflight
  before any WSL2 LAN echo result is accepted.

### VPN-F044 -- L4 stress fixed UDP source-port base collided with ambient Android sockets

- **First observation:** After F043 preflight passed, the first 4-flow UDP
  stress retry failed before exercising OI3 because the app attempted to bind
  fixed local UDP ports `40000`--`40003` and Android already had an ambient
  socket occupying `192.168.4.151:40003` for a remote QUIC/443 flow.  The app
  reported `BindException`/`EADDRINUSE`.
- **Interpretation:** This was a POC harness defect, not a VPN datapath or
  owner-lifecycle result.  Fixed local ports are too brittle on a real Android
  device because unrelated system or application UDP traffic can reuse the
  same ephemeral range.
- **POC Correction:** `SnortVpnService` accepts `sourcePortBase`, clamps it to
  the safe multi-flow port range, logs it, and binds UDP flows at
  `sourcePortBase + flow`.  `MainActivity` forwards the extra, the formal S125
  runner defaults to `UDP_SOURCE_PORT_BASE=43000` and
  `TCP_SOURCE_PORT_BASE=44000`, each cell manifest records `sourcePortBase`,
  and `s125-parse-results.py` validates UDP flow ports from the manifest rather
  than assuming `40000`.  Static and dynamic regressions are in
  `test_verify_s168_owner_teardown_lifecycle.py`.
- **Post-correction evidence:** The rebuilt APK accepted
  `--ei sourcePortBase 43000`; the app start log recorded
  `sourcePortBase=43000`; flow logs used local ports `43000`--`43003`; and the
  source-port collision did not recur in the 4-flow rerun.
- **Status:** `CLOSED_FOR_POC_HARNESS`; formal runners must keep the source
  port base configurable and manifest-recorded for real-device multi-flow
  cells.

### VPN-F045 -- OI3 UDP per-datagram owner generation cannot satisfy closed echo

- **First observation:** The corrected endpoint and source-port-base 4-flow
  UDP closed cell (`runId=56779517593894`) used `sourcePortBase=43000` against
  `192.168.4.5:42185`.  Same-package direct UDP/TCP preflight had already
  passed, and VPP OI3 multi was active.  The app sent `287` datagrams but
  received only `180`, with `errors=107`, `unexpected=5`,
  `fatalFlows=0`, and `executorTimeout=false`.
- **Evidence:** The host echo fixture was symmetric (`udp_rx=283 udp_tx=283`),
  so the endpoint received and echoed the traffic it saw.  VPP pid `11048`
  survived the run; OI3 multi reported two active owners, owner residues `0`,
  and no owner error string.  No Scudo/SIGABRT heap boundary was observed in
  the captured evidence.
- **Minimized follow-up evidence:** A short 2-flow closed probe used
  `sourcePortBase=43000` (`43000` hashes to owner 0 and `43001` hashes to
  owner 1 for `192.168.4.151 -> 192.168.4.5:42185`).  It still failed app
  closed echo correctness: `runId=58708249433631`, `sent=38 received=20
  errors=18 unexpected=0 fatalFlows=0 executorTimeout=false`.  VPP pid `11544`
  remained alive; OI3 multi showed `route=39/29 reject=0/0 wrong-owner=9`,
  owner residues `0`, and no owner error string.  The local fixture was stopped
  at `udp_rx=31 udp_tx=31` after the direct preflight plus the 2-flow probe.
  This rules out the simplest explanation that only 4 flows over two owners
  cause the loss through route rejection.
- **1-flow/per-port evidence:** After ADB was temporarily restored through
  `SAKAMOTO_ADB=/home/js/.local/bin/adb`, the device was cleaned (`pidof vpp`
  empty; app force-stopped), a per-source-port echo fixture was started, and
  the same-package direct UDP preflight passed (`bytes=128 packets=2
  received=2`).  The 1-flow OI3 multi probe then still failed:
  `runId=47889971598670`, `sent=19 received=10 errors=9
  unexpected=0 fatalFlows=0 executorTimeout=false`.  VPP pid `12783`
  survived; owner0 showed `generation=20 ingress=34 output=20 residue=0`;
  owner1 contained only earlier ambient input.  Host per-port counters proved
  the decisive shape: the direct preflight used one stable app source port
  (`192.168.4.151:56055=2/128`), while the OI3 packets arrived as one datagram
  each from many protected-socket ephemeral source ports (`33247`, `35380`,
  `39699`, `44095`, `48024`, `52482`, `57487`, ...), not from app local port
  `43000`.
- **Root cause:** HIGH confidence.  `oi3_parse_tun_packet()` captured the
  original destination in `target_address`, but did not preserve the original
  app source endpoint.  `oi3_rewrite_return()` rewrote only the return packet's
  source address/port back to the original destination; it left the destination
  address/port as the protected underlay socket's ephemeral local tuple.  A
  packet written back to the VPN TUN with that destination cannot reliably
  reach the app socket bound to `10.111.0.2:43000`.
- **POC corrections applied and validated locally:** `oi3_main_t` now stores
  `source_address`, `source_address_length`, and `source_port` from the
  original TUN packet.  `oi3_rewrite_return()` rewrites both directions of the
  return tuple: source becomes the original destination, destination becomes
  the original app source, and TCP/UDP checksums are recomputed.  Static
  regression `test_oi3_tun_return_rewrite_restores_original_app_source` covers
  IPv4/IPv6 source capture and destination rewrite.  A later 1-flow device
  minimization exposed two additional UDP short-flow lifecycle defects: rearm
  cleared owner-local pending TUN packets, and a later owner token could submit
  a second pending UDP datagram into the same HEV generation.  The POC now
  preserves pending packets across rearm and logs/defers
  `reason=udp-generation-busy` once a multi-owner UDP generation has already
  submitted one datagram.  Static regression coverage now includes pending
  preservation and one-pending-per-generation behavior.
- **Post-correction device evidence (2026-08-25):** The rebuilt APK was
  installed and run on Pixel Android 16 through repo-local `./dev/adb` using
  the Linux adb backend.  Plugin hash `58de3b2f...9592484`; final APK hash
  `25f81f74...85c3806`.  Package-scoped VPN baseline was clean
  (`route=0/0 reject=0/0`; host `udp_total=0`).  The `udp-generation-busy`
  guard was active in VPP stdout and prevented same-generation double submit.
  Nevertheless, the registered 1-flow UDP closed echo still failed:
  `runId=101015684203310`, `udpClosedTimeoutMs=1000`, `sent=10 received=0
  errors=10 late=10`; VPP showed `route=18/0`, owner0 `ingress=18 output=17
  residue=0`; the WSL2 echo fixture saw `udp_total=17`.  A harness revision
  made UDP timeouts intent-configurable and a follow-up 5000ms run still failed:
  `runId=93283213967631`, `sent=2 received=0 errors=2 late=2`; VPP showed
  `route=5/0`, owner0 `ingress=5 output=4 residue=0`; host saw `udp_total=4`.
- **Late S169 correction and closure (2026-08-25):** The final missing UDP
  lifecycle piece was in HEV's UDP connector session semantics. The
  owner-context UDP forward path returned terminal status after a protected
  response was written back into lwIP, so OI3 could wake on the fd while HEV had
  no runnable connector task left. The POC now patches HEV so UDP no-frame
  polls are non-terminal and protected UDP responses return a positive
  per-datagram completion without destroying the connector session. Together
  with OI3's `udp_datagram_inflight` latch, this makes one canonical UDP flow
  persistent across many datagrams.
- **S169 device evidence:** Rebuilt hashes: APK
  `c15604413b3cb234a958b42d5c23892228fb4cd2f761af8ce2790e3ce1e48a61`, HEV
  `37481673d6547c5f2a178de04bf4c4b5f60ba6ce1bed7c7cba1cd22b606ac96d`, OI3
  plugin `60243ba744dee0201e99b1d350cde7cfea807dad7933e76f180bffcbac7423ff`.
  The 1-flow run `86632836943396` passed (`sent=834 received=834 errors=0`);
  host `udp_total` increased `3 -> 1253`; VPP repeatedly logged
  `tun-udp-window complete`. The two-owner run `139608275148756` passed
  (`sent=1702 received=1702 errors=0`), with both owners cleaning up `PASS`
  and zero residue.
- **Residual non-claim:** F045 closure is scoped to the tested one-active-flow
  per owner envelope. The historical two-owner 4-flow timeout is owned by
  VPN-F046, not by UDP lifecycle loss; F046 is closed separately by the
  four-owner correction.
- **Status:** `CLOSED_FOR_TWO_OWNER_UDP_CLOSED_ECHO`; remaining 4-flow/E2
  conclusions must use the separate F046 capacity disposition.

### VPN-F046 -- Registered 4-flow closed echo exceeded the two-owner/single-active-flow topology

- **First observation:** After VPN-F045 was corrected, the fresh 4-flow UDP
  closed run `83202807976373` used `sourcePortBase=43100` against the same
  preflighted WSL2 echo fixture. Two flows passed and two flows timed out:
  port `43100` reported `sent=883 received=883 errors=0`; port `43103`
  reported `sent=880 received=880 errors=0`; ports `43101` and `43102` each
  reported `sent=10 received=0 errors=10`.
- **Evidence:** The host fixture was symmetric for admitted traffic
  (`udp_total` increased `1253 -> 3890`). VPP emitted exactly 20 matching
  `oi4 multi-admission result=REJECT ... reason=owner-busy` records, one for
  each failed app send. The rejected hashes were routed to owners that already
  had different active UDP hashes. The two admitted flows continued to emit
  `direct-send`, `tun-output result=OK`, `tun-udp-window complete`, and
  `oi3_cleanup result=PASS`.
- **Control evidence:** A fresh 2-flow control using the documented
  `sourcePortBase=43000` mapped one active flow to each owner and passed:
  `runId=139608275148756`, app `sent=1702 received=1702 errors=0`, host
  `udp_total` increased `3890 -> 6455`, and both owners cleaned up with zero
  residue.
- **Root cause:** HIGH confidence. The previous OI4 Pixel topology hard-coded
  `owner_count = 2`, starts `target-thread-a 1` and `target-thread-b 2`, and
  each owner admits exactly one `active_flow_hash` until the owner idles and
  rearms. A third or fourth simultaneous UDP flow whose hash lands on an
  already-active owner is intentionally rejected as `owner-busy`.
- **POC Correction:** The selected design admits the registered 4-flow cell by
  expanding OI4 to four owner contexts, preserving the existing safety model of
  one active UDP canonical hash per owner. The Android `vpp-oi3-multi` startup
  now starts four workers and passes `target-thread-a 1 target-thread-b 2
  target-thread-c 3 target-thread-d 4`; `show sakamoto-oi3 multi` and VPP
  stdout report four route/reject ledgers.
- **Post-correction evidence:** The rebuilt APK
  `96726fa8e56d74e731105c71568735af338f74fcb06cc067eff00b7525b07179` packaged
  OI3 plugin `b97c57a853a31e0bd7451dd4216519553091954ba45412b3b3def0825dda5951`
  with the unchanged HEV owner-context library
  `37481673d6547c5f2a178de04bf4c4b5f60ba6ce1bed7c7cba1cd22b606ac96d`.
  The Pixel/WSL2 run `127931250090287` used `flows=4`,
  `sourcePortBase=43000`, and `udpClosedTimeoutMs=1000`; app summary was
  `sent=3698 received=3698 errors=0 mismatches=0 unexpected=0 late=0
  reordered=0 fatalFlows=0 executorTimeout=false`. VPP startup logged
  `owners=4`; owner ingress counts were `1366`/`1366`/`1372`/`1395`; four
  owners cleaned up `PASS` with `residue=0`; and F046-specific rejects were
  absent (`owner-busy=0`, `multi-admission result=REJECT=0`).
- **Residual non-claim:** This is a bounded POC capacity closure for the
  registered four-flow UDP closed-echo envelope. It is not a production shard
  count, arbitrary-flow-count proof, soak, or E2 performance result.
- **Status:** `CLOSED_FOR_FOUR_OWNER_UDP_CLOSED_ECHO`; do not reinterpret the
  historical two-owner 4-flow timeout as a UDP lifecycle regression.

### VPN-F047 -- OI3 multi TCP flow timeout was absolute rather than idle

- **First observation:** S171's first corrected-artifact bounded E2 sample
  passed Direct UDP, OI3 UDP and Direct TCP, but failed OI3 TCP 1400B:
  run `34068893509792` reported `sent=186 received=185 errors=1
  fatalFlows=1`, `SocketTimeoutException:Read_timed_out`, cleanup `5/0`,
  `ownerBusy=0`, `multiRejectNonTail=0`, and only same-tuple `tcp-tail`
  rejects.
- **Minimized evidence:** `tcp:1:1400 steady=6` reproduced the failure in
  `evidence/s171-e2-oi3-direct-sample-20260825-tcp-steady6-repeat/`: Direct
  passed 3/3, while OI3 failed 3/3 with `sent=N received=N-1`. Raising the app
  read timeout to 15 seconds in
  `evidence/s171-e2-oi3-direct-sample-20260825-tcp-steady6-timeout15s/` still
  failed 3/3, ruling out a too-short Java timeout. A shorter `steady=3`
  differential passed, showing the payload size was not independently broken.
- **Root cause:** HIGH confidence. `OI3_TUN_FLOW_TIMEOUT_NS` was an absolute
  five-second multi-owner TCP generation lifetime. Active TCP ingress/output did
  not refresh `tun_flow_deadline_ns`; a steady TCP stream crossing that
  boundary could therefore be cleaned up and re-armed while the Java socket was
  still using the same tuple. The re-arm installed the completed tuple
  tombstone and later same-tuple non-SYN packets were rejected as `tcp-tail`.
- **POC Correction:** `owner_inline_oi3.c` now refreshes the TUN flow deadline
  on multi-owner TCP activity and treats FIN/RST as the terminal signal. Static
  coverage is in
  `scripts/tests/test_verify_s171_e2_oi3_direct_sample.py`, including
  `test_oi3_multi_tcp_deadline_is_refreshed_by_activity`.
- **Post-correction evidence:** Rebuilt artifact APK
  `3ba6f24260e2e2dc417e3f150f04ad7a67e6458c26e630e369e623e0dc8f14e4`,
  plugin `6a0fdd9f915be2127ef5cd5423514db836def0ffebd51239178644c8d6a4f643`,
  and HEV
  `37481673d6547c5f2a178de04bf4c4b5f60ba6ce1bed7c7cba1cd22b606ac96d` passed
  `tcp:1:1400 steady=6 repeats=3` in
  `evidence/s171-e2-oi3-direct-sample-20260825-tcp-steady6-after-fix/`, with
  OI3 runs `357/357`, `370/370`, and `371/371`, zero `tcpTailReject`, and
  `failureCount=0`.
- **S171 full sample evidence:** The same rebuilt closure passed
  `evidence/s171-e2-oi3-direct-sample-20260825-after-fix-full/` with Direct and
  OI3 cells for UDP 64B, UDP 4x1400B and TCP 1400B all valid; OI3 TCP run
  `52350053089758` reported `sent=612 received=612`, cleanup `4/0`,
  `ownerBusy=0`, `tcpTailReject=0`, and `multiRejectNonTail=0`.
- **Residual non-claim:** This closes the bounded S171 direct-vs-final-topology
  sample and the TCP idle-timeout hotspot. It does not close matched HEV
  baseline performance, screen-off/Doze, thermal/device-state, broad
  IPv4/IPv6/DNS or final audit evidence.
- **Status:** `CLOSED_FOR_BOUNDED_E2_SAMPLE`.

### VPN-F048 -- Matched HEV E2 baseline requires an explicit comparison APK with tun-poc

- **First observation:** After S171, the next E2 step required a matched
  Direct/HEV/OI3 HTTP baseline on the same WSL2 LAN endpoint. The current
  canonical OI3 APK carried `libhev_external_driver_poc_plugin.so` and
  `libhev-socks5-tunnel.so`, but no `libtun_poc_plugin.so` or
  `tun_poc_plugin.so`.
- **Evidence:** `unzip -Z1` on the canonical APK showed only OI3/HEV members.
  The new S172 runner's default `direct hev oi3` preflight stops before ADB
  with
  `missing_any_apk_member=lib/arm64-v8a/libtun_poc_plugin.so lib/arm64-v8a/tun_poc_plugin.so reason=hev-baseline-tun-poc`;
  raw log:
  `evidence/s172-e2-http-baseline-sample-20260825/run-20260825-125021-144734.log`.
- **Root cause:** HIGH confidence. Android `vpp-hev` is `vppMode=2`, a
  forward/tun-poc path in `vpn_fd_probe.c`; `write_vpp_files()` therefore
  selects `tun_poc_plugin.so`/`libtun_poc_plugin.so`. OI3 modes select
  `libhev_external_driver_poc_plugin.so`. The canonical OI3 APK intentionally
  omitted `tun_poc`, so it is valid for OI3 evidence but not sufficient for a
  matched HEV comparison arm. Before this correction, Java start-outcome
  provenance only marked owner-resolver `vppMode=5` as requiring `tun_poc`,
  which made `vpp-hev` missing-plugin failures too easy to classify as generic
  startup failures.
- **POC Correction:** `SnortVpnService` now marks all tun-poc VPP modes `1..12`,
  including `vpp-hev`, as requiring
  `libtun_poc_plugin.so|tun_poc_plugin.so`. Added
  `scripts/android-run-s172-e2-http-baseline-sample.sh`, which preflights APK
  members before ADB/device work and requires OI3 plugin + owner-context HEV
  plus `tun_poc` when the HEV arm is selected. Static coverage is in
  `scripts/tests/test_verify_s172_e2_http_baseline_sample.py`.
- **Supported claim:** The repeated E2 baseline blockage is a build/runner
  provenance boundary. A valid matched Direct/HEV/OI3 slice requires an
  explicit comparison APK carrying both the selected OI3 plugin and a compatible
  Android arm64 `tun_poc_plugin.so`; VPP `name-filter` keeps the plugin choice
  arm-specific.
- **Non-claim:** This does not close E2 performance/device-state feasibility,
  and it does not change the canonical OI3 result into a tun-poc-bearing
  artifact.
- **Status:** `CLOSED_AS_PREFLIGHT_AND_RUNNER_FIX`. The accepted S172 run later
  used that comparison APK successfully; see VPN-F049 for the follow-up
  HTTP-probe/OI3 admission hotspot. The full E2 matrix remains open.

### VPN-F049 -- S172 duration-only HTTP baseline exposed OI3 TCP admission-before-tombstone and owner-busy limits

- **First observation:** After the comparison APK was built, S172's
  Direct/HEV/OI3 runner still failed in the OI3 arm. The first failed device
  comparison run had OI3 `requests=2 successes=2 errors=0` but
  `cleanup=4/1`; the next run after the admission fix had `cleanup=4/0` but
  `requests=2 successes=1 errors=1`.
- **Evidence:**
  - `evidence/s172-e2-http-baseline-sample-20260825/cells-20260825-130051-110628.csv`
    captured the cleanup failure after successful OI3 HTTP bytes.
  - `evidence/s172-e2-http-baseline-sample-20260825/cells-20260825-131000-916301.csv`
    captured the duration-only owner-busy shape after cleanup was fixed.
  - Accepted run:
    `evidence/s172-e2-http-baseline-sample-20260825/cells-20260825-131542-644207.csv`
    with `failureCount=0`.
- **Root cause:** HIGH confidence. The first failure was an OI3 lifecycle race:
  while a successful TCP flow was entering teardown, multi-owner admission still
  accepted same-flow FIN/ACK tail packets before the completed tuple tombstone
  was published. That created a FIN-only generation with no output and produced
  `oi3_cleanup result=FAIL`. After that was fixed, the remaining failure was a
  POC design mismatch: a duration-only stream probe generated a second request
  while the previous OI3 owner was still active, so a same-owner SYN was
  correctly rejected as `owner-busy`. That is a capacity/throughput condition,
  not a matched single-request HTTP baseline.
- **POC correction:** `owner_inline_oi3.c` now closes owner-local multi
  admission at the start of `oi3_finish_for()` and reopens it only after
  `oi3_rearm_tun_flow()` has published the tombstone/wait-SYN state.
  `SnortVpnService`'s app HTTP stream probe now parses `Content-Length`,
  exits the read loop as soon as the body is complete, records
  `contentLengthCompletions`, and supports the existing `count` extra as a
  request cap. S172 now defaults `MAX_REQUESTS=1`, passes `--ei count`, waits
  for OI3 `STOPPED`/four cleanup lines, normalizes zero-match counts, and
  requires `contentLengthCompletions == successes`.
- **Supported claim:** The bounded S172 Direct/HEV/OI3 matched HTTP baseline
  construction slice passes on Pixel 6a / Android 16 with comparison APK
  `67f16c3a045c0a786e49ecb1f99a7a6496080ea0761404447c04434617880a94`, OI3
  plugin
  `96e0e9f4cbf61fa2216c2ecff2e0ed568a98f966f0ef3b9f647cc74c92381806`,
  `tun_poc`
  `4f5608a631215a622b60bb72026edb6a8743011ed2c7d5ede9e1243a3844b0cd`, and
  HEV owner-context library
  `37481673d6547c5f2a178de04bf4c4b5f60ba6ce1bed7c7cba1cd22b606ac96d`.
- **Non-claim:** This is not an OI3 throughput/capacity result and does not
  close full E2 performance/device-state feasibility. Multi-request,
  multi-owner HTTP throughput requires a separate capacity-aware design.
- **Status:** `CLOSED_FOR_MATCHED_HTTP_BASELINE_SLICE`; full E2 remains open.

### VPN-F050 -- S173 foreground HTTP staircase exposed OI3 deterministic-owner single-active TCP successor-SYN capacity cliff

- **First observation:** After S172 accepted the one-GET matched HTTP baseline,
  a 4-request foreground HTTP staircase passed Direct and HEV but failed OI3 at
  `3/4`.
- **Initial evidence:** `cells-20260825-132911-843206.csv` showed Direct `4/4`,
  HEV `4/4`, and OI3 `requests=4 successes=3 errors=1`. Hash-quality-only
  correction to `fnv1a+mix` improved distribution but did not close the
  staircase: unpaced `cells-20260825-135431-402507.csv` and 6s-paced
  `cells-20260825-135602-091258.csv` both remained OI3 `3/4` with VPP
  `owner-busy` SYN rejects.
- **Root cause:** HIGH confidence. OI3 multi-owner selection is deterministic
  `hash % owner_count`; it is not an idle-owner allocator. Each owner admits
  one active TCP generation. A new sequential HTTP TCP connection can therefore
  hash to an owner whose previous generation has not finished teardown/re-arm.
- **POC correction:** The selected fix preserves canonical owner selection
  instead of moving the flow to another owner. `owner_inline_oi3.c` now carries
  busy successor SYN packets as `OI3_TUN_DEFERRED_KIND`, deduplicates them in a
  bounded owner-local `multi_deferred[]` queue, forces a completed active owner
  toward bounded stop/re-arm, and promotes one deferred SYN after
  `oi3_rearm_tun_flow()` publishes the completed generation's tombstone/wait
  state. Normal admission rolls back active-flow reservation on enqueue failure
  (`admission-rollback`), late non-SYN tail is classified as
  `tcp-non-syn-busy`, and TCP pending tail is cleared at re-arm
  (`tcp-rearm-stale-tail`) so stale packets cannot enter the next deferred
  successor context.
- **Intermediate defect found and closed:** OI3 repeat=5 run
  `cells-20260825-142114-146880.csv` had one failing repeat after the first
  deferred-SYN fix. Its VPP log showed `pending=2` at deferred promotion and
  cleanup `FAIL ... output=1 direct=0`, proving stale pending tail could be
  mixed into the next generation. The `tcp-rearm-stale-tail` correction closes
  that sub-defect.
- **Closure evidence:** Final OI3 plugin
  `9282f8c82c5223e2c7b144f85a2533100df646ec821ff0ef91737b9ef8a85186` in APK
  `441b0279e2685d0d89b6092ce00f64e49742a1fcfaaf691611c826a20fca97c4`.
  OI3 repeat=5 run
  `evidence/s172-e2-http-baseline-sample-20260825/cells-20260825-142858-176008.csv`
  passed all five cells with `requests=4 successes=4 errors=0`,
  `contentLengthCompletions=4`, cleanup `8/0`, `valid=1`, and `failures=0`;
  every repeat hit `owner-busy-deferred` and `multi-deferred admit`.
  Matched Direct/HEV/OI3 run
  `cells-20260825-143509-282679.csv` passed Direct `4/4`, HEV `4/4`, and OI3
  `4/4`, all `valid=1`, with OI3 cleanup `8/0` and two deferred successor-SYN
  promotions.
- **Non-claim:** This closes only the bounded S173 4-request foreground HTTP
  staircase slice. It is not a general TCP pool, throughput, soak, thermal, or
  power proof.
- **Status:** `CLOSED_FOR_BOUNDED_HTTP_STAIRCASE_SLICE`. Continue remaining
  E2 work; record any new architecture cliff as a separate finding instead of
  reopening F050.

### VPN-F051 -- S176 concurrent UDP flows collided on a busy deterministic primary owner despite idle capacity

- **First observation:** The post-S175 final APK passed Direct UDP/TCP, OI3
  single-flow UDP, and OI3 TCP, but the OI3 four-flow UDP closed-echo cell
  failed twice. Evidence
  `evidence/s176-e2-l4-udp-tcp-final-apk-20260825/cells-20260825-152536-302639.csv`
  recorded OI3 UDP4 `1888/1878` and `1897/1887`, ten app errors in each
  repeat, `ownerBusy=11`, `multiRejectNonTail=11`, and manifest
  `failureCount=2`.
- **Root cause:** HIGH confidence. OI3 multi-owner selection was deterministic
  `hash % owner_count`. For concurrent UDP, one flow hashed to a primary owner
  already active for a different UDP hash while another owner was idle. Unlike
  TCP successor SYNs, distinct UDP datagram flows can be assigned to an idle
  owner if the selected owner is recorded in a bounded flow-route table and all
  later datagrams for that flow follow the pinned route.
- **POC correction:** `owner_inline_oi3.c` now adds bounded UDP flow-route
  pinning (`OI3_MULTI_FLOW_ROUTE_CAPACITY=16`). UDP route lookup runs before
  canonical owner modulo; if the UDP primary owner is busy for a different
  hash, `oi3_multi_udp_idle_owner()` may select an idle owner and
  `oi3_multi_flow_route_insert()` pins that route. TCP remains on the S173/F050
  canonical-owner deferred-admission path. Static verifier coverage includes
  `test_udp_multi_flow_uses_idle_owner_route_pinning`.
- **Build-provenance correction:** The accepted Android plugin was built from
  the clean product Android VPP build/source, not from the mutable
  `work/vpp-android-configure-probe` tree that still carried the rejected P6
  conditional-wake ABI. The accepted plugin has no
  `vlib_frame_queue_wakeup_mode` dependency and was packaged with
  `work/android-hev-poc7-stage`.
- **Closure evidence:** Accepted APK
  `f4e350c6478ce9f495afa9b1b97f174c79915592a461aeb25d7e8cdd803e1541`, OI3
  plugin
  `5012eeecb16828edca58f3dc98ddd52330a3b09b26394a3baa94b7c39604cc72`, and
  HEV owner-context library
  `37481673d6547c5f2a178de04bf4c4b5f60ba6ce1bed7c7cba1cd22b606ac96d`.
  Minimal route-pinning regression
  `evidence/s176-e2-l4-udp4-f4-route-pinning-cleanabi-20260825/cells-20260825-155119-253253.csv`
  passed both OI3 UDP4 repeats (`2504/2504`, `2483/2483`) with cleanup `8/0`,
  `ownerBusy=0`, `multiRejectNonTail=0`, and `failureCount=0`; logs contain
  `reason=udp-idle-owner` and `route-pinned=1`. Full S176
  `evidence/s176-e2-l4-udp-tcp-route-pinning-cleanabi-20260825/cells-20260825-155427-072214.csv`
  passed all 12 Direct/OI3 UDP/TCP cells with `failureCount=0`. OI3-only
  16-request HTTP regression
  `evidence/s176-s175-http16-oi3-route-pinning-cleanabi-20260825/cells-20260825-160228-023067.csv`
  passed both repeats at `16/16`, cleanup `20/0`, and `failureCount=0`.
- **Non-claim:** This closes only the bounded four-owner UDP route-pinning
  slice plus the OI3 HTTP16 regression. It does not prove arbitrary flow count,
  UDP throughput, IPv6/DNS, browser/multi-app traffic, CPU/thermal/power,
  Doze, long-soak, or final EG-17 performance readiness.
- **Status:** `CLOSED_FOR_BOUNDED_UDP_MULTI_FLOW_ROUTE_PINNING_SLICE`.

### VPN-F052 -- S177 resource runner treated transient WSL/ADB transport and blocking log reads as target evidence

- **First observation:** The post-S176 E1 resource slice repeatedly failed or
  stayed incomplete before it could produce a valid CSV/manifest. Evidence
  directories `s177-e1-e2-final-short-resource-20260825`,
  `s177-e1-final-resource-short-20260825`, and
  `s177-e1-final-resource-short2-20260825` stopped during APK install,
  startup/preflight, or interrupted cleanup with WSL
  `UtilAcceptVsock: accept4 failed 110` / incomplete manifest symptoms.
- **Root cause:** HIGH confidence. These were harness/environment failures, not
  OI3 dataplane failures. S170 still hard-coded old S169 artifact expectations
  in provenance, `wait_vpp_ready` directly grepped VPP log paths that can block
  on-device, and one transient `adb_su`/WSL transport failure caused immediate
  `set -e` exit instead of bounded retry.
- **POC correction:** S170 provenance now defaults `apk_expected`,
  `plugin_expected`, and `hev_stage_expected` to the currently packaged
  artifact hashes while retaining `S170_EXPECTED_*` overrides for historical
  reruns. `wait_vpp_ready` reads only regular log files through bounded
  `tail -n 80 | grep`, and `adb_read` has a bounded retry loop that preserves
  the caller's `errexit` state.
- **Closure evidence:** Static verifier coverage added
  `test_wait_vpp_ready_does_not_block_on_log_paths` and
  `test_adb_read_has_bounded_retry_for_wsl_transport_flakes`; S170/S171
  verifier run passed 10 tests. Accepted run
  `evidence/s177-e1-final-resource-short3-20260825/` recorded run
  `20260825-163352-816347`, two cycles, `failureCount=0`, fixture
  `2008/2008`, cycle 1 `763/763 errors=0`, cycle 2 `784/784 errors=0`,
  cleanup `4/0` in both cycles, stable fd/thread counts, thermal status `0`,
  and final artifact hashes matching S176.
- **Non-claim:** This closes the S170/S177 runner-validity hotspot and supports
  a short foreground resource slice. It does not prove Doze, long soak,
  matched CPU/latency/throughput budgets, IPv6/DNS breadth, or the final
  EG-17/EG-18 verdict.
- **Status:** `CLOSED_FOR_HARNESS_RETRY_AND_NONBLOCKING_LOG_READ`.

### VPN-F053 -- S178 B1 runner conflated dataplane proof with lifecycle cleanup-marker timing

- **First observation:** S178 B1 dual-stack DNS reruns on the current final
  artifact produced valid AppA DNS responses and native dataplane markers, but
  early runner verdicts still failed or stayed ambiguous because they mixed
  post-response lifecycle marker timing, `tun0` residue probing, and source-port
  reuse symptoms into the same pass/fail bucket.
- **Root cause:** HIGH confidence.  The hotspot was runner/POC design, not a
  demonstrated IPv4/IPv6 DNS dataplane failure.  `su ip link show tun0` can
  return success with empty output on this device, so exit-code-only residue
  checks were false positives.  Force-stopping the app/VPN immediately after
  AppA returned could miss late `oi3_cleanup result=` markers.  Reusing fixed
  TCP source ports across reruns could produce local `Address not available`
  failures unrelated to owner-inline routing.
- **POC correction:** S178 now detects `tun0` by captured output text, adds a
  bounded native settle window and regular-file cleanup-marker tail, chooses a
  dynamic default source-port base while retaining overrides, and splits
  verdicts between full lifecycle `PASS` and
  `PASS_DATAPLANE_CLEANUP_MARKER_MISSING`.
- **Closure evidence:** Static verifier
  `test_verify_s178_b1_final_dualstack_dns.py` guards the runner/verdict split.
  Accepted run
  `evidence/s178-b1-final-dualstack-dns-20260825/` recorded run
  `20260825-170934-541913` against VPN APK
  `f4e350c6478ce9f495afa9b1b97f174c79915592a461aeb25d7e8cdd803e1541`
  and AppA APK
  `c6d0e744c4c506b26dfd635f2798a11382aff2969bce9fc5d2f6a137f9154731`.
  Six IPv4/IPv6 UDP/TCP DNS cells all had AppA DNS success, valid 61-byte
  responses, native direct/broker/TUN-output markers, `appValid=1`,
  `nativeValid=1`, `valid=1`, and zero post-run `vpp`/`tun0` residue.
  Manifest status was `PASS_DATAPLANE_WITH_CLEANUP_MARKER_GAPS` with
  `cellsRecorded=6`, `passCount=3`, `cleanupMarkerGapCount=3`,
  `failureCount=0`, `appValidCount=6`, and `nativeValidCount=6`.
- **Non-claim:** This closes the S178 B1 dataplane-vs-cleanup-marker POC
  hotspot and supports current-artifact dual-stack DNS dataplane.  It does not
  close TCP lifecycle cleanup-marker timing for the three marker-gap rows,
  forced large-response DNS fallback, arbitrary external traffic, throughput,
  CPU/thermal/power, Doze, long soak, or final E2/E1 readiness.
- **Status:** `CLOSED_FOR_DATAPLANE_LIFECYCLE_SPLIT`.

### VPN-F054 -- S180 B1 fallback could not be proven by independent UDP and TCP DNS probes

- **First observation:** After S178, B1 still listed large-response/forced DNS
  fallback as open.  The current AppA B1 helper could send a supplied DNS
  payload over UDP or TCP and validate a response, but it had no resolver
  fallback state machine.  Treating separate UDP and TCP cells as forced
  fallback would overstate the evidence.
- **Root cause:** HIGH confidence.  The missing seam was in the POC helper and
  runner design, not in the owner-inline dataplane.  A valid fallback proof
  needs one operation where UDP receives a trigger (`TC=1`) and the same query
  is retried over TCP, with app and endpoint evidence joined by query ID.
- **POC correction:** AppA now supports explicit
  `b1FallbackTcpOnTruncated=true` and `b1FallbackTcpSourcePort`.  S180 starts a
  WSL2/LAN DNS fixture that returns UDP `TC=1` and a TCP full response for the
  same query ID.  The runner rejects independent UDP/TCP requests as fallback
  evidence and requires AppA fallback fields plus fixture, native and residue
  proof.
- **Closure evidence:** Accepted run
  `evidence/s180-b1-dns-fallback-20260825/` recorded run
  `20260825-173925-730529` against VPN APK
  `f4e350c6478ce9f495afa9b1b97f174c79915592a461aeb25d7e8cdd803e1541`
  and AppA APK
  `24eb2af558fdb44a300e86a08643125b048c3d31b14ca9272cebc0674a2d3a88`.
  Fixture `192.168.4.5:53535` recorded UDP query `1234`, UDP truncated
  response `1234`, TCP query `1234`, and TCP full response `1234`.  AppA
  recorded `fallback_attempted=true`, `fallback_reason=udp_tc`,
  `udp_truncated=true`,
  `return_outcome=dns_tcp_fallback_response_received`,
  `fallback_return_outcome=dns_response_received`, and
  `tcp_response_valid=true`.  Native evidence recorded `brokerSuccess=2`,
  `tunOutput=4`, `directSend=2`, cleanup `1/0`, `failureCount=0`, and zero
  post-run `vpp`/`tun0` residue.
- **Non-claim:** This closes only the bounded IPv4 WSL2/LAN forced-TC fallback
  cell.  It does not prove public resolver fallback behavior, IPv6 fallback,
  arbitrary large DNS responses, throughput, CPU/thermal/power, Doze, or long
  soak.
- **Status:** `CLOSED_FOR_REAL_FALLBACK_HELPER_AND_FIXTURE`.

### VPN-F055 -- S181 WSL2 closed TCP port was not a stable real-refusal fixture through Android VPN/OI3

- **First observation:** The S181 full-device B2 runner originally treated an
  unbound WSL2/LAN TCP port as a real transport-refusal cell and passed
  `oi3ExpectedFailure=real-refused`.  Latest pre-correction evidence
  `evidence/s181-b2-full-device-transport-explore-20260825/` run
  `20260825-182316-640498` proved the parameter path and multi-owner
  environment were working, but the cell still failed: AppA saw
  `tcp_connect_succeeded/dns_response_timeout`, OI3 recorded broker/protect
  success, TUN output and return rewrite, but no transport-failure event or
  endpoint refusal.
- **Root cause:** HIGH confidence POC-design mismatch.  In this topology the
  Android VPN/OI3 TCP proxy can complete the app-facing handshake before the
  protected underlay destination produces a result.  A merely unbound WSL2/LAN
  TCP port did not produce a deterministic native refusal/RST/`ECONNREFUSED`
  signal at the OI3 cleanup boundary.  Treating that fixture as
  `EXPECTED_REAL_TRANSPORT_REFUSAL` overstated the evidence.
- **POC correction:** S181 now names the third cell
  `closed-tcp-timeout`, does not pass `real-refused`, and requires the
  behavior actually observed on the full-device path: AppA TCP connect
  succeeds locally, DNS read times out, native broker/protect/TUN-output/
  handshake/rewrite markers are present, direct-send is absent, transport and
  infrastructure failure counters are zero, and cleanup is
  `PASS_EXPECTED_AMBIENT_TIMEOUT` / `EXPECTED_TIMEOUT`.  Static regression
  `test_verify_s181_b2_full_device_transport.py` prevents reverting the cell
  to a refusal claim without a deterministic reset/refusal fixture.
- **Closure evidence:** Accepted run
  `evidence/s181-b2-full-device-transport-explore-20260825/` /
  `20260825-183033-563849` passed all three cells on VPN APK
  `70f14dc28ec102175bb6eddd31f83b2aec6efd27942c18a72450b36e8c66ce31`
  and AppA APK
  `24eb2af558fdb44a300e86a08643125b048c3d31b14ca9272cebc0674a2d3a88`.
  Positive UDP DNS passed with `EXPECTED_DIRECT_REPLY`; real UDP no-reply
  passed with `PASS_EXPECTED_REAL_NO_REPLY` / `EXPECTED_REAL_NO_REPLY`; and
  `closed-tcp-timeout` passed with `PASS_EXPECTED_AMBIENT_TIMEOUT` /
  `EXPECTED_TIMEOUT`.  All cells had `appValid=1`, `fixtureValid=1`,
  `nativeObserved=1`, `nativeExpected=1`, `failureCount=0`, and zero post-run
  `vpp`/`tun0` residue.
- **Non-claim:** This does not prove real external RST/`ECONNREFUSED`
  behavior, policy drop, bind/protect failure, infrastructure failure, public
  Internet behavior, production timeout constants, performance, Doze, or long
  soak.  A real-refusal claim requires a deterministic refusal/reset fixture
  and an observed native refusal signal.
- **Status:** `CLOSED_FOR_REAL_TCP_TIMEOUT_DESIGN_CORRECTION`.

### VPN-F056 -- S182 representative real policy drop needs an OI3 dispatcher seam, not Android app exclusion

- **First observation:** After S181, B2 still needed a representative real
  policy-drop slice on the full-device OI3 multi path.  Android
  `addDisallowedApplication()` would route AppA outside the VPN and therefore
  could not prove that owner-inline policy stops a packet before broker/socket
  transport.  The existing `blockOwnerUid` gate was also not available in
  `vpp-oi3-multi`.
- **Root cause:** HIGH confidence POC seam gap.  Policy drop must be observed
  inside the selected OI3 multi dispatcher path, before tuple hashing, owner
  admission, TUN queueing, FlowStackOwner creation, or Android bind/protect
  brokerage.  A pre-owner drop has no owner cleanup generation; requiring an
  `oi3_cleanup` marker would be the wrong proof shape for this seam.
- **POC correction:** `vpp-oi3-multi` now accepts a POC-only
  `SAKAMOTO_OI3_POLICY_DROP_IP4` value passed from the existing
  `blockIp4Dst` intent extra.  Matching IPv4 packets are dropped in
  `oi3_multi_tun_read_ready()` before owner lookup/admission and log
  `oi4 multi-policy-drop result=DROP stage=pre-owner ... no-transport=1
  broker=0 socket=0`.  S182 runs only a positive control plus the
  policy-drop cell so it does not depend on unrelated S181 timeout cleanup
  markers.
- **Closure evidence:** Accepted run
  `evidence/s182-b2-real-policy-drop-20260825/` /
  `20260825-190147-303631` passed both cells on VPN APK
  `804a69734de9ceb2bc6f91c15fb8b09d3df8517b3bc7562c63a8379967b87a96`
  and AppA APK
  `24eb2af558fdb44a300e86a08643125b048c3d31b14ca9272cebc0674a2d3a88`.
  The policy-drop fixture was ready on `192.168.4.5:53544` and recorded no
  packet.  AppA recorded `udp_datagram_sent/dns_response_timeout`; native
  recorded `policy-drop-ip4=192.168.4.5` and the pre-owner DROP marker;
  verifier CSV recorded `brokerSuccess=0`, `tunOutput=0`, `directSend=0`,
  `transportFailures=0`, `infrastructureFailures=0`, `policyDrop=1`,
  `failure_count=0`, and zero post-run `vpp`/`tun0` residue.
- **Non-claim:** This closes only the representative target-IP policy-drop
  slice on the selected full-device OI3 multi path.  It does not prove
  per-App UID drop, Android UID lifecycle/cache convergence, deterministic
  RST/`ECONNREFUSED`, bind/protect failure, infrastructure failure, IPv6,
  public Internet behavior, production policy authoring, performance, Doze, or
  long soak.
- **Status:** `CLOSED_FOR_PRE_OWNER_POLICY_DROP_SLICE`.

### VPN-F057 -- S183 OI3 UID gate treated async owner-lookup sentinel as terminal

- **First observation:** S183 first valid device run
  `evidence/s183-b2-real-uid-drop-20260825/` /
  `20260825-191707-411618` proved that the new native TUN gate was wired into
  `vpp-oi3-multi`, but it forwarded the AppA UDP packet with
  `ownerUid=-1 cached=0`.  The WSL2 fixture then received the supposedly
  dropped query on `192.168.4.5:53545`, and OI3 created a broker/socket path.
- **Root cause:** HIGH confidence POC seam bug.  `UidAttributionContract.lookup()`
  is sentinel-first by design: the first lookup submits bounded async Android
  `ConnectivityManager.getConnectionOwnerUid()` work and returns
  `INVALID_UID`; a later lookup observes `COMPLETION_ACCEPTED` as a cache hit.
  The legacy native gate treated the first `uid=-1` sentinel as a terminal
  policy fact and therefore made the policy decision too early.
- **POC correction:** `vpp-oi3-multi + blockOwnerUid>=0` now reuses the native
  TUN gate, while legacy HEV/shim startup remains limited to the old
  `vpp-hev-owner-gate` mode.  The gate calls
  `query_owner_uid_with_bounded_wait()` before applying UID policy: it submits
  the first lookup, waits briefly for the async completion to populate the
  scoped cache, retries the same canonical key, and logs
  `lookup-attempts=N` with the final decision.  The S183 runner records
  `uid-attribution-contract.jsonl` alongside the owner-gate, AppA, fixture and
  native logs.
- **Closure evidence:** Accepted run
  `evidence/s183-b2-real-uid-drop-20260825/` /
  `20260825-192207-202830` passed both cells on VPN APK
  `a222fd3a82993903aa67f1f377b0787891556ee72036c682719597663c2fd12c`
  and AppA APK
  `24eb2af558fdb44a300e86a08643125b048c3d31b14ca9272cebc0674a2d3a88`.
  The UID-drop cell used AppA UID `12630`; AppA recorded
  `udp_datagram_sent/dns_response_timeout`; the UID contract recorded
  `MISS_SUBMITTED -> COMPLETION_ACCEPTED uid=12630 -> CACHE_HIT uid=12630`;
  the owner gate logged
  `gate drop ... ownerUid=12630 cached=0 lookup-attempts=2`; the fixture was
  ready on port `53545` and recorded no `uid_drop_udp_query`; verifier CSV
  recorded `gateDrop=2`, `gateForward=0`, `policyDrop=0`,
  `transportFailures=0`, `failure_count=0`, and zero post-run `vpp`/`tun0`
  residue.
- **Non-claim:** This closes only a representative full-device AppA UID-drop
  slice at the native TUN gate before OI3 multi broker/socket creation.  It is
  not a VPP-internal UID policy proof, not a production nonblocking/capacity
  design, not complete UID lifecycle/cache convergence, not a distinct-App
  IPv4/IPv6 matrix, and not evidence for public Internet, performance, Doze,
  or long soak.
- **Status:** `CLOSED_FOR_BOUNDED_UID_GATE_SLICE`.

### VPN-F058 -- S184 real LAN TCP RST propagation seam

- **Observation:** S184's bounded full-device run waited for the fixture's
  `tcp_timeout_port_unbound` event, then bound a TCP listener with
  `SO_LINGER(1, 0)`.  The fixture recorded one accepted connection and one
  `tcp_rst_sent` event for AppA peer `192.168.4.151:45954`.  The positive UDP
  control in the same run passed.
- **Evidence:**
  `evidence/s184-b2-real-rst-20260825/` /
  `20260825-193618-437793`; fixture log hash
  `d5168de02790a01af588f8008052ce1befa2e8a88c85250bb44895c0e778bf03`;
  machine summary hash
  `cd432602b4aadd8200d60805876df2e9e94661f55b7445384ba7daed4d11b3bf`.
- **Original root cause:** HIGH-confidence observation-seam gap.  The AppA record remained
  `tcp_connect_succeeded/dns_response_timeout`.  Native recorded
  `output=1 handshake=1 rewritten=1 direct=0`, but
  `transport-failures=0 connector-error=0 reported=0`; no reset/error event
  was joined to the owner generation.  The TUN packet's real-flow cell is
  ordinary `TCP4`, so the bounded `OI3_CELL_REFUSED` probe is not entered.
  Cleanup then emitted `result=FAIL outcome=EXPECTED_REAL_TRANSPORT_REFUSAL`
  with `error=unexpected-real-refused`, while `buffers=12/12 residue=0` and
  infrastructure failures remained zero.
- **Owner-event correction:** Rebuilt run
  `evidence/s184-b2-real-rst-owner-event-20260825/` /
  `20260825-203915-342533` moved exact socket-result publication into the HEV
  session that owns `readv`/`writev`, on owner 2 and generation 1.  It recorded
  exactly one `READ_ERROR errno=104 Connection reset by peer`,
  `transport-failures=1`, `reported=1`, `reset-observed=1`, `peer-eof=0`, and
  zero infrastructure failures.  Fixture connection/RST evidence and the UDP
  control were valid.  This closes the observation half of the finding.
- **Downstream root cause:** The protected-side payload had already been sent,
  so `direct=1` is valid and the prior `direct=0` reset oracle was wrong.
  AppA still timed out because owner-context `tcp_abort_ctx()` is implemented
  as silent `tcp_close_ctx()` purge/free.  Native emitted SYN-ACK and ACK but
  no downstream RST/FIN before teardown.  Thus upstream `ECONNRESET` is not
  represented on the TUN-side TCP session.
- **Correction and accepted evidence:** Added the narrow owner-local
  `tcp_send_reset_ctx()` operation and invoked it once only for exact HEV
  `ECONNRESET`, before ordinary PCB teardown.  The bounded rerun
  `evidence/s184-b2-real-rst-downstream-reset-20260825/` /
  `20260825-210129-290257` recorded one owner `READ_ERROR errno=104`, one
  downstream `RST|ACK`, AppA `tcp_payload_sent/dns_response_reset` with
  `Connection reset`, `PASS_EXPECTED_REAL_RESET`, `transport-failures=1`,
  `downstream-reset-observed=1`, `infrastructure-failures=0`, and
  `buffers=7/7 residue=0`; no VPP/tun0 residue remained.
- **Verifier pit:** The old summarizer read `native-combined.log`, which already
  embeds `vpp-stdout.log`, and then read `vpp-stdout.log` again.  Its derived
  CSV/manifest therefore counted the single reset twice and returned a false
  `FAIL`.  The parser now uses event presence plus the authoritative once-only
  cleanup counters.  Raw evidence was not rewritten and no device rerun was
  spent on this verifier-only defect.
- **Interpretation:** This is neither policy drop, bind/protect failure, nor
  infrastructure failure.  It proves a post-SYN reset fixture can be reached,
  but the current connector/event seam cannot distinguish that reset from a
  timeout without inventing a refusal verdict.
- **Boundary:** The correction does not globally turn teardown aborts into
  wire-visible RST and does not accept timeout, EOF, or silent purge as reset.
  It supports only the bounded controlled post-SYN LAN reset slice, not
  pre-connect `ECONNREFUSED`, public-Internet behavior, arbitrary TCP teardown,
  production timeout constants, Doze, or long soak.
- **Status:** `CLOSED_FOR_BOUNDED_REAL_RST_SLICE`; the S184 hotspot stop is
  lifted.  Full details: `S184_B2_REAL_RST_HOTSPOT.md`.

### VPN-F059 -- S185 bind/protect/broker infrastructure failure oracle

- **First observation:** S185 initially had the same visible App surface for
  all target cells: `udp_datagram_sent/dns_response_timeout`.  Without a
  phase-specific native oracle, bind failure, protect failure, broker
  unavailable, policy drop, no-reply, and transport timeout can all collapse
  into the same app-level timeout.
- **Root cause:** HIGH confidence POC-oracle gap.  The infrastructure branch is
  pre-connector but not monolithic.  A bind failure should attempt bind and
  stop before protect; a protect failure should bind, attempt protect, and stop
  before transport; broker unavailable should not attempt bind or protect at
  all.  Reusing one “broker failed” assertion either over-accepts the wrong
  phase or rejects a valid phase-specific result.
- **POC correction:** OI3 now maps `oi3ExpectedFailure=bind-failure`,
  `protect-failure`, and `broker-unavailable` to exact OI2 broker request
  flags and completion enums.  The classifier requires exact broker result,
  exact bind/protect phase counts, zero TUN output, zero Direct send, zero
  fixture query, zero transport failure, one infrastructure failure, and exact
  settlement.  The S185 wrapper enables only the positive UDP DNS control and
  the three infrastructure cells.
- **Closure evidence:** Accepted run
  `evidence/s185-b2-infrastructure-failures-20260825-run1/` /
  `20260825-213903-524622` passed all four cells on VPN APK
  `5ab5ef07e178ee4e0f613c7d7b231b355088953a1e517fc075ffb1a72baaaf8a`,
  AppA APK
  `05a6081804235ba8618cd1d27f329c9e7080161661f8144fd6034388acc9b24c`,
  OI3 plugin
  `2ad3068daa32aa788933bb947f0f09cfed52b283e9bae72fd222772022d6fe89`,
  and HEV
  `420e67e71029888c3d6423b24a513bf6ed760fd159762903f22ee4235d016466`.
  The run recorded `pass_count=4`, `failure_count=0`, no design gaps, and
  zero post-run `vpp`/`tun0` residue.  Native CSV rows recorded
  `EXPECTED_BIND_FAILURE` with `brokerInfra=1/0/0`,
  `EXPECTED_PROTECT_FAILURE` with `brokerInfra=0/1/0`, and
  `EXPECTED_BROKER_UNAVAILABLE` with `brokerInfra=0/0/1`; all failure cells
  had `transportFailures=0` and `infrastructureFailures=1`.
- **Non-claim:** This closes only bounded infrastructure-failure separation on
  the selected full-device AppA/OI3 multi path.  It is not policy-drop,
  post-connect transport failure, pre-connect `ECONNREFUSED`, public-Internet,
  production capacity, production timeout, Doze, soak, or complete distinct-App
  evidence.
- **Status:** `CLOSED_FOR_BOUNDED_INFRA_FAILURE_SLICE`.  Full details:
  `S185_B2_INFRASTRUCTURE_FAILURE_EXECUTION.md`.

### VPN-F060 -- S152 residual A2 UID matrix needs controlled tuple and stage oracle

- **First observation:** The S152 A2-1 rerun
  `evidence/s152-a2-1-two-app-20260825-dualplugin-rerun1/` was
  `INCONCLUSIVE`: setup, dual App UIDs, native start, eight App runtime
  records, and cleanup passed, but only 5/8 registered tuples joined to native
  owner-resolver evidence.
- **Root cause:** HIGH confidence POC-design gap plus harness defect.  The
  runner used public `1.1.1.1` and Cloudflare IPv6 endpoints as the tuple
  source.  Three TCP tuples failed in the App socket layer before native
  resolver evidence: AppA IPv4/TCP `45641` and AppA IPv6/TCP `45643` returned
  `Address not available`, while AppB IPv4/TCP `45651` returned
  `ECONNREFUSED`.  The runner also failed to pass an A2-1 UID contract stage,
  so native resolver and Java UID contract rows were labelled
  `cell=A2-4 stage=startup`.
- **Evidence boundary:** The valid parts prove only that the device, dual App
  packages, allowed UID scope, and some UDP/AppB IPv6 TCP resolver joins were
  reachable in that run.  They do not prove the complete two-App IPv4/IPv6
  TCP/UDP matrix, lifecycle refresh/recovery, reverse attribution, or UID-drop
  zero-broker/socket behavior.
- **Required POC correction:** Replace public endpoints with controlled
  WSL2/LAN fixtures for the registered IPv4/IPv6 TCP/UDP tuples; pass the
  exact A2-1 cell/stage through App, Java UID contract, native resolver,
  manifest, and verifier; and reject tuple-only resolver matches from another
  cell or `startup`.  Rerun only the smallest A2-1 resolver-join slice before
  adding lifecycle or drop variants.
- **Correction evidence:** S155 implemented the controlled WSL2/LAN fixture,
  A2-1 `uidContractStage`, exact stage-aware verifier, and VpnLite/AppA/AppB
  installed-hash provenance.  The run1 stage-arm harness defect was corrected
  by commit `cef24fb`, and rerun2 proved all eight exact `STAGE_BEGIN` records
  with `cell_id=A2-1`.
- **Status:** `CLOSED_AS_POC_DESIGN_FIX`.  The original public-endpoint/startup
  oracle defect is closed, but the corrected matrix exposed successor finding
  `VPN-F061`.  Full details:
  `S152_A2_UID_LIFECYCLE_DESIGN_GAP.md` and
  `S155_A2_UID_MATRIX_RERUN2_RESOLVER_CORRELATION_GAP.md`.

### VPN-F061 -- S155 controlled A2-1 matrix exposed TCP owner-lookup and per-flow stage-correlation gap

- **First observation:** The corrected S155 A2-1 rerun
  `evidence/s155-a2-1-fixture-stage-20260825-run2/` was valid but
  `INCONCLUSIVE`: artifact/device/fixture readiness, dual App UIDs, installed
  APK hashes, native VPP start, allowed UID scope, eight runtime records, eight
  exact `STAGE_BEGIN` records, VPN handle, and cleanup all passed, but only 3/8
  registered tuples produced decisive native resolver + UID contract joins.
- **Observed split:** AppA IPv4/UDP `45642`, AppA IPv6/UDP `45644`, and AppB
  IPv4/UDP `45652` passed with correct UIDs.  AppA/AppB IPv6 TCP produced
  repeated `LOOKUP_UNAVAILABLE` / `android-api-invalid-uid` completions.  AppA
  and AppB IPv4 TCP had runtime records but no decisive resolver/contract join.
  AppB IPv6 UDP had a Java `COMPLETION_ACCEPTED` for uid `12631`, but no
  decisive native resolver uid hit.
- **Root cause candidates:** The current Android owner API seam may not supply
  stable UID attribution for these TCP shapes, especially IPv6 TCP, without a
  different tuple direction/timing or replacement contract.  Separately, native
  resolver logging samples a process-global current stage via `copy_stage()`;
  delayed asynchronous resolver work can therefore be attributed to the next
  tuple stage rather than to the request's own flow identity.
- **Correction:** S156 repaired the seam in three parts: VpnLite APK artifact
  gates require resolver `cell/stage/request` strings, native resolver requests
  carry immutable per-request cell/stage/request metadata, and the A2 traffic
  adapter no longer reuses fixed TCP source ports.  TCP commands request
  `sourcePort=0`, record the actual VPN-local source port, repeat four times,
  and the manifest selects a repeat with a decisive positive resolver UID.
- **Closure evidence:** `evidence/s156-a2-1-correlation-20260825-run5/`
  passed with `registeredTuples=8`, `passedTuples=8`, clean source provenance
  at `gitHead=a3e66a6c3fb34967ca98a39ed5a47c28b8f342be`, and
  `resolverCorrelationSchema=a2-1-resolver-cell-stage-request/v1`.
- **Status:** `CLOSED_FOR_S156_A2_1_BASE_MATRIX`.  A2-2/A2-4/A2-5 may proceed
  only if they inherit the request-correlation and TCP dynamic-port guardrails.
  This finding does not close lifecycle recovery, reverse attribution, cache
  sizing/expiry, or production capacity.  Full details:
  `S155_A2_UID_MATRIX_RERUN2_RESOLVER_CORRELATION_GAP.md`.

### VPN-F062 -- S156-guarded A2-2 rerun needed explicit owner-completion delay to prove pending overlap

- **First observation:** The S156-guarded A2-2 rerun
  `evidence/s186-a2-2-cache-concurrency-20260826-run1/` was
  `INCONCLUSIVE`: all four registered App/family UDP tuples produced correct
  same-identity `MISS_SUBMITTED -> COMPLETION_ACCEPTED -> CACHE_HIT` chains,
  but the native ledger never exceeded `maxPendingObserved=1`.
- **Root cause:** Android owner lookup completed faster than the runner could
  arm and launch the next staged App request.  The 250 ms AppA/AppB delivery
  stagger and the per-stage ADB control round trip protected intent delivery
  and resolver `cell/stage/request` correlation, but also serialized the
  first-wave miss/completion enough to lose the pending-overlap proof.
- **Correction:** Commit `4b5182a` applies the existing bounded
  `uidContractCompletionDelayMillis` control while arming A2-2 stages and
  records `uidCompletionDelayMillis` in source provenance and manifest.  This
  delays asynchronous owner completion without changing tuple keys, App UIDs,
  cache identity, or FlowOwner topology.
- **Closure evidence:** `evidence/s186-a2-2-cache-concurrency-20260826-run2/`
  passed at clean `gitHead=4b5182a4069ba0142f65446f7a15e064fe1807c7`,
  `gitDirty=false`, with `registeredTuples=4`, `passedSequences=4`,
  `concurrent=true`, `maxPendingObserved=2`, `maxCacheObserved=4`, final
  `pending=0/cache=0/flow-ids=0`, controlled fixture endpoints
  `192.168.4.5:55553` and
  `fd76:d462:c4e3:0:542e:6667:7d53:b784:55553`, and resolver
  `cell/stage/request` correlation.
- **Status:** `CLOSED_FOR_S186_A2_2_CONCURRENCY`.  This closes A2-2 under the
  S156 guardrails.  It is a POC timing correction, not evidence that UID must
  enter the canonical FlowOwner key or block owner execution.  It does not
  claim production cache sizing, lifecycle invalidation, external connectivity,
  or B1/B2 whole-device behavior.

### VPN-F063 -- Remaining A2 historical PASS bundles lack S156 guardrail provenance

- **First observation:** After S156 and S186 tightened the A2 evidence
  contract, the 2026-08-23 A2-4, A2-5, and A2-6 PASS bundles still carried
  only the older public-endpoint/provenance envelope.  Their manifests name
  `destinationHost=1.1.1.1` and `destinationPort=53`, and do not carry
  `uidContractCellId`, controlled fixture metadata, or
  `resolverCorrelationSchema=a2-1-resolver-cell-stage-request/v1`.
- **Root cause:** The earlier A2 aggregate was functionally useful but mixed
  two evidence generations.  A2-1/A2-2 now prove UID attribution through a
  controlled WSL2/LAN fixture plus immutable resolver request correlation,
  while A2-4/A2-5/A2-6 still used the pre-S156 oracle.  Reusing those old PASS
  bundles as final closure would silently weaken the current UID/drop seam.
- **Correction:** The A2-4, A2-5, and A2-6 runners/verifiers now reject public
  resolver endpoints, require the controlled fixture envelope, require
  `uidContractCellId`, require resolver `cell/stage/request` correlation, and
  gate APK members on the native resolver correlation strings.  The old PASS
  bundles are retained as historical functional baselines but should evaluate
  `INVALID` under the S156-era verifier.
- **Partial closure evidence:** S188 reran A2-4 on clean head
  `138a2f4f4db5d5c73b199eb9bd37e101afa286e0` with controlled WSL2/LAN fixture
  metadata, `uidContractCellId=A2-4`, and
  `resolverCorrelationSchema=a2-1-resolver-cell-stage-request/v1`.  Bundle
  `evidence/s188-a2-4-lifecycle-native-join-20260826-overlay-run1/` passed
  with no `failureReasons`, no `invalidReasons`, and no architecture
  interruption.  The S188 artifact seam correction is recorded separately as
  `VPN-F065`.
- **Further closure evidence:** S189 reran A2-5 on clean head
  `9b7968662a3512e90a0a7b178ec75d5b79a39da6` with controlled WSL2/LAN fixture
  metadata, `uidContractCellId=A2-5`, and the same resolver correlation
  schema.  Bundle
  `evidence/s189-a2-5-admission-ledger-20260826-run1/` passed the known-UID
  allow/drop admission ledger: the allow key crossed the real downstream
  transport/broker/socket seam, while the fresh dropped key produced zero
  downstream transport, broker, or socket events.
- **Final closure evidence:** S190 reran A2-6 on clean head
  `ff69c0669f30bba838cccf853962a8d7e67d7ffc` with controlled WSL2/LAN fixture
  metadata, `uidContractCellId=A2-6`, and the same resolver correlation
  schema.  Bundle
  `evidence/s190-a2-6-replay-settlement-20260826-run1/` passed live transport
  settlement, replay falsifiers, bounded contract settlement, native ledger
  bounds, orderly cleanup, and process/TUN residue settlement.  The final
  aggregate audit
  `evidence/s190-a2-aggregate-20260826-run1/a2-aggregate.json` passed across
  A2-0 through A2-6 with no errors and `architectureInterruption=false`.
- **Status:** `CLOSED_FOR_S190_A2_AGGREGATE`.  This is an evidence-standard
  correction, not a behavioral contradiction of the earlier UID/drop results.
  It does not require blocking FlowOwner, adding UID to the canonical flow key,
  reviving stale identity, or adding an alternate transport path.

### VPN-F064 -- S187 A2-3 current refresh needed explicit OI3 cleanup control before product stop

- **First observation:** The first S187 current-artifact IPv4 bundle
  `evidence/s187-a2-3-controlled-return-20260826-ip4/` functionally proved
  the controlled reverse path but evaluated `INVALID` because native cleanup
  was not observed before the force-stop fallback.  AppA same-socket return,
  OI3 ingress/output, raw TUN tuple/payload, canonical UID/package/stage join,
  owner-pthread identity, zero Android UID lookup, zero transport re-entry,
  and broker `1/1` all passed.  Cleanup evidence was
  `cleanupObservedBeforeForceStop=false`, `nativeCleanupObserved=false`,
  `contractCleanupObserved=true`, `forceStopFallback=true`, and
  `pollAttempts=26`.
- **Root cause:** The A2-3 verifier correctly requires the native A2-3
  `event=CLEANUP` marker.  The runner's ordinary `--ez stop true` path asked
  the product VPN service to stop, and that path terminates the native child
  with TERM/KILL rather than driving the OI3 bounded stop path.  Native stdout
  therefore recorded signal/process settlement with `normal-stop-requested=0`
  and bypassed the OI3 cleanup emitter.  `SnortVpnService` already exposed the
  limited test-only `oi3Control` JNI control, but `MainActivity` had no
  control-only bridge for shell-driven legacy POC intents, and the runner did
  not send `oi3Control=stop`.
- **Correction:** Commit `c9eb3c5` adds the `MainActivity` control-only bridge
  and updates the A2-3 runner to send `oi3Control=stop` before the ordinary VPN
  stop.  Static tests now require that ordering and require the bridge to copy
  only `EXTRA_OI3_CONTROL` for this cleanup path.
- **Closure evidence:** Clean-head S187 reruns
  `evidence/s187-a2-3-controlled-return-20260826-clean-ip4/` and
  `evidence/s187-a2-3-controlled-return-20260826-clean-ip6/` both pass with
  `gitHead=c9eb3c587bd8d46a277e69b733db48ef263d1ab7`, `gitDirty=false`,
  VpnLite APK SHA-256
  `0a4adfe379577289ee608a22d6ebd4f5fc4dd7577b53b59943871d4147d69ccf`, AppA
  APK SHA-256
  `29a4d0913cbf67fcdb33a6dd06381735fe657f16228f1088fff47917974b5a3c`, and
  OI3 plugin SHA-256
  `5012eeecb16828edca58f3dc98ddd52330a3b09b26394a3baa94b7c39604cc72`.
  Both cleanup receipts report `cleanupObservedBeforeForceStop=true`,
  `nativeCleanupObserved=true`, `contractCleanupObserved=true`,
  `forceStopFallback=false`, and `pollAttempts=2`.  Both result files retain
  zero Android UID lookup, zero transport re-entry, same-socket App return,
  raw TUN tuple/payload match, and broker settlement.
- **Status:** `CLOSED_FOR_S191_A2_3_CLEANUP_CONTROL`.  This is a POC cleanup
  control correction.  It does not weaken the A2-3 datapath claim, require UID
  in the FlowOwner key, or add a product stop semantics claim.

### VPN-F065 -- S188 A2-4 Android overlay dropped S156 resolver correlation from the product runtime

- **First observation:** S188 A2-4 repeatedly failed before it could test the
  lifecycle/native-join claim.  One run used a stale VpnLite APK that lacked
  the `assets/vpp-tun-poc-plugin.sha256` asset and required plugin members.
  The corrected-artifact run then still evaluated `INVALID`: the APK contained
  a plugin member, but VPP did not load `tun_poc`; `show plugins` had no
  plugin row, `show tun-poc` and `tun-poc stage` were `unknown input`, and
  `vpp-owner-resolver-aggregate.log` recorded `queries=0`.
- **Root cause:** The product Android VPP overlay did not carry the S156 native
  resolver correlation change into the pinned product runtime source.  The
  usable S156 plugin existed in an older isolated work tree and contained
  `cell %s stage %s request %llu`, but it was built against a different
  `libvlib.so` than the current product runtime.  Mixing that plugin into the
  current APK produced a provenance-looking artifact that the runtime could
  not actually load.  This is an Android runtime overlay/artifact seam, not a
  UID attribution, FlowOwner, or lifecycle design contradiction.
- **Correction:** Commit `138a2f4` makes
  `experiments/vpp-nfq-poc/scripts/apply-vpp-android-overlay.sh` insert the
  S156 correlation into `plugins/tun_poc/tun_poc.c` for product Android runtime
  builds.  The overlay now writes the resolver query as
  `cell <cell> stage <stage> request <id>` at request creation time and derives
  the cell from `SAKAMOTO_A2_STAGE_CELL`.  The A2-4 static test now asserts
  that the overlay carries `tun_poc_ledger_cell`,
  `SAKAMOTO_A2_STAGE_CELL`, `cell %s stage %s`, and `request %llu`.
- **Closure evidence:** S188 clean rerun
  `evidence/s188-a2-4-lifecycle-native-join-20260826-overlay-run1/` passed at
  `gitHead=138a2f4f4db5d5c73b199eb9bd37e101afa286e0`,
  `gitDirty=false`.  It records fixture destination `192.168.4.5:55553`,
  VpnLite APK SHA-256
  `5aef6c5e20c02e82f4e2acdf882f8f1686fd19774040ea972507bf66b6b1be39`, AppA
  APK SHA-256
  `7b082e62109addc465d91e5df82e0fca47cf206158db2d6a2f929dcbca9b4809`, runtime
  `libvpp_runtime.so` SHA-256
  `cc2dfaaee109f1c54f884010dfdf856e8c462a288f7594ee43513b7c3287c022`,
  `libvlib.so` SHA-256
  `e6b6bf8f6864f77801a22bc60a8259744982af57aa9e933dc3c4f01361fde522`, and
  `libtun_poc_plugin.so` SHA-256
  `d919117842eb41b6924693f7b79a2d20ee6ce22f8ab371b7995039c38b46d9bc`.  The
  native resolver ledger, all nine lifecycle stages, Java contract joins,
  network-handle restart, generation refresh, contract cleanup, native cleanup
  ledger, and final settlement passed.  `native-stale-join` remains
  `INCONCLUSIVE` only because `staleNativeJoinRequired=false`; it is an
  explicit non-claim, not a failure.
- **Status:** `CLOSED_FOR_S188_A2_4_OVERLAY_CORRELATION`.  Future Android
  runtime/APK POCs must prove that the selected tun plugin is built from the
  same product runtime source/stage that supplies `libvlib.so`, not merely that
  an APK member with the expected filename exists.

### VPN-F066 -- S153/S170 resource runner waited for cleanup markers without driving OI3 cleanup control

- **First observation:** S153 reused the S170 E1 resource runner for a
  one-cycle residual preflight.  The data path succeeded, but the run failed
  because `cleanup_pass=0`: `sent=255`, `received=255`, `errors=0`,
  `fixtureRx=501`, `fixtureTx=501`, `residual_vpp=` empty, `tun0_after=0`, and
  `rules_match=1` in
  `evidence/s153-e1-residual-20260826-preflight-positive2/`.
- **Root cause:** The runner had a bounded `wait_stop_cleanup_marker` helper,
  but it only requested ordinary product stop before waiting for
  `oi3_cleanup result=`.  Product stop supervises native child shutdown and is
  not the test-only OI3 bounded cleanup command.  Therefore the runner was
  waiting for a marker that it had not caused the native control path to emit.
  This is the S170/S153 instance of the same cleanup-control seam recorded for
  A2-3 in `VPN-F064`.
- **Correction:** The S170 runner now sends `oi3Control=multi-stop` before
  ordinary product stop, records `cleanup-pre-stop.log`, merges pre-stop and
  post-stop cleanup logs, and keeps process/TUN/ip-rule residue checks
  separate from marker counting.  The static S170 regression requires
  `run_oi3_control "multi-stop"`, `wait_oi3_cleanup`, `cleanup-pre-stop.log`,
  and the ordering before `stop_vpn`.
- **Closure evidence:** Post-fix smoke
  `evidence/s153-e1-residual-20260826-cleanup-fix-smoke/` passed with
  `runId=20260826-024859-356974`, `sent=258`, `received=258`, `errors=0`,
  `cleanup_pass=8`, `cleanup_fail=0`, `fixtureRx=506`, `fixtureTx=506`,
  `residual_vpp=` empty, `tun0_after=0`, `rules_match=1`, and
  `failureCount=0`.
- **Status:** `CLOSED_FOR_S153_CLEANUP_SMOKE`.  This closes the runner hotspot,
  not the full S153 E1 residual matrix.  Future POC runners that claim native
  bounded cleanup must drive the explicit OI3 cleanup control first and treat
  ordinary product stop as a separate Android lifecycle/residue settlement
  step.

### VPN-F067 -- S153 foreground resource trend over-bound E1 resource settlement to UDP exact closed-echo

- **First observation:** After the S153/S170 cleanup-control fix, the S153
  foreground resource trend used UDP exact closed-echo as both its traffic
  driver and its resource-trend correctness gate.  The first current-artifact run
  `evidence/s153-e1-residual-20260826/resource-foreground/`
  (`runId=20260826-030526-927489`, endpoint `192.168.4.5:42360`,
  `SOURCE_PORT_BASE=46600`, `udpClosedTimeoutMs=1000`) passed cycle 1 but
  failed cycle 2 with `sent=1309`, `received=1305`, `errors=4`, and `late=4`.
  Fixture RX/TX matched and cleanup/residue still passed.
- **Timeout falsifier:** Raising only `udpClosedTimeoutMs` to `3000` did not
  close the gap:
  `evidence/s153-e1-residual-20260826/resource-foreground-timeout3000-probe/`
  (`runId=20260826-031012-417454`, endpoint `192.168.4.5:42361`,
  `SOURCE_PORT_BASE=46620`) failed cycle 1 with `sent=1317`, `received=1315`,
  `errors=2`, and `late=0`.  Native logs showed
  `oi3 tun-submit deferred reason=udp-datagram-inflight`, `oi3 tun-flow
  timeout`, and UDP window rearm at the tail; decoding `tun-output-raw` showed
  a missing flow-3 sequence in native output.  This rules out a simple 1s app
  timeout explanation.
- **Control evidence:** The same current APK/plugin/HEV hashes passed the old
  registered S170/F046 tuple shape in
  `evidence/s153-e1-residual-20260826/resource-foreground-s170shape-probe/`
  (`runId=20260826-031314-315178`, endpoint `192.168.4.5:42185`,
  `SOURCE_PORT_BASE=43000`, `udpClosedTimeoutMs=1000`): two cycles passed with
  `sent=3327`, `received=3327`, `errors=0`, `fixtureRx=3836`,
  `fixtureTx=3836`, and `failureCount=0`.
- **Full-run falsifier:** Promoting that old tuple shape back to the full
  five-cycle exact-echo resource trend still failed:
  `evidence/s153-e1-residual-20260826/resource-foreground-corrected/`
  (`runId=20260826-031549-830075`, endpoint `192.168.4.5:42185`,
  `SOURCE_PORT_BASE=43000`) failed cycle 1 with `sent=1382`,
  `received=1377`, `errors=5`, and `late=4`.  Native evidence showed one UDP
  datagram inflight when the five-second flow deadline fired; cleanup passed
  the generation as `EXPECTED_DIRECT_REPLY`, rearmed the remaining pending
  datagrams, and delivered them late while the inflight sequence was not
  recovered.
- **POC correction:** S153 is an E1 resource/lifecycle settlement POC, not the
  owner of UDP lossless correctness.  The accepted foreground resource trend
  now uses a paced UDP fire-and-count driver (`EXPECT_ECHO=false`) and requires
  nonzero app sends, zero app-side probe errors, fixture RX/TX symmetry, native
  owner/buffer/credit ledgers, exact cleanup, residue checks, and resource
  snapshots.  UDP exact closed-echo remains a separate correctness envelope
  owned by S169/F046 and is not re-litigated as the S153 resource trend gate.
- **Closure evidence:** The corrected foreground resource driver passed in
  `evidence/s153-e1-residual-20260826/resource-foreground-firecount/`
  (`runId=20260826-032313-031928`, `EXPECT_ECHO=false`, endpoint
  `192.168.4.5:42189`, `SOURCE_PORT_BASE=43000`): five cycles recorded
  nonzero app sends and zero app probe errors, fixture `12639/12639`,
  cleanup `16/0` or `20/0`, no residual `vpp`, no `tun0`, matching ip rules,
  and `failureCount=0`.
- **Status:** `CLOSED_FOR_S153_FIRE_AND_COUNT_RESOURCE_DRIVER`.  This is a POC
  registration/design correction plus a useful native boundary signal, not a
  UID/drop-policy contradiction.  It closes only the S153 foreground resource
  driver; UDP exact closed-echo remains bounded to its dedicated correctness
  evidence.

### VPN-F068 -- S153 epoch lifecycle runner over-bound underlay replacement to TCP exact transition and byte-exact wlan rules

- **First observation:** After the foreground resource driver correction,
  S153 `state-lifecycle-run3` passed `normal-stop-start`, `screen-off`,
  `forced-doze`, and `fault-restart`, but failed `epoch-restart` with
  `cleanup_pass=13`, `cleanup_fail=2`, `residual_vpp=` empty,
  `tun0_after=0`, and `rules_match=0` in
  `evidence/s153-e1-residual-20260826/state-lifecycle-run3/`.
- **Root cause:** The epoch cell used a TCP exact transition probe as the
  active flow while the runner deliberately disabled Wi-Fi, waited for underlay
  loss, re-enabled Wi-Fi, and restarted the VPN.  That driver turned a
  lifecycle/epoch-cleanup question into a TCP connect/exact-reply timing
  question under a forced underlay transition.  The rule oracle also compared
  Android `ip rule` output byte-for-byte across Wi-Fi replacement; Android
  legitimately changed the wlan fwmark/netId, and the first normalization regex
  missed `lookup wlan0` lines with trailing whitespace.
- **Correction:** The S153 epoch transition now uses UDP fire-and-count as the
  active-flow driver, preserving the intended "real traffic crosses the epoch"
  seam without requiring TCP exact connect success during Wi-Fi replacement.
  The oracle requires underlay lost/available epoch evidence, OI3 cleanup,
  residue settlement, and fresh post-restart UDP recovery.  The wlan rule
  normalization now matches `lookup wlan0[[:space:]]*$` and masks Android's
  replacement fwmark value.
- **Closure evidence:** The corrected run
  `evidence/s153-e1-residual-20260826/state-lifecycle-run4/`
  (`runId=20260826-034519-077696`, `UDP_EXPECT_ECHO=false`,
  `UDP_PORT=42359`, `TCP_PORT=42360`, `SOURCE_PORT_BASE=46530`) passed all
  five phases: `normal-stop-start` `16/0`, `screen-off` `14/0`,
  `forced-doze` `16/0`, `fault-restart` `16/0`, and `epoch-restart` `16/0`,
  with no residual `vpp`, `tun0_after=0`, matching rules, fixture
  `17567/17567`, and `phaseFailures=0`.
- **Status:** `CLOSED_FOR_S153_EPOCH_FIRE_AND_COUNT_DRIVER`.  This is a POC
  runner/oracle correction, not evidence of a target lifecycle cleanup defect.
  Future epoch/lifecycle POCs must not use exact TCP transition success as the
  oracle for a deliberately broken/replaced physical underlay unless that exact
  TCP property is itself the registered question.

### VPN-F069 -- E2 matched HTTP/device-state latency exceeds ADR-0007 comparative threshold

- **First observation:** S174/S175 bounded HTTP staircase cells were correct and
  clean but showed OI3 p95 around 1.3--2.6 seconds while matched Direct/HEV
  stayed below 100 ms.  The result strengthened correctness construction but
  left EG-17 open.
- **Device-state confirmation:** S192 extended the matched S172 HTTP runner to
  screen-off and forced-Doze.  Both accepted runs used comparison APK
  `c943d32e3eec0d0281d60dae2acd9af6455eecadbaab81657ce056049c5b8678`, OI3
  plugin `5012eeecb16828edca58f3dc98ddd52330a3b09b26394a3baa94b7c39604cc72`,
  HEV `37481673d6547c5f2a178de04bf4c4b5f60ba6ce1bed7c7cba1cd22b606ac96d`,
  and `tun_poc_plugin.so`
  `d919117842eb41b6924693f7b79a2d20ee6ce22f8ab371b7995039c38b46d9bc`.
  Direct, HEV and OI3 all completed `8/8` requests under screen-off and
  forced-Doze, `stateValid=1`, OI3 cleanup was `12/0` or `11/0`, and both
  manifests recorded `failureCount=0`.
- **Boundary:** The accepted S192 cells rule out a target correctness,
  cleanup, UID, policy, or device-state failure for this shape.  They preserve
  the E2 performance problem: screen-off OI3 p95/p99 was `2604ms` versus Direct
  `77ms` and HEV `23ms`; forced-Doze OI3 p95/p99 was `2618ms` versus Direct
  `81ms` and HEV `20ms`.
- **S199--S204 diagnosis update:** The post-audit latency diagnosis split this
  umbrella risk into one corrected defect and one remaining hotspot.  S199
  rejected the TCP payload timer-kick candidate (`0/4` OI3 successes and four
  `SocketTimeoutException`s).  S200/S201/S202 close the missing connector
  write-interest defect as VPN-F070: OI3 now completes `4/4` and `8/8` cells
  without the earlier seconds-level payload stall, and the matched S202 run has
  OI3 p95 `584ms` instead of the earlier 1.3--2.6s class.  S203/S204 then
  identify VPN-F071: multi dispatcher ingress reaches native promptly, but
  selected-owner TUN enqueue can lag by roughly 160--500ms; a target-trigger
  wake candidate did not materially improve p95 (`535ms`) and was reverted.
- **S205--S214 diagnosis update:** The later handoff/post-send work corrected
  the initial F071 interpretation and split it again.  S205/S206 moved TUN and
  broker completion delivery onto explicit owner/completion handoff paths but
  still showed OI3 around 0.5s p95.  S211 then added a targeted
  post-Direct-send read observer guarded by `direct_recv_events`; the focused
  OI3 cell improved to p50/p95/p99 `31/95/95ms`.  Matched S212b and reverted
  S214 still show an open residual: OI3 completes `8/8`, but p95 remains
  `336--357ms` while Direct/HEV remain `86/22ms` in the matched run.  Native
  timing localizes the residual to the first HTTP payload submit not promptly
  driving Direct send until Android retransmits the payload roughly 200ms
  later.  This is recorded as VPN-F072.
- **Status:** `OPEN_RISK`.  The final feasibility audit is
  `ADJUSTMENT_REQUIRED_E2_PERFORMANCE`, not `SUPPORTS_BASELINE`.  Main-stack
  import must wait for a focused latency/cost diagnosis and a corrected E2
  rerun, or for an explicit architecture decision that changes the route.

### VPN-F070 -- OI3 connector poll missed protected write interest after TCP payload submit

- **First observation:** S174/S175/S192 matched HTTP cells showed OI3 p95/p99
  around 1.3--2.6 seconds while Direct and HEV stayed below 100ms.
- **Isolated failure mode:** After Android submitted TCP payload through TUN,
  HEV/lwIP needed protected socket write readiness.  OI3 connector polling
  subscribed to `POLLOUT` only while `connector_connect_pending` was true.  If
  connect was already complete and no Direct send had occurred, the owner could
  wait for retransmission or a connector deadline before writing the request.
- **Rejected POC correction:** S199
  `evidence/s199-e2-oi3-tcp-payload-kick-20260826/`
  (`runId=20260826-045947-713819`) added a timer-kick after TCP payload submit.
  It produced OI3 `0/4`, four app `SocketTimeoutException`s, and
  `failureCount=1`; native evidence showed the kick created ACK-only TUN output
  without solving Direct send readiness.  Do not use generic payload timer
  kicks as this fix.
- **POC correction:** Add `connector_write_pending`; set it after TCP payload
  submit when `direct_send_events == 0`; include `POLLOUT` while connect or
  write is pending; clear it on Direct send and lifecycle/re-arm boundaries.
- **Post-correction evidence:** S200
  `evidence/s200-e2-oi3-connector-write-interest-20260826/`
  (`runId=20260826-050600-460730`) passed OI3 `4/4`,
  p50/p95/p99 `351/514/514ms`, cleanup `8/0`.  S201
  `evidence/s201-e2-oi3-write-interest-8req-20260826/`
  (`runId=20260826-050729-932835`) passed OI3 `8/8`,
  p50/p95/p99 `525/539/539ms`, cleanup `12/0`.  S202
  `evidence/s202-e2-matched-write-interest-8req-20260826/`
  (`runId=20260826-050854-725207`) passed Direct `8/8`
  p95 `80ms`, HEV `8/8` p95 `25ms`, and OI3 `8/8` p95 `584ms`.
- **Supported claim:** The old seconds-level OI3 TCP payload stall had a
  concrete connector write-interest root cause and is corrected for the
  bounded matched HTTP shape.
- **Non-claim:** ADR-0007 E2 comparative latency is not closed; OI3 remains
  materially slower than Direct/HEV.
- **Status:** `CLOSED_FOR_S200_S202_WRITE_INTEREST_SLICE`.

### VPN-F071 -- OI3 multi dispatcher-to-owner handoff and post-send read wake path caused the first residual tail

- **First observation:** After VPN-F070, OI3 still completed matched HTTP but
  remained around 0.5s p95, far above Direct/HEV.
- **Evidence:** S203
  `evidence/s203-e2-oi3-syn-admission-timing-20260826/`
  (`runId=20260826-051405-366520`) added native wall-time probes and passed
  OI3 `4/4`, p50/p95/p99 `250/526/526ms`.  S204
  `evidence/s204-e2-oi3-target-trigger-wake-20260826/`
  (`runId=20260826-051804-388905`) passed OI3 `4/4`, p50/p95/p99
  `314/535/535ms`.  S205
  `evidence/s205-e2-oi3-owner-fd-handoff-20260826/`
  (`runId=20260826-053720-990568`) passed OI3 `4/4`,
  p50/p95/p99 `406/527/527ms`.  S206
  `evidence/s206-e2-oi3-owner-event-handoff-20260826/`
  (`runId=20260826-054602-682259`) passed OI3 `4/4`,
  p50/p95/p99 `291/522/522ms`.
- **Observed delay:** S203/S204 showed selected flows reaching `oi4
  multi-ingress` promptly, then waiting roughly 160--500ms before `oi3
  tun-queue enqueue` on the owner.  S205/S206 changed the seam to explicit
  per-owner TUN handoff and broker-completion handoff.  That narrowed the
  handoff itself but did not close p95; the remaining delay then showed up
  after Direct send, waiting for Direct read readiness.
- **Rejected POC correction:** The target-thread interrupt/wakeup candidate in
  S204 did not materially improve the delay and was reverted.  S209
  `evidence/s209-e2-oi3-tcp-nodelay-20260826/`
  (`runId=20260826-055233-228968`) proved `TCP_NODELAY` alone was not the fix:
  OI3 `4/4`, p50/p95/p99 `238/524/524ms`.
- **POC correction:** S211
  `evidence/s211-e2-oi3-post-send-direct-recv-guard-20260826/`
  (`runId=20260826-055822-728962`) added a targeted
  `connector-poll-arm-after-direct-send` observer guarded by
  `direct_recv_events`.  The focused OI3 cell passed `4/4`,
  p50/p95/p99 `31/95/95ms`, cleanup `8/0`.
- **Supported claim:** The original F071 class is no longer correctly described
  as a generic UID, policy, fixture, dispatcher, or broker-completion failure.
  The handoff and post-send-read seams have targeted corrections for the
  bounded focused cell.
- **Non-claim:** Matched 8-request E2 is not closed; the residual moved to
  VPN-F072.
- **Status:** `CLOSED_FOR_S205_S211_HANDOFF_POST_SEND_SLICE`.

### VPN-F072 -- OI3 first HTTP payload submit can wait for app retransmission before Direct send

- **First observation:** After the F071 post-send observer, the focused
  four-request OI3 cell improved sharply, but longer matched E2 still retained
  OI3 outliers.
- **Evidence:** S212b
  `evidence/s212b-e2-matched-after-post-send-read-observer-20260826/`
  (`runId=20260826-060037-266591`) passed Direct `8/8` p95 `86ms`, HEV `8/8`
  p95 `22ms`, and OI3 `8/8` p95 `336ms`, cleanup `11/0`.  S214
  `evidence/s214-e2-oi3-post-send-revert-drain-20260826/`
  (`runId=20260826-060752-407437`) passed OI3 `8/8`,
  p50/p95/p99 `73/357/357ms`, cleanup `11/0`.
- **Rejected POC correction:** S213
  `evidence/s213-e2-oi3-stale-wake-drain-20260826/`
  (`runId=20260826-060542-527708`) tried to drain stale connector wakes.  It
  worsened connect-tail behavior, producing OI3 `8/8` but p95 `476ms`, and was
  reverted before S214.
- **Observed delay:** In the S212b/S214 outliers, the first HTTP payload reaches
  native and is submitted, but no Direct send follows until Android repeats the
  payload roughly 200ms later.  Once Direct send happens, the S211 observer
  drives Direct read promptly.  The residual is therefore a first-payload
  write-drive problem, not the earlier post-send read-wake problem.
- **Supported claim:** OI3 correctness, cleanup, fixture reachability, and
  Direct/HEV controls are stable for this shape; the remaining E2 blocker is a
  narrow OI3 scheduling/readiness seam around first payload submission.
- **Next correction direction:** Instrument and fix the connector/poll/owner
  re-entry path between first payload submit and first Direct send.  Avoid
  reintroducing generic payload timer kicks or stale-wake drains; both have
  negative evidence.
- **Status:** `OPEN_RISK`.  Main-stack import remains blocked until F072 is
  corrected and matched Direct/HEV/OI3 E2 is rerun, or until an explicit
  architecture decision changes the route.

## Consolidation audit

- All prior 30 source findings map to one of `VPN-F001`--`VPN-F026`; the S140
  hotspot adds `VPN-F027`/`VPN-F028`, the S141 underlay investigation adds
  `VPN-F029`, S142 adds the stream-framing finding `VPN-F030`, and S143
  identifies and closes its short-segment owner-drive seam as `VPN-F031`.
  S146 adds `VPN-F032`, a negative-outcome cleanup contract defect; S147 closes
  it for the controlled full-TUN POC and unblocks B2-dependent work. S150 adds
  `VPN-F033`, a real underlay-handle/epoch propagation design gap; S151 closes
  it for the selected Pixel artifact by adding the Java→native callback/epoch
  seam and rerunning the transition with bounded explicit VPN session restart.
  S150 remains the historical hotspot record; it no longer pauses C1, while
  C2/D/E retain their own evidence gates. S152 adds `VPN-F034`, a real-flow
  normal-stop classification gap; S153 closes that sub-gate. S156 adds
  `VPN-F035`, the one-flow-per-VPN-session lifecycle hotspot; S157 closes it for
  the registered positive-flow TUN re-arm contract. S158 adds `VPN-F036`: the
  final OI3 artifact's historical single-owner limitation is now closed for
  D1/D2 by the implemented two-owner route. S159 adds VPN-F037: S160 closes
  the HEV credit-accounting portion for the tested UDP overload envelope and
  S161 closes the timed D3-to-B1 recovery gate. S160 adds VPN-F038 for the
  reproducible full-route ambient TCP owner-stop contamination; S161 closes it
  as a classified run-validity outcome. S163 adds VPN-F039 for incompatible
  OI3/HEV build stages and closes it as a packaging preflight correction. S164
  adds VPN-F040 for the external-ingress port-0 wildcard design gap; S165
  implements and regresses the explicit external-only demux correction, closing
  the correctness arm and reopening the remaining E2 matrix.
- S166 records the legacy owner-resolver UDP one-shot verdict boundary: an
  asynchronous first `uid=-1` miss was incorrectly required to complete within
  the only packet. The runner now defaults to a same-socket two-packet retry;
  the corrected Pixel cell passed with the bounded `PROBE_WAIT=12` window,
  three resolver hits and two UID-block packets. This is a fixture correction,
  not a new product finding or architecture hotspot. S166 also records VPN-F041:
  a same-tuple FIN/ACK tail after a
  successful single-owner TCP re-arm was admitted as a new generation and
  emitted a secondary cleanup `FAIL` despite zero residue. The owner-local
  canonical TCP tombstone gate now rejects that tail before admission; the
  corrected ARM64 regression has one clean generation-1 `PASS` and no cleanup
  `FAIL`. This finding is closed for the bounded correctness arm and was not
  repeated as a three-attempt hotspot.
- S167 extends the resolver evidence to IPv6 UDP: both allow and drop cells
  preserved the exact external destination, resolved the package UID without
  resolver errors, and recorded the expected zero/two UID-block packets. This
  closes only the bounded IPv6 UDP UID protocol cell; matched E2 performance,
  strict-owner external-ingress negatives, and final-topology load remain open.
- S168 adds VPN-F042 for the multi-owner teardown heap-corruption seam: two
  valid pre-fix cells shared the Scudo/SIGABRT signature, and the deferred
  thread-local HEV task drain passed the bounded 2-flow regression with clean
  per-owner cleanup and zero residue. The follow-up lifecycle correction
  (bounded retry plus destroy guards) still left the registered fixed-artifact
  4-flow cell reproducing the same owner-context Scudo/SIGABRT boundary for
  the fourth valid recurrence. The follow-up diagnosis found the missing
  owner-thread affinity guard: a foreign VPP worker could finish/destroy another
  owner's Flow Stack. OI3 now defers foreign-owner finish to the target owner
  thread, and the Android APK preflight is corrected to use a single VPP
  runtime/plugin build closure with native-library `name-filter` loading. The
  Pixel preflight now loads the OI3 plugin and starts `vpp-oi3-multi`; the
  approved 2026-08-25 4-flow rerun did not reproduce heap corruption. F043
  records and closes the missing same-package endpoint preflight rule, and F044
  records and closes the fixed source-port-base harness collision. S169 closes
  F045 for the tested two-owner UDP closed-echo envelope by making the HEV UDP
  connector persistent across datagrams. F046 then closed the remaining
  registered 4-flow mismatch by expanding OI4 to four owner contexts and
  validating the four-flow UDP closed-echo cell with zero app errors, zero
  `owner-busy` rejects, and four clean owner teardowns. S170 adds the bounded
  post-F046 E1 repeat/stop resource trend: five four-owner UDP cycles, stable
  app/VPP FD counts, bounded RSS variation, owned fixture RX/TX, and no
  residual VPP/tun0 after cleanup. S171 adds and closes F047 for the
  multi-owner TCP absolute-timeout hotspot; the corrected bounded
  direct-vs-OI3 sample passes UDP 64B, UDP 4x1400B and TCP 1400B cells with
  zero TCP tail rejects. S172 adds and closes F048 as a matched-HEV-baseline
  build/runner preflight hotspot: `vpp-hev` needs explicit `tun_poc` packaging
  in a comparison APK, while the canonical OI3 APK remains valid without it.
  S172 also adds and closes F049: owner-local admission is now closed while TCP
  tombstones are published, and the matched HTTP baseline is count-bounded
  (`MAX_REQUESTS=1`) rather than a duration-only throughput probe. The accepted
  Direct/HEV/OI3 HTTP construction slice has `failureCount=0`. S173 adds and
  closes F050 for deterministic-owner TCP successor-SYN pressure by deferring
  busy successor SYNs on their canonical owner and clearing stale TCP pending
  tail at re-arm; S174/S175 extend that HTTP staircase to 8 and 16 unpaced
  requests. S176 adds and closes F051 for concurrent UDP primary-owner
  collision by adding UDP-only idle-owner route pinning while leaving TCP on
  the F050 canonical-owner deferred path. S177 adds and closes F052 for the
  S170/S177 resource-runner harness hotspot: current-artifact provenance,
  nonblocking VPP log reads, and bounded `adb_read` retry now allow the short
  final resource slice to produce valid evidence. S178 adds and closes F053 for
  the B1 runner/verdict hotspot by splitting current-artifact DNS dataplane
  proof from late lifecycle cleanup-marker evidence. S180 adds and closes F054
  for the B1 fallback POC-design gap: forced fallback now requires one AppA
  operation with UDP `TC=1` followed by same-query TCP retry, not independent
  UDP/TCP probes. S181 adds and closes F055 for the real B2 transport-fixture
  design gap: an unbound WSL2 TCP port is a valid closed-port timeout fixture
  through Android VPN/OI3, not a stable native real-refusal fixture. S182 adds
  and closes F056 for the representative real policy-drop seam: target-IP drop
  is proven as a pre-owner dispatcher result, not via Android app exclusion or
  an owner cleanup marker. S183 adds and closes F057 for the OI3 UID-drop gate:
  the native pre-OI3 gate must wait for the existing async UID contract's cache
  completion rather than treating the first `uid=-1` sentinel as terminal.
  S184 adds and closes F058: the first run reached a real LAN post-SYN TCP RST
  without a native connector event; the owner-event correction observed one
  owner-local `ECONNRESET`; and the final narrow `tcp_send_reset_ctx()`
  correction emitted one rewritten downstream `RST|ACK` to AppA.  The bounded
  closure run records AppA `dns_response_reset`,
  `PASS_EXPECTED_REAL_RESET`, one transport failure, zero infrastructure
  failure, exact settlement, and zero residue.  A duplicate-log verifier
  false negative was corrected without rerunning valid device evidence. S185
  adds and closes F059 for the infrastructure-failure oracle: bind failure,
  protect failure, and broker unavailable must use exact broker result and
  phase-specific bind/protect accounting instead of one shared timeout/broker
  assertion. S152 adds F060 as an A2 design gap: public endpoints and
  startup-labelled resolver rows cannot close the residual two-App UID
  lifecycle matrix. S155 closes that original oracle defect with controlled
  fixtures and exact stage logs, then adds F061 for the successor TCP
  owner-lookup/per-flow stage-correlation gap. S186 closes F062 for the
  S156-guarded A2-2 pending-overlap proof by adding a bounded owner-completion
  delay to the otherwise passing four-key cache/concurrency run. S188/S189/S190
  track F063: the remaining historical A2-4/A2-5/A2-6 PASS bundles had to be
  rerun with the S156 guardrail provenance instead of being reused as final
  closure; S188/S189/S190 plus the final aggregate now close it. S187/S191
  closes F064: A2-3's current-artifact refresh required an explicit test-only
  OI3 cleanup stop before ordinary product stop, and now passes IPv4/IPv6 on
  clean head. S188 closes F065: the product Android VPP overlay must carry the
  S156 resolver correlation into the same runtime source and ABI set used by
  the APK. S153/S170 closes F066 for the resource-runner recurrence of the
  same cleanup-control seam: drive OI3 cleanup control first, then use product
  stop only as lifecycle/residue settlement. S199--S204 split the F069 E2
  performance risk: F070 closes the connector write-interest defect that caused
  seconds-level payload stalls, while F071 remains open for dispatcher-to-owner
  frame-queue/wake tail latency.
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
- SAKAMOTO-138 is follow-up evidence for VPN-F026 and EG-08/EG-09; its
  Host/model PASS does not close the Pixel `OPEN_RISK` or the campaign's
  nonblocking Android UID gap.
- SAKAMOTO-140 closes two run-validity defects without closing B1: artifact
  alias provenance (VPN-F027) and Android per-UID LAN eligibility (VPN-F028).
- SAKAMOTO-141 adds a third B1 run-validity/transport boundary: an API-success
  bind/protect pair is invalid unless its selected handle is a non-VPN
  physical underlay (VPN-F029).

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
| S140 | B1 artifact provenance hotspot | VPN-F027 |
| S140 | B1 Android 16 LAN eligibility hotspot | VPN-F028 |
| S164 | HEV external-ingress gateway wildcard-port hotspot | VPN-F040 |
| S165 | HEV external-ingress correction and controlled TCP regression | VPN-F040 |
| S166 | owner-resolver UDP one-shot fixture correction | A2 evidence hygiene |
| S166 | single-owner TCP re-arm FIN/ACK tail admission gap | VPN-F041 |
| S167 | IPv6 UDP UID allow/drop extension | A2 protocol evidence |
| S168 | Multi-owner teardown deferred-drain correction and regression | VPN-F042 |
| S184 | Real LAN TCP RST observation and bounded downstream propagation closure | VPN-F058 |
| S185 | Bind/protect/broker infrastructure failure separation | VPN-F059 |
| S152 | Residual two-App UID matrix design gap | VPN-F060 |
| S155 | Controlled A2-1 rerun2 resolver/correlation gap | VPN-F061 |
| S186 | S156-guarded A2-2 pending-overlap revalidation | VPN-F062 |
| S188/S189/S190 | Remaining A2 S156 guardrail reruns | VPN-F063 |
| S187/S191 | A2-3 current-artifact cleanup-control rerun | VPN-F064 |
| S188 | A2-4 Android overlay/runtime resolver-correlation closure | VPN-F065 |
| S153/S170 | Resource runner cleanup-control smoke correction | VPN-F066 |
| S153 | Epoch lifecycle runner transition/oracle correction | VPN-F068 |
| S192/S193 | E2 device-state comparison and final audit performance gap | VPN-F069 |
| S199--S202 | OI3 connector write-interest diagnosis and correction | VPN-F070 |
| S203--S211 | OI3 dispatcher/owner handoff and post-send read-wake diagnosis/correction | VPN-F071 |
| S212--S214 | OI3 first-payload write-drive residual diagnosis | VPN-F072 |

## SAKAMOTO-139 A2 addendum (2026-08-23)

The detailed A2 raw evidence is recorded in
[`S136_A2_UID_POLICY_EXECUTION_JOURNAL.md`](S136_A2_UID_POLICY_EXECUTION_JOURNAL.md)
and the machine-readable artifact
[`uid-attribution-contract-android-a2.json`](prototypes/uid_attribution_contract/artifacts/uid-attribution-contract-android-a2.json).
This addendum preserves the existing consolidation and records the new
fixture/correction facts:

### VPN-F026 -- A2 status update

- **A2 evidence:** Chrome UID 10180 produced narrow real IPv4 TCP and UDP
  attribution through tun0/VPP. Long-window and near-simultaneous dual
  ordinary-App IPv4/UDP/TCP cells observed Chrome UID 10180 and Maps UID 10176
  on the same tun0/VPP path, including Maps TCP and `/proc` sockets for both
  UIDs. The historical Chrome IPv6 443 run produced one exact-target
  `uid=10180` completion, but final HTTP/80 and ULA retries were `uid=-1` for
  every exact target query, so current target UID attribution is intermittent
  rather than closed. The
  bounded contract matrix recorded package-scoped wrong-UID rejection and live
  pending/cache replay assertions in addition to
  miss/completion/hit, refresh, unavailable, and bounded high-water outcomes.
  Its replay control emitted live wrong-owner/generation/duplicate/stale/scope/
  cross-App/key-mutation assertions with pending/cache before-after state; A1
  Host/model remains the decisive cross-implementation baseline. A historical
  narrow VpnLite UID 12628 IPv4 UDP observation is
  retained with an explicit raw-overwrite caveat.
- **A2 gap:** Repeatable Chrome IPv6 target UID completion at the VPP post-policy
  boundary is absent/ambiguous despite the historical one-off completion and
  forced tuple observations, and the two-App observation remains a narrow
  IPv4/TCP/UDP plus concurrent boundary rather than a complete per-UID/reverse
  matrix. The finding remains
  `OPEN_RISK`.

### VPN-F026-A2-FIXTURE-01 -- androidruntime direct socket bypassed tun0

- **Observation:** UID 12620's DebugControlActivity socket connected using
  local Wi-Fi address `192.168.4.151`, while VPP saw no tuple/resolver/cache
  work. RuntimeService was absent before and after the VPN/activity probe.
- **Interpretation:** This is a decisive fixture/binding failure for the
  intended second-UID cell, not evidence against owner-inline/nonblocking
  execution or the immutable FlowOwner key.
- **Status:** `OPEN_RISK` (A2 evidence gap).

### POC-CORRECTIONS-A2 -- ordinary harness corrections

- **Status:** `CLOSED_FOR_POC`.
- **Corrections:** owner-resolver plugin selection now chooses
  `tun_poc_plugin.so`; comma-separated allowed packages are added one by one;
  drop tests use explicit sentinel UID `99999`; unavailable `tcpdump` falls
  back to `/proc/net/tcp*` and VPP counters.
- **Integrity:** A temporary route-instrumentation build stopped on retained
  VPP source mutation and was reverted; no failed build was used as evidence.
- **Architecture impact:** none. Plane state and ticket state are unchanged.

### POC-CORRECTIONS-A2-FINAL -- registered A2 closure

- **Status:** `CLOSED_FOR_POC`.
- **Evidence:** The final aggregate
  `results/s139-a2-aggregate-20260823-1338/a2-aggregate.json` is `PASS` for
  A2-0 through A2-6. The bounded Pixel 6a cells now include the deterministic
  two-App UID matrix, async cache/concurrency, controlled return, lifecycle
  joins, real allow/drop downstream admission, and replay/resource settlement.
- **Hotspot disposition:** The repeated “verify UID” stop was a compound
  fixture/verdict issue: asynchronous `uid=-1` was treated as terminal,
  A2-6 replay fixtures used stale hard-coded UIDs, and native admission
  evidence used a one-shot shared tuple snapshot. The runner now uses a
  bounded repeat barrier, Java replay derives the accepted UID from the
  registered allow scope, and native admission logs the packet-local tuple
  after the stage-scoped write succeeds.
- **Scope boundary:** This closes the registered A2 POC claims only. The
  consolidated `VPN-F026` Pixel risk remains `OPEN_RISK` for unregistered
  Chrome/IPv6 timing, production cache sizing, reverse-flow Android lookup,
  and external-connect behavior; those are not silently converted to PASS.
- **Architecture impact:** none; B1 remains a separate Plane gate.
