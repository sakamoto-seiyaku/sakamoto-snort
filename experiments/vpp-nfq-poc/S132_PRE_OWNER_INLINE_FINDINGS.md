# SAKAMOTO-132 pre-owner-inline finding inventory

Date: 2026-08-23

This inventory recovers the problem-bearing evidence that predates the
owner-inline OI1--OI5 chain.  It is an input to the cross-POC Finding Ledger,
not an implementation backlog.  A `CLOSED` finding means that a POC correction
was rerun successfully or a later POC established the required invariant; it
does not mean that production code already contains that correction.

## Evidence lineage inspected

- Early Linux/Host and Pixel VPN evidence:
  [ANDROID_VPN_EXPERIMENT_PLAN.md](ANDROID_VPN_EXPERIMENT_PLAN.md),
  [ANDROID_VPN_EXPERIMENT_LOG.md](ANDROID_VPN_EXPERIMENT_LOG.md), and
  [POC_STATUS.md](POC_STATUS.md), including SAKAMOTO-2--7 and SAKAMOTO-10.
- Direct Egress topology lineage: the historical S83--S102 series and the
  recovery/decision material summarized in
  [ANDROID_VPP_CURRENT_STATE_HANDOFF.md](../../docs/ANDROID_VPP_CURRENT_STATE_HANDOFF.md).
  The S98--S102 completion chain is historical `OVERALL_PARTIAL`; it is not the
  current route and is not resumed by this inventory.
- Pinned HEV/lwIP isolation and execution-topology frontier: SAKAMOTO-114--118,
  especially the authoritative SAKAMOTO-117 Plane conclusion
  `PAIRED_PASS / INLINE_BLOCKED_CORRECTNESS / OVERALL_NEED_REFACTOR`.
- Later corroboration used only to classify status or duplication:
  [S119_HEV_LWIP_WORKER_MEMO.md](S119_HEV_LWIP_WORKER_MEMO.md),
  [S127_OI2_EXECUTION_JOURNAL.md](S127_OI2_EXECUTION_JOURNAL.md), and
  [OI_REQUIREMENT_AUDIT.md](OI_REQUIREMENT_AUDIT.md).

## Retained findings

### F132-01 -- HEV child-path teardown emitted an allocator failure

- **First observation / environment:** Linux Host POC-C3 completed one real
  curl/TUN/VPP/HEV/SOCKS HTTP flow, but HEV stderr emitted
  `free(): invalid size` after the datapath result.
- **Evidence:** `ANDROID_VPN_EXPERIMENT_PLAN.md` records the risk; the
  chronological C3 record is in `ANDROID_VPN_EXPERIMENT_LOG.md`.
- **Root-cause confidence:** LOW.  The datapath completed and later Android
  lifecycle probes did not reproduce the signal, so the exact double-free or
  allocator owner was never isolated.
- **POC correction:** Split Android Phase 3A into a packaging/lifecycle probe
  before reconnecting the full datapath; retain stderr and process-residue
  evidence.  This was an evidence-isolation correction, not a root-cause fix.
- **Formal invariant:** Every Flow Stack generation must have explicit
  allocation/ownership/close ledgers and a bounded teardown result; a clean
  packet result cannot override an allocator or residue failure.
- **Supports:** The early full Host datapath was technically viable, while its
  lifecycle evidence was not clean enough to promote directly.
- **Does not support:** A claim that the allocator defect is fixed, or that the
  old child/SOCKS path is production-safe.
- **Status:** `OPEN_RISK` on the historical child path; that topology is
  superseded, but the teardown invariant remains applicable.

### F132-02 -- Synchronous protect brokerage blocks the caller

- **First observation / environment:** Pixel 6a protect POC.  The HEV child
  kept the original upstream socket, sent an `SCM_RIGHTS` duplicate, and waited
  for the app parent to perform `VpnService.protect()` before bind/connect.
- **Evidence:** `POC_STATUS.md` SAKAMOTO-3 evidence and known-gap boundary;
  the historical implementation is `android/vpn-lite/native/vpn_fd_probe.c`.
- **Root-cause confidence:** HIGH.  Waiting for the broker result is explicit
  in the old one-request-at-a-time protocol.
- **POC correction:** None in the old path.  OI-2 later replaced it with
  separate bounded request/completion channels and an asynchronous Android
  broker, then passed Host and Pixel cells.
- **Formal invariant:** A FlowOwner may submit a descriptor duplicate and
  continue graph work, but must never perform synchronous JNI, `poll`, `recv`,
  bind/protect, connect, or send while awaiting Android platform work.
- **Supports:** Android bind/protect can be performed across the process
  boundary before transport use.
- **Does not support:** Reusing the old synchronous broker on a canonical
  FlowOwner, broker concurrency, or lifecycle correctness.
- **Status:** `CLOSED` as an architecture finding by OI-2; the old correction is
  reference-only.  Duplicate of the OI-2 broker findings in SAKAMOTO-134.

### F132-03 -- A harness accept ceiling produced a false lifecycle failure

- **First observation / environment:** Pixel 6a 50-cycle VPP/HEV lifecycle
  campaign.  The first formal attempt stopped at a 32-accept limit in the mock
  SOCKS fixture rather than at a target-runtime limit.
- **Evidence:** `POC_STATUS.md`, SAKAMOTO-4 known-gap record.  The clean rerun
  completed 50 start/HTTP/protect/stop cycles with stable active fd counts and
  no stopped-process, TUN, route, or rule residue.
- **Root-cause confidence:** HIGH; the fixture limit was reproducible and
  removed before the from-scratch rerun.
- **POC correction:** Remove the harness-only limit and invalidate the earlier
  run instead of interpreting it as product capacity.
- **Formal invariant:** POC fixtures must expose and report their own admission
  limits; a harness ceiling cannot be used as target capacity or failure
  evidence.
- **Supports:** Short-flow process recreation was stable for the registered 50
  cycles after fixture correction.
- **Does not support:** Long-lived flows, parallel load, process death, handover,
  sleep, or production capacity.
- **Status:** `CLOSED` for the POC harness.

### F132-04 -- Screen-off TCP latency remained near four seconds

- **First observation / environment:** Pixel 6a SAKAMOTO-7, three 300-second
  TCP and three 300-second UDP rounds with simulated battery unplug and
  screen-off/Doze.  App/VPP/HEV stayed alive for 96/96 samples, but TCP p95/p99
  remained about 4.05/4.06 seconds.
- **Evidence:** `POC_STATUS.md` current result and known-gap boundary.
- **Root-cause confidence:** LOW.  The experiment did not separate Android
  scheduling/background-service delay from VPP, HEV, SOCKS, or endpoint delay.
- **POC correction:** None.  The run correctly retained a resource-stability
  GO and a background-TCP HOLD instead of broadening one into the other.
- **Formal invariant:** Lifecycle/resource health and traffic latency are
  separate evidence dimensions; background/device-state cells must include a
  comparable foreground or local-path control before attributing latency.
- **Supports:** One bounded Pixel idle/load window had stable process and
  resource behavior.
- **Does not support:** Acceptable background TCP latency, battery
  certification, or identification of the responsible layer.
- **Status:** `OPEN_RISK`; carry to the engineering-envelope and lifecycle gap
  map, not as an owner-inline architecture contradiction.

### F132-05 -- Tuple attribution needs sticky, nonblocking flow ownership

- **First observation / environment:** Pixel Android owner lookup could return
  a package UID for early TCP packets and `-1` for later packets on the same
  tuple.  A one-entry VPP-side tuple cache retained the earlier attribution;
  a 20-packet UDP burst then required one resolver query.
- **Evidence:** `POC_STATUS.md` current results and known gaps for Android owner
  lookup/cache and VPP-internal UID enforcement.
- **Root-cause confidence:** MEDIUM.  Resolver volatility is observed, while
  its timing and all Android API causes were not isolated.
- **POC correction:** A minimal one-active-tuple cache, sufficient only for the
  scoped functional proof.
- **Formal invariant:** UID attribution is resolved outside the owner hot path,
  cached by canonical tuple/provenance with bounded lifetime, and never allowed
  to change the owner/shard key for an existing flow.
- **Supports:** VPP-internal UID allow/drop and a minimal cached lookup are
  viable for tested IPv4/IPv6 TCP/UDP cells.
- **Does not support:** Production cache size, expiry, reverse-flow semantics,
  concurrency, nonblocking miss handling, or network-epoch refresh.
- **Status:** `OPEN_RISK`; this becomes a dedicated future claim family rather
  than a reason to reopen Direct Egress.

### F132-06 -- The pinned HEV public scheduler takes over a VPP worker

- **First observation / environment:** SAKAMOTO-117 on Host and Pixel 6a.  The
  pinned public HEV path had no bounded step symbols and a real WAITIO run held
  the calling worker for about 250 ms; the direct inline arm was therefore a
  correctness blocker.  The paired native-thread arm passed its scoped
  transport/protect/cleanup proof.
- **Evidence:** Authoritative SAKAMOTO-117 Plane comment and later reproduction
  in `S119_HEV_LWIP_WORKER_MEMO.md` (`hev_task_system_run()` takeover around
  125/127 ms in the narrower runner).
- **Root-cause confidence:** HIGH.  The takeover/wait behavior is the public
  scheduler contract, not a statistical performance effect.
- **POC correction:** S119/S120 introduced a temporary bounded external-driver
  step; OI-1 later added explicit `RUNNABLE`/`WAITING`/`STOPPED`, wait-only
  wakes, stale/duplicate rejection, and fairness.
- **Formal invariant:** HEV/lwIP execution on a FlowOwner is entered only
  through a bounded drive call with quantum/wall limits; `WAITING` returns to
  VPP and is rearmed only by matching packet/fd/timer/control wakes.
- **Supports:** The blocker was the scheduler seam, not a proof that
  owner-local lwIP state or owner-inline architecture was impossible.
- **Does not support:** Selecting paired-thread as the production topology or
  treating the temporary step function as a production API.
- **Status:** `CLOSED` as an architecture blocker by the later external-driver
  and OI-1 evidence.  Duplicate of SAKAMOTO-133 scheduler findings.

### F132-07 -- Mechanical TLS isolation could not construct independent lwIP domains

- **First observation / environment:** Host SAKAMOTO-114 against exact pinned
  HEV/lwIP.  A bounded TLS surgery failed reproducibly at the TCP PCB
  declaration/static-initializer boundary: the listen/active/TIME_WAIT lists,
  list table, and `tcp_active_pcbs_changed` could not become independent domains
  through mechanical thread-local conversion; the list table also required
  runtime/context construction.
- **Evidence:** Authoritative SAKAMOTO-114 Plane blocker comment, recorded
  surgery/log/resource-ledger hashes, followed by the SAKAMOTO-118 completion
  comment for explicit `FlowStackOwnerContext`.
- **Root-cause confidence:** HIGH for the bounded TLS approach.  It is not a
  claim that same-process isolation was impossible.
- **POC correction:** SAKAMOTO-118 moved PCB lists, allocators/pools, config,
  DNS/session/task/stop state, netif/IP/timer and credits behind an explicit
  context-addressed C API.  Same-process, same-link-image protected IPv4/IPv6
  TCP/UDP, fault/peer-continuity, repeat lifecycle and zero-residue Host cells
  passed.
- **Formal invariant:** Each FlowStackShard owns an explicit mutable transport
  domain; no calling-thread TLS guess, process-global core lock, duplicate image,
  or external child provides ordinary-path isolation.
- **Supports:** Explicit owner contexts are feasible in the pinned source and
  are the correct substrate for later VPP packet and owner-inline seams.
- **Does not support:** Android TUN evidence, a production context layout, shard
  count, or execution topology.
- **Status:** `CLOSED` as an architecture prerequisite by SAKAMOTO-118.

## Evidence boundaries that are not findings

- SAKAMOTO-2 proves a normal app-UID/no-`su` Pixel path, but the device was
  bootloader-unlocked; that is runtime identity evidence, not release-device
  security evidence.
- SAKAMOTO-3 proves bind/protect order and non-recursion for three IPv4 plus
  three IPv6 requests; its fixed Wi-Fi/device-local mock endpoint does not prove
  public relay or network migration.
- SAKAMOTO-5 covers proxy refusal, a short blackhole, and controlled Wi-Fi
  off/on on one Pixel.  No independently controllable second underlay existed,
  so true cross-network handover is untested rather than failed.
- SAKAMOTO-6 covers one 600-second forced-Doze window and wake recovery.  It is
  not a long-term power, OEM-retention, or natural-Doze result.
- S83--S102 and S114--S118 are retained as historical topology evidence.  Their
  partial or superseded paths must not be resumed merely because an individual
  cell passed.

## Consolidation notes

- Merge F132-02 with the directional-channel and broker-lifecycle root causes
  recovered by SAKAMOTO-134; retain the early synchronous protocol as the first
  observation.
- Merge F132-06 with the S119/S120 scheduler seam and OI-1 findings recovered by
  SAKAMOTO-133/134.
- Keep F132-07 separate from scheduler affinity: explicit mutable-state
  isolation and bounded execution are independent obligations.
- Keep F132-04 and F132-05 distinct: one is unexplained background latency, the
  other is attribution consistency/nonblocking ownership.
