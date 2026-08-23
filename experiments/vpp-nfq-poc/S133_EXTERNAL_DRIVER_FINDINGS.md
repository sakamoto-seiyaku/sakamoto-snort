# SAKAMOTO-133 external-driver and packet-boundary finding inventory

Date: 2026-08-23

This inventory recovers problem-bearing evidence from SAKAMOTO-119--125.  POC
corrections are reference implementations only.  `CLOSED` means the corrected
cell was rerun or a later POC established the invariant; `OPEN_RISK` means the
formal implementation or a future POC must still close the question;
`INCONCLUSIVE` preserves a registered evidence state rather than describing a
defect.

## Evidence inspected

- S119/S120 scheduler records:
  [S119_EXECUTION_JOURNAL.md](S119_EXECUTION_JOURNAL.md),
  [S119_HEV_LWIP_WORKER_MEMO.md](S119_HEV_LWIP_WORKER_MEMO.md),
  [S120_EXECUTION_JOURNAL.md](S120_EXECUTION_JOURNAL.md), and
  [S120_EXTERNAL_DRIVER_MEMO.md](S120_EXTERNAL_DRIVER_MEMO.md).
- S121--S124 packet/cost/real-TUN journals and memos:
  [S121_PACKET_PATH_MEMO.md](S121_PACKET_PATH_MEMO.md),
  [S122_PACKET_PATH_PERF_MEMO.md](S122_PACKET_PATH_PERF_MEMO.md),
  [S123_COST_ATTRIBUTION_MEMO.md](S123_COST_ATTRIBUTION_MEMO.md), and
  [S124_REAL_TUN_MEMO.md](S124_REAL_TUN_MEMO.md), with their corresponding
  `S12x_EXECUTION_JOURNAL.md` records and `results/s122`/`results/s123` raw
  result trees.
- S125 registered design, chronological journal, parser tests, and decision
  memo: [S125_POC7_DESIGN.md](S125_POC7_DESIGN.md),
  [S125_EXECUTION_JOURNAL.md](S125_EXECUTION_JOURNAL.md), and
  [S125_COPY_INVESTMENT_MEMO.md](S125_COPY_INVESTMENT_MEMO.md).
- Plane conclusions/comments were cross-checked where available.  Local
  journals remain the hash-bearing evidence source.

## Retained findings

### F133-01 -- Bounded stepping without readiness scheduling still polls

- **First observation / environment:** Host S119/S120 VPP worker seam.  The
  temporary `driver_step(budget=1)` returned after one quantum and kept HEV/lwIP
  callbacks on worker 1, but the S120 trigger allocated/re-enqueued work every
  turn and `next_timeout_ms` did not control scheduling.
- **Root-cause confidence:** HIGH; the temporary plugin behavior and counters
  are explicit.
- **POC correction:** OI-1 later replaced unconditional requeue with explicit
  `RUNNABLE`/`WAITING`/`STOPPED`, timer/FD wake publication, stale/duplicate
  rejection, and graph fairness on Host and Pixel.
- **Post-correction evidence:** `S126_OI1_EXECUTION_JOURNAL.md`, all registered
  Host and Pixel cells with owner-thread callbacks and zero residue.
- **Formal invariant:** `WAITING` never self-requeues or busy-polls; only a
  generation-matching wake rearms bounded owner execution.
- **Supports:** External driving can return control to VPP while preserving
  worker affinity.
- **Does not support:** Treating S120 alone as an event-driven idle/wakeup
  design or production scheduler API.
- **Status:** `CLOSED` by OI-1.  Duplicate of F132-06 and the OI-1 findings in
  SAKAMOTO-134.

### F133-02 -- Synchronous echo requires more than one pbuf credit

- **First observation / environment:** Host S121 real VPP-worker packet seam.
  With `inflight_pbuf_credit_limit=1`, ingress still held its pbuf when the
  synchronous receive callback requested output, producing
  `FLOW_STACK_OWNER_PBUF_LIMIT (-5)` and zero output.
- **Root-cause confidence:** HIGH; the raw credit-1 failure and credit-2 rerun
  differ only in the explicit bound.
- **POC correction:** Raise the test owner limit to two and rerun; ingress and
  egress balanced `1/1`, copies `33/33`, queue error zero.
- **Formal invariant:** Credits account for the maximum simultaneously held
  ingress, protocol, and output objects; acquire/release and failure settlement
  are visible and bounded.
- **Supports:** A copy-based worker-local packet seam with explicit ownership
  can close cleanly.
- **Does not support:** Production credit size, asynchronous/multi-packet
  pressure, or zero-copy.
- **Status:** `CLOSED` as a contract finding; capacity sizing remains a gap.

### F133-03 -- A foreign VPP worker called HEV task TLS and crashed

- **First observation / environment:** Pixel 6a S122.  The device stopped in
  the netif-output boundary; instrumentation identified the last operation as
  `hev_task_self()` on the foreign VPP worker.
- **Root-cause confidence:** HIGH; removing the per-packet lookup and rebuilding
  was followed by 16/16 UDP and 16/16 TCP passing matrix cells.
- **POC correction:** Remove the HEV current-task/TLS lookup from the foreign
  synchronous boundary; carry explicit owner context instead.
- **Formal invariant:** No foreign thread calls HEV task-system TLS helpers or
  mutates owner/lwIP state; every mutable callback asserts its canonical owner
  identity.
- **Supports:** The packet boundary is viable when owner context and thread
  affinity are explicit.
- **Does not support:** The test-only patch as a production API or arbitrary
  cross-thread HEV calls.
- **Status:** `CLOSED` for the POC seam; duplicate of the later owner-affinity
  and wrong-owner tripwire findings.

### F133-04 -- TCP fixtures can silently invalidate packet-path measurements

- **First observation / environment:** Pixel S122/S123.  The first long TCP
  fixture failed to advance both sequence spaces; the 1400-byte fixture
  segmented without proving requested packet count; an S123 prebuilt checksum
  update was sensitive to integer promotion and failed after the first packet.
  An earlier UDP fixture also encoded the destination port with the wrong byte
  order.
- **Root-cause confidence:** HIGH; each issue was isolated in raw device runs
  and the corrected matrices passed.
- **POC correction:** Advance both sides' sequence numbers, advertise MSS 1460,
  fail on count mismatch, and replace the checksum update before collecting
  accepted samples.
- **Post-correction evidence:** S122 final 32-cell matrix and S123 288/288
  formal measurement files passed.
- **Formal invariant:** Every performance cell first proves checksum, sequence,
  handshake, packet-count, and byte-ledger correctness for the exact artifact;
  invalid setup cannot contribute metrics.
- **Supports:** Corrected deterministic TCP/UDP fixtures can measure the two
  explicit boundary copies.
- **Does not support:** General TCP segmentation, chained pbufs, production
  checksum cost, or performance conclusions from discarded cells.
- **Status:** `CLOSED` for the registered fixtures.

### F133-05 -- Temporary owner pools imposed false multi-flow ceilings

- **First observation / environment:** Pixel S124 real `VpnService` TUN.  UDP
  32-flow initially completed `7/32`, and TCP stopped at four flows.
- **Root-cause confidence:** HIGH.  The ceilings mapped to eight session slots
  and two TCP PCBs per temporary owner context, not the VPP tuple hash.
- **POC correction:** Expand test-only HEV session/PCB/segment/pbuf pools; the
  rerun completed UDP `32/32` and TCP `8/8` plus `32/32`, with traffic split
  across both owners.
- **Formal invariant:** Pool/credit limits are explicit configuration and part
  of the resource ledger; rejection/overload must identify the exhausted
  resource and must not be misclassified as a routing or architecture failure.
- **Supports:** The two-worker real-TUN ownership seam survives the tested
  flow counts after fixture-capacity correction.
- **Does not support:** A production pool size, capacity, soak, or absence of a
  resource cliff.
- **Status:** `OPEN_RISK` for formal capacity sizing; the POC false ceiling is
  understood and corrected.

### F133-06 -- Background traffic exposed unbounded queue-pressure behavior

- **First observation / environment:** Pixel S124.  A background-traffic run
  recorded 37 queue congestion drops; controlled app-only runs recorded zero.
- **Root-cause confidence:** MEDIUM.  Queue pressure is observed, but the POC
  did not isolate arrival mix, exact queue occupancy, or intended overload
  policy.
- **POC correction:** Isolate the controlled correctness run and retain the
  background result as a pressure signal rather than accepting or hiding it.
- **Formal invariant:** Each owner queue has an explicit bounded capacity,
  admission/overload outcome, occupancy/drop counters, and no ownership leak
  when handoff rejects.
- **Supports:** Controlled correctness is clean and pressure can reach the
  handoff boundary.
- **Does not support:** Safe overload behavior, a capacity number, or a reason
  to change the owner-inline topology.
- **Status:** `OPEN_RISK`; carry into the overload/engineering-envelope batch.

### F133-07 -- Shared output counters raced across workers

- **First observation / environment:** Pixel S125 two-worker UDP check.
  `pbuf-bytes` and `write-bytes` diverged even though transport output was
  byte-correct; the output u64 counters were updated concurrently.
- **Root-cause confidence:** HIGH.  Atomic accumulation restored exact byte
  closure and the rerun exercised both owners.
- **POC correction:** Make the test counters atomic.
- **Formal invariant:** Mutable per-owner accounting is shard-local; any
  process-wide diagnostic aggregation is race-safe and cannot influence
  datapath decisions.
- **Supports:** The mismatch was instrumentation state, not missing packet
  bytes.
- **Does not support:** A process-global mutable transport authority or the
  production telemetry design.
- **Status:** `CLOSED` for POC instrumentation; duplicate of OI-4's no-global-
  mutable-state invariant.

### F133-08 -- Low-bit tuple hashing collapsed even-port TCP flows

- **First observation / environment:** Pixel S125, TCP 8-flow/two-worker short
  check.  Android even ephemeral ports caused the original FNV low bit to map
  every flow to one owner.
- **Root-cause confidence:** HIGH for the fixture/input distribution; the exact
  production tuple population remains unknown.
- **POC correction:** Add a test-only final avalanche, after which both owners
  carried traffic and byte/copy ledgers closed.
- **Formal invariant:** Canonical tuple hashing must be evaluated against real
  Android tuple distributions and sufficient output bits; distribution tests
  must distinguish hash bias from capacity or affinity failure.
- **Supports:** Two owner paths can be exercised when the fixture actually
  distributes tuples.
- **Does not support:** Freezing the avalanche or shard count as the production
  hash contract, or claiming balanced load under real traffic.
- **Status:** `OPEN_RISK` for production hash/distribution design.

### F133-09 -- Dropped handoff buffers were freed twice

- **First observation / environment:** Pixel S125 control arm.  With
  `drop_on_congestion=1`, `vlib_buffer_enqueue_to_thread()` had already freed a
  rejected buffer; the plugin freed it again and VPP ended in `SIGSEGV`.
- **Root-cause confidence:** HIGH; the VPP helper ownership rule was identified,
  the second free removed, and later control smokes remained crash-free.
- **POC correction:** Remove the plugin-side free on helper-rejected buffers;
  retain the failure directory and invalidate its measurements.
- **Formal invariant:** Every enqueue outcome has exactly one documented buffer
  owner and exactly one terminal settlement; helper ownership transfer is part
  of the C interface, not inferred at the call site.
- **Supports:** The crash was an ownership-contract violation in the POC path.
- **Does not support:** That all formal handoff/drop paths are audited or that
  queue pressure is solved.
- **Status:** `CLOSED` for the POC correction; mandatory regression invariant
  for the formal implementation.

### F133-10 -- Burst pacing and diagnostic reads contaminated measurements

- **First observation / environment:** Pixel S125.  Sleeping only after a full
  32-packet batch created queue-overrunning microbursts despite a 10 ms/packet
  average; full `show s124-vpn-tun` also invoked HEV pool/credit diagnostics and
  could delay 20--30 seconds under load.
- **Root-cause confidence:** HIGH for both measurement artifacts.
- **POC correction:** Pace between packets, rerun repaired controls, and add a
  read-only `show ...-lite` snapshot for paired observations.  Invalid cells
  remained excluded.
- **Formal invariant:** Offered-load shape and diagnostic cost are measured and
  isolated; observation cannot call mutable/locking stack diagnostics on the
  hot path or transform a cost cell into a queue-capacity cell.
- **Supports:** Repaired control cells can run without enqueue drops and the
  light snapshot reduces one known observer effect.
- **Does not support:** Passing the registered instrumentation gate or a final
  performance investment decision.
- **Status:** `CLOSED` for the identified harness defects; residual measurement
  variance belongs to F133-11.

### F133-11 -- Two-copy investment evidence is formally inconclusive

- **First observation / environment:** Pixel S122--S125.  The two explicit
  boundary copies are real and measurable.  Representative copy shares are
  small and simpleperf places checksum/lock/netfilter signals above memcpy, but
  required same-artifact controls, instrumentation deltas, thermal recovery,
  and the complete registered matrix were not all valid or completed.
- **Root-cause confidence:** Not applicable; this is an evidence state.
- **POC correction:** Several measurement defects were corrected, then the
  remaining matrix was deliberately paused rather than changing thresholds.
- **Formal invariant:** No zero-copy/lwIP ownership decision is made unless all
  registered correctness, control, resource, instrumentation, and profiling
  gates are valid for matched artifacts.
- **Supports:** Keep the current copy-based path as the baseline; visible copy
  is not presently the first optimization target.
- **Does not support:** `DEFER`, `TARGETED`, `MUST_INVEST`, zero-copy, or a
  production lwIP memory-model conclusion.
- **Status:** `INCONCLUSIVE` and paused.  It is not a blocker for the
  owner-inline feasibility campaign unless a future claim explicitly depends
  on a copy-investment decision.

## Evidence boundaries that are not findings

- S119/S120 prove bounded same-worker HEV/lwIP progress and affinity, not real
  packet ingress/egress or event-driven waiting.
- S121 proves one 33-byte worker-local UDP echo and two explicit copies, not
  multi-buffer pressure or zero-copy.
- S122/S123 synthetic matrices are real Pixel measurements but not real TUN
  concurrency or a complete VPP/TUN/kernel copy budget.
- S124 proves real `VpnService` TUN ingress/return and two-owner local echo.  It
  does not preserve and use an arbitrary original destination for protected
  Direct Egress; OI-3 supplies that later evidence.
- A single flow landing on one owner is expected tuple-hash behavior and cannot
  prove or disprove two-owner isolation.

## Consolidation notes

- Merge F133-01 with F132-06 and the OI-1 cancel/rearm finding under one
  scheduler/wakeup root-cause family while retaining each environment.
- Merge F133-03 and F133-07 with the OI-4 wrong-owner/global-mutable invariants.
- Keep F133-05 (owner pool sizing), F133-06 (queue overload), and F133-08 (hash
  distribution) separate; their symptoms can all look like missing throughput
  but their causes and required POCs differ.
- Keep F133-09 as a distinct exactly-once buffer-ownership finding.
