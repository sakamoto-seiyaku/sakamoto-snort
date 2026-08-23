# SAKAMOTO-134 owner-inline OI1--OI5 finding inventory

Date: 2026-08-23

This inventory recovers the actual defects and POC corrections exposed while
proving OI1--OI5.  It is problem-centric: passing cells and untested scope are
recorded separately from observed failures.  Every correction remains a POC
reference, not a production implementation.

## Evidence inspected

- [S126_OI1_EXECUTION_JOURNAL.md](S126_OI1_EXECUTION_JOURNAL.md) -- Host and
  Pixel scheduler/wakeup/fairness cells.
- [S127_OI2_EXECUTION_JOURNAL.md](S127_OI2_EXECUTION_JOURNAL.md) -- Host, VPP
  worker, and Pixel Java/native asynchronous broker cells.
- [S128_OI3_EXECUTION_JOURNAL.md](S128_OI3_EXECUTION_JOURNAL.md) -- Host
  original-destination/TUN evidence and controlled Pixel functional matrix.
- [S129_OI4_EXECUTION_JOURNAL.md](S129_OI4_EXECUTION_JOURNAL.md) -- model and
  real two-pthread Host shard evidence.
- [S130_OI5_EXECUTION_JOURNAL.md](S130_OI5_EXECUTION_JOURNAL.md) -- model, Host,
  and controlled Pixel generation/epoch/fault/restart evidence.
- [OI_REQUIREMENT_AUDIT.md](OI_REQUIREMENT_AUDIT.md) -- requirement-level
  provenance, hashes, non-claims, and the scoped `OWNER_INLINE_ACCEPTED`
  interpretation.

`CLOSED` below means that the corrected POC cell and its evidence boundary are
understood.  The invariant must still be implemented and tested again in the
formal version.

## Retained findings

### F134-01 -- A stale cancel byte broke wait-helper rearm

- **First observation / environment:** Host OI-1 mixed timer/FD cell.  A cancel
  byte remained in the shared wait pipe, so the rearmed helper returned
  immediately and missed the expected FD readiness.
- **Root-cause confidence:** HIGH.
- **POC correction / post-correction evidence:** Drain the cancel pipe before
  rearm.  The final Host and Pixel mixed traces accept both timer and FD wakes,
  reject stale/duplicate tokens, keep callbacks on the owner pthread, and end
  with zero residue.
- **Formal invariant:** Wait-helper arm/cancel is an epoch-aware state machine;
  stale control bytes cannot satisfy a new generation, and helper output is an
  opaque wake token only.
- **Supports:** The wait-only helper topology can make timer/FD progress without
  driving HEV/lwIP.
- **Does not support:** Reusing a shared fd without drain/generation rules or
  moving mutable callbacks to the helper.
- **Status:** `CLOSED`; merge with the broader scheduler finding F133-01.

### F134-02 -- One bidirectional broker channel consumed its own completion

- **First observation / environment:** Host OI-2 socket probe.  A single
  bidirectional `SOCK_SEQPACKET` endpoint let the broker read its own completion
  as a request, break the receive loop, and strand the last family/type request.
- **Root-cause confidence:** HIGH.
- **POC correction / post-correction evidence:** Separate bounded request and
  completion channels; Host, VPP-worker, and Pixel matrices then completed all
  family/failure/queue/tripwire/delayed-stop cells.
- **Formal invariant:** Platform requests and owner completions are directional
  channels with distinct ownership, bounded capacity, and unambiguous message
  type/version.
- **Supports:** Asynchronous brokerage works when the directions are explicit.
- **Does not support:** Reusing the historical synchronous or bidirectional
  protocol.
- **Status:** `CLOSED`; consolidate with F132-02 under the broker root cause.

### F134-03 -- Broker stop raced thread publication

- **First observation / environment:** Host OI-2.  `stop_broker()` could run
  before the new thread stored `broker_running=true`; the thread then
  overwrote the stop state and polled forever.
- **Root-cause confidence:** HIGH.
- **POC correction / post-correction evidence:** Add an independent C11 atomic
  stop flag.  Delayed-stop and final Pixel service-stop evidence terminates
  cleanly with no VPP process residue.
- **Formal invariant:** Stop intent is monotonic and publish-before-use; a
  worker/broker start cannot clear a concurrently issued stop, and join is
  bounded.
- **Supports:** The race was a lifecycle seam, not an owner-inline topology
  contradiction.
- **Does not support:** General production process/service lifecycle hardening.
- **Status:** `CLOSED`.

### F134-04 -- Queue completion accounting could finish with work inflight

- **First observation / environment:** Host VPP OI-2 queue-full cell.
  `completed + rejected` reached the expected count while another accepted
  request remained inflight, so its later valid completion was misclassified
  as stale.
- **Root-cause confidence:** HIGH.
- **POC correction / post-correction evidence:** Require `inflight == 0` before
  terminal completion.  The post-fix Host and Pixel queue cells have accepted
  requests completed, rejected sockets closed, and residue zero.
- **Formal invariant:** A generation reaches terminal state only after every
  admitted request has exactly one completion/abort settlement and all rejected
  descriptors have exactly one close.
- **Supports:** Bounded queue rejection can coexist with clean accepted work.
- **Does not support:** A production queue size or overload policy.
- **Status:** `CLOSED`; capacity behavior remains a separate gap.

### F134-05 -- Android packaging omitted network-state authority

- **First observation / environment:** First Pixel OI-2 APK.  Calling
  `ConnectivityManager.getActiveNetwork()` raised `SecurityException` because
  `ACCESS_NETWORK_STATE` was absent.
- **Root-cause confidence:** HIGH.
- **POC correction / post-correction evidence:** Declare the permission,
  rebuild the exact APK, and rerun Java `Network.bindSocket()` then
  `VpnService.protect()` for IPv4/IPv6 TCP/UDP.
- **Formal invariant:** The packaged manifest and runtime authority needed by
  the broker are artifact-gated before interpreting any network failure.
- **Supports:** The failure occurred before the architecture seam and required
  no owner-path redesign.
- **Does not support:** Other Android/OEM permissions or release policy.
- **Status:** `CLOSED` for the selected Pixel artifact.

### F134-06 -- Broker teardown errors could spin

- **First observation / environment:** Pixel OI-2 child teardown.  After the
  stop boundary, a non-`EAGAIN` receive error/`ENOENT` could be logged repeatedly.
- **Root-cause confidence:** HIGH.
- **POC correction / post-correction evidence:** Log the disconnect once and
  exit the broker receive loop; the final artifact stops with no VPP process
  while preserving late-completion rejection.
- **Formal invariant:** Channel disconnect after stop is terminal for that
  broker generation, not a retryable readiness event; teardown cannot spin.
- **Supports:** Bounded broker lifecycle on the tested Pixel sequence.
- **Does not support:** Arbitrary process-death or OS-restart behavior.
- **Status:** `CLOSED`.

### F134-07 -- TUN connectors were never initialized

- **First observation / environment:** Host/Pixel OI-3 TUN branch.  Broker
  submission could succeed while no TCP/UDP owner socket was created because
  the connector callback structs had not been initialized.
- **Root-cause confidence:** HIGH.
- **POC correction / post-correction evidence:** Initialize the connector
  callbacks.  The later Host and controlled Pixel matrix records owner-local
  socket creation, broker completion, Direct send/receive, and cleanup.
- **Formal invariant:** A shard cannot accept a transport flow until all
  protocol callbacks and capability tables are initialized and artifact-
  identity checked.
- **Supports:** This was an implementation omission, not evidence against the
  module boundary.
- **Does not support:** Treating a successful broker request alone as a Direct
  Egress result.
- **Status:** `CLOSED`.

### F134-08 -- Canonical listener normalization lost original destination

- **First observation / environment:** Host/Pixel OI-3.  The real TUN
  destination was passed directly to the canonical HEV listener, conflating
  listener addressing with protected underlay destination/provenance.
- **Root-cause confidence:** HIGH.
- **POC correction / post-correction evidence:** Retain the raw original
  destination for `connect(2)`, normalize only the HEV-submitted copy to the
  canonical listener address, then rewrite owner output back to the original
  endpoint.  Host real-TUN and the controlled Pixel IPv4/IPv6 matrix close
  byte/provenance ledgers with zero residue.
- **Formal invariant:** Packet normalization never destroys immutable original-
  destination/provenance facts; listener view, underlay connect target, and TUN
  return rewrite are distinct typed values.
- **Supports:** One owner-inline path can preserve original destination without
  SOCKS or a second datapath.
- **Does not support:** External/default-route reachability or arbitrary NAT/
  redirection behavior.
- **Status:** `CLOSED` for the bounded seam.

### F134-09 -- Endpoint readiness made timeout classification race-dependent

- **First observation / environment:** OI-3 synthetic underlay/no-reply cells.
  The owner could begin before the endpoint fixture was ready, turning the
  intended timeout/refusal classification into a timing-dependent diagnostic.
- **Root-cause confidence:** HIGH.
- **POC correction / post-correction evidence:** Publish an explicit ready
  latch before starting the owner and apply a 512-step bounded ceiling.  The
  refreshed Host and Pixel cells reach their registered refusal/timeout outcome
  with zero residue.
- **Formal invariant:** Fixture/service readiness is an explicit prerequisite;
  every wait/failure class has a bounded deadline and stable classification.
- **Supports:** Transport refusal, no-reply timeout, and policy drop can remain
  distinct in the tested cells.
- **Does not support:** Arbitrary external RST/`SO_ERROR` behavior or production
  timeout values.
- **Status:** `CLOSED` for the POC fixture; external failure classification is
  still a future evidence gap.

### F134-10 -- A second TUN reader stole packets from the datapath

- **First observation / environment:** Pixel OI-3 controlled run.  A diagnostic
  sidecar sharing the TUN fd could race VPP and consume app ingress.
- **Root-cause confidence:** HIGH; TUN reads are destructive, not observational.
- **POC correction / post-correction evidence:** Make VPP stdout the
  authoritative packet ledger and keep the sidecar at `observer-read=0`; it
  witnesses route/lifetime only.  The final seven-cell matrix then has raw VPP
  ingress/output evidence.
- **Formal invariant:** Exactly one component reads a TUN generation.  Packet
  diagnostics are emitted by that reader or by non-consuming metadata hooks.
- **Supports:** Final Pixel packet evidence is attributable to VPP rather than
  a competing sidecar.
- **Does not support:** Duplicating a TUN fd as a safe packet observer.
- **Status:** `CLOSED`; mandatory formal datapath invariant.

### F134-11 -- Completion watchers accidentally owned inherited broker fds

- **First observation / environment:** OI-5 same-process generation work on
  Host/Pixel.  VPP `clib_file_del_by_index()` closes the descriptor registered
  with it; registering the inherited Android completion endpoint directly
  would destroy broker infrastructure during generation teardown.
- **Evidence:** The documented correction in
  `overlay/src/plugins/hev_external_driver_poc/owner_inline_oi3.c` duplicates
  the completion fd for each watcher.  S130 Pixel generations 1--5 recreate
  their watcher while inherited broker fds remain stable and produce no
  completion `EPIPE`.
- **Root-cause confidence:** HIGH; the VPP file-registration ownership rule is
  explicit and the corrected lifecycle is observed.
- **POC correction:** Register a per-generation `dup()` and retain the inherited
  infrastructure descriptor for subsequent generations.
- **Formal invariant:** Registration APIs have explicit fd ownership; every
  generation owns and closes only its watcher duplicate, never the inherited
  broker channel.
- **Supports:** Same-process restart can preserve broker infrastructure while
  replacing generation-local watchers.
- **Does not support:** Leaking or sharing generation-local readiness state.
- **Status:** `CLOSED`.

### F134-12 -- Stop could race the first owner token

- **First observation / environment:** OI-5 lifecycle integration.  A stop
  issued before the first queued owner token was consumed could otherwise let
  that token start a new context after stop intent.
- **Evidence:** The POC source marks `finish_requested` before enqueueing the
  stop token and finishes only after the current owner token/buffer residue is
  reclaimed.  Host restart/fault and controlled Pixel normal/fault/restart
  sequences settle every generation with residue zero.
- **Root-cause confidence:** HIGH for the identified ordering race.
- **POC correction:** Publish monotonic finish intent before stop work and gate
  final destruction on reclaiming the current owner token.
- **Formal invariant:** Admission closes before quiesce; no queued start can
  cross a stop-generation boundary, and final destruction waits for all
  obligated owner tokens/buffers to settle.
- **Supports:** The bounded stop/restart ordering on the enumerated Host/Pixel
  sequences.
- **Does not support:** Unbounded soak, concurrent service death, or production
  restart policy.
- **Status:** `CLOSED`.

## Passing evidence and exact boundaries

| Gate | Highest-fidelity evidence | Supported conclusion | Explicit non-claim |
| --- | --- | --- | --- |
| OI-1 | Host + Pixel arm64 | `SCOPED_SCHEDULER_WAKE_GO` | No broker, Direct Egress, multi-owner, production topology |
| OI-2 | Host + Pixel Java/native broker | `SCOPED_ASYNC_BROKER_GO` | No full remote TUN, capacity, migration, production lifecycle |
| OI-3 | Host + controlled Pixel IPv4/IPv6 TCP/UDP and failure matrix | `SCOPED_DIRECT_EGRESS_GO` | No external/default route, arbitrary device traffic, capacity, soak |
| OI-4 | Deterministic model + real two-pthread Host UDP/TCP | `SCOPED_SHARD_ISOLATION_GO` | No Pixel multi-owner, four-worker, pressure, capacity |
| OI-5 | Model + Host + controlled Pixel generations/fault/underlay | `SCOPED_GENERATION_TEARDOWN_GO` | No arbitrary route, pressure, capacity, soak, release |

Together these support `OWNER_INLINE_ACCEPTED` only within the bounded POC
contract.  They do not freeze a production implementation.  The architecture
baseline remains revisable if later, higher-fidelity evidence contradicts a
required invariant or exposes a material constraint.

## Untested scope is not a finding

- OI-3/OI-5 Pixel routes only `10.200.0.0/24` or `fd00:200::/64` to a loopback
  underlay; external/default-route behavior is untested, not failed.
- OI-4 real two-owner transport is Host-only.  Pixel multi-owner isolation is
  an evidence gap, not a device defect.
- Capacity, overload policy, sustained pressure, soak, power/thermal envelope,
  and release lifecycle were deliberately outside OI1--OI5.
- The controlled refusal fixture establishes one bounded classification seam;
  it is not general external-kernel refusal evidence.

## Consolidation notes

- Consolidate F134-02 through F134-06 into distinct broker sub-causes under one
  higher-level asynchronous-broker family; do not erase their separate
  ownership and lifecycle invariants.
- Consolidate F134-07/F134-08 with original-destination/provenance findings, but
  keep callback initialization separate from address normalization.
- Keep F134-10 (single TUN reader), F134-11 (watcher fd lifetime), and F134-12
  (stop/token ordering) distinct; all can manifest as missing traffic during
  teardown but have different owners and regression tests.
