# SAKAMOTO-139 A2 POC Design Revision

Date: 2026-08-23  
Updated: 2026-08-25 (S155 controlled A2-1 rerun exposed VPN-F061)
Status: evidence-guided working design; A2-1 paused by `VPN-F061`
Scope: Pixel multi-App UID attribution, policy, and transport-admission only

## Outcome

A2 keeps its original question and minimum evidence. It is not reduced to the
cells that already pass, and it does not borrow B1/B2 whole-device Direct
Egress conclusions. The correction is to split the current mixed runner into
independently decidable cells at explicit seams:

- real App traffic generation;
- Android UID attribution and lifecycle;
- VPP policy and transport admission;
- controlled reverse projection;
- downstream broker/socket admission accounting;
- durable evidence capture and verdict evaluation.

Current Pixel evidence supports retaining the nonblocking owner-inline and
UID-independent FlowOwner design. It also shows that the current aggregate
`INSUFFICIENT` result is partly a harness-classification problem: decisive UID
and cache events are durable, and lifecycle control events were observed, while
an empty volatile logcat capture is still used as a global provenance gate.
Lifecycle closure remains unproven because Java and native events are not yet
stage-correlated. The provenance gate and stage model must be corrected rather
than repeated.

This revision does not change ADR-0007, the Plane dependency DAG, or the rule
that B1 remains blocked until A2 closes.

S155 later implemented the A2-1 fixture/stage correction and proved that the
original public-endpoint/startup-stage oracle defect is closed.  The corrected
rerun is still `INCONCLUSIVE`: only 3/8 registered A2-1 tuples produced
decisive native resolver + UID contract joins.  The successor gap is
`VPN-F061`, recorded in
[`S155_A2_UID_MATRIX_RERUN2_RESOLVER_CORRELATION_GAP.md`](S155_A2_UID_MATRIX_RERUN2_RESOLVER_CORRELATION_GAP.md).
Do not continue dependent A2 cells until the TCP owner-lookup and per-flow
stage-correlation seam is repaired or the A2-1 claim is explicitly revised.

## Facts that force the correction

1. The corrected androidruntime fixture produced VPN-bound IPv4/IPv6 TCP/UDP
   tuples for UID 12629 with exact resolver miss, completion, and cache-hit
   evidence. UID attribution itself is not the repeating failure.
2. The latest lifecycle window records app/network scope refresh,
   lookup unavailable/available, and a recovered tuple with
   `uid=-1 -> uid=12629`; the contract also contains miss, completion, and hit.
   The raw data lacks stage correlation, so it cannot prove which repeated
   trigger produced each event or that Java and native caches converged at the
   same stage.
3. `SnortVpnService` is configured with an allowed package and the durable UID
   contract records `ALLOWED_UID_SCOPE uids=[12629]`, but the captured
   `snort-vpn-service.log` is empty. Volatile logcat is therefore not a valid
   sole provenance authority.
4. Current owner-drop evidence proves VPP blocked UID 12629 packets, but the
   protect log contains only broker startup. Aggregate absence cannot prove
   that a particular dropped flow created no broker request or socket.
5. Current `handoff-forward-fd` cells have `shim-rx=0`, `direct return=0`, and
   TUN `tx=0`. Repeating an outbound UID probe cannot manufacture reverse
   evidence.

## Preserved architecture and interruption rules

- UID is attributed after canonical FlowOwner selection. It never enters the
  canonical flow key and never changes a live flow's owner.
- FlowOwner execution never waits for Android lookup, broker work, socket I/O,
  or evidence persistence.
- A TUN-origin packet and a controlled flow-stack-return packet use immutable,
  distinct provenance and the same direction-independent canonical flow key.
- A policy drop never crosses the transport-admission seam.
- Harness defects, missing evidence, endpoint timing, and fixture corrections
  cause `INVALID` or `INCONCLUSIVE`; they do not interrupt the campaign.
- Interrupt only if stable UID attribution requires blocking FlowOwner,
  changing canonical ownership, reviving stale identity, or introducing an
  alternate/unprotected path.

## Revised POC modules and seams

### Traffic Generator module

The interface is one deterministic operation:

```text
emit(stage_id, app_id, family, protocol, source_port, destination)
  -> runtime record
```

Two POC-only Android adapters use the same implementation with different
application IDs so they receive distinct UIDs. Each adapter supports fixed
IPv4/IPv6 TCP/UDP tuples and writes a durable runtime record containing its
package, UID, source port, VPN bind result, VPN network handle, and local
address. Chrome/Maps remain useful historical observations, not the final
deterministic matrix.

### UID Attribution module

The existing contract remains the interface: nonblocking lookup submission,
generation-tagged completion, cache hit, scoped refresh, unavailable result,
and bounded pending/cache state. Android owner lookup and the unavailable/fault
control are its two adapters.

For A2 evidence, every event must also be attributable to a registered stage.
A durable `STAGE_BEGIN` marker sets `cell_id`, `stage_id`, and a monotonic
sequence before traffic is triggered. Contract events and native resolver logs
record that stage until the next marker.

### Policy and Transport Admission module

The interface is the outcome of policy for one identified canonical flow:

```text
decide(flow_id, canonical_key, uid, provenance)
  -> POLICY_DROP | TRANSPORT_ADMITTED
```

`TRANSPORT_ADMITTED` means the packet crossed the post-policy VPN Flow Stack
Packet Boundary. It is not a claim that an external socket connected or that
the destination replied.

### Controlled Return adapter

A controlled Pixel adapter attaches to the actual VPN Flow Stack return seam
used by HEV/lwIP. After a real-App UDP forward packet crosses transport
admission, the adapter produces one bounded reflected payload through that same
return interface. It may synthesize the controlled payload, but it must not
bypass Flow Stack return ingress, canonical distribution, the normal VPP graph,
or the TUN Adapter.

The return packet must carry flow-stack-return provenance, resolve to the same
canonical key and FlowOwner, reuse the attributed UID without another Android
lookup, avoid transport re-entry, increment the actual Flow Stack return and
TUN-TX observations, and be received by the originating traffic adapter.

The durable verifier also decodes the native `tun-output-raw` packet. Its IP
family, source/destination addresses, UDP ports, and payload must match the
originating App record; a text `OUTPUT` ledger cannot mask a malformed packet
header. The OI3 parser must reject unrelated or malformed TUN frames without
clearing the committed target of an in-flight flow, because Android may
deliver IPv6 control frames between ingress and return.

This closes A2 controlled reverse traffic plus identity/provenance. It does not
prove a protected external Direct socket, original-destination send/receive, or
an Internet reply; B1 still owns those conclusions. A pure mock, a VPP-only
tuple injection, or a counter change without TUN/app receipt is insufficient.

### Admission Ledger adapter

The ledger attaches to the actual transport-admission, Android broker, and
socket call sites. A controlled mode may stop before external connect, but it
must use the real broker interface and create, bind/protect, and settle a real
socket for the allow control. A mock downstream adapter is not decisive.

The adapter exposes a durable per-flow ledger with these events:

```text
POLICY_DECISION
TRANSPORT_ADMITTED
BROKER_REQUEST
BROKER_COMPLETION
SOCKET_CREATED
SOCKET_SETTLED
```

The allow control must exercise and settle the real downstream seam so zero
counters are not a dead-instrumentation result. The drop stage uses a fresh
canonical key with no pre-existing PCB, socket, or ledger entry. Its ledger
must contain `POLICY_DECISION=DROP` and zero downstream events for that exact
stage/flow; pre-existing flow state cannot be used to prove socket absence. No
external connect is needed for this A2 claim; B2 repeats the same separation on
the complete real path.

### Evidence Verifier module

Runners only orchestrate the device and capture raw files. They no longer own
dozens of duplicated grep-based acceptance rules. One verifier interface
consumes a registered manifest and an evidence directory:

```text
verify(cell-manifest.json, evidence-directory) -> result.json
```

Package/runtime, contract, VPP, return, broker, and cleanup readers are
internal adapters. This concentrates correlation and verdict semantics in one
module instead of spreading them across each shell runner.

## Required evidence envelope

Every correlated event uses the fields that apply to its stage:

```text
schema
cell_id
stage_id
sequence
monotonic_ns
generation
network_epoch
app_epoch
flow_id
token
canonical_key
direction
packet_provenance
app_package
uid
owner
event
result
reason
```

Every raw bundle also retains:

- device model, Android build fingerprint, serial alias, and wall-clock date;
- APK package-to-UID snapshot, APK path/hash, VpnLite hash, and VPP/plugin
  source provenance;
- active VPN network handle, VPN UID, allowed UID scope, and exact tuple;
- pre/post VPP, resolver, cache, pending, sentinel, broker, socket, and cleanup
  snapshots;
- supported claim and explicit non-claims.

Allowed-package provenance is proved by joining all of the following:

1. a durable `cmd package list packages -U` snapshot;
2. the expected package-to-UID mapping;
3. a durable VpnService builder/configuration receipt showing each successful
   `addAllowedApplication` and a digest of the established VPN configuration;
4. the durable `ALLOWED_UID_SCOPE` contract event;
5. the traffic adapter's runtime UID and VPN network handle;
6. the exact VPN-source tuple observed by VPP.

Logcat remains diagnostic evidence only. Package/UID/policy-scope joins without
the VpnService configuration receipt are narrow provenance and cannot close
A2-0.

The native VPP start outcome is an instrumentation gate in front of those six
joins. For owner-resolver mode, a durable receipt must record `vppMode=5`,
`rc=0`, and the name and SHA-256 of the extracted `tun_poc_plugin` artifact.
A2-0 joins that runtime hash to the plugin hash embedded in the locally built
APK and joins the local APK hash to the installed package snapshot.
A missing plugin, a nonzero native start result, or a missing/malformed start
receipt is `INVALID`; it is not a valid run with an inconclusive UID tuple.
This rule was added after the 2026-08-23 A2-0 fixture established the VPN and
then immediately lost `tun0` because the APK omitted the owner-resolver plugin.

## Revised A2 cell matrix

| Cell | Question and decisive evidence | PASS within cell scope | Non-claims |
| --- | --- | --- | --- |
| **A2-0 session provenance** | Do package, UID, APK, VPN builder configuration, VPN handle, allowed scope, and VPP tuple identify one exact run? | All six provenance joins above match and cleanup is clean | UID correctness beyond captured tuples |
| **A2-1 two-App dual-stack matrix** | Can two deterministic App UIDs each create IPv4/IPv6 TCP/UDP tuples? | Eight exact tuples resolve to the correct App UID with no ambient ambiguity | External connect/reply |
| **A2-2 async cache/concurrency/bounds** | Do four concurrent fresh App/family tuples preserve miss/completion/hit and bounded state? | Exactly four tuples cover both Apps and both IP families; no cross-App hit; each has a same-identity sequence; pending/cache high-water is within declared capacity and returns to zero/bounded steady state | Production cache sizing or load capacity |
| **A2-3 controlled reverse traffic** | Does an actual Flow Stack return-seam reflection reuse canonical owner and UID without loopback contamination? | Same canonical key/owner/UID, no new Android lookup, actual return/TUN-TX counters advance, no transport re-entry, and the originating app receives the payload | Protected external Direct Egress or Internet reply |
| **A2-4 lifecycle native join** | Do registered app, VPN/network, runtime, unavailable, and restore stages invalidate and recover coherently? | Stage-correlated Java/native miss, completion, hit, epoch and cache deltas agree; stale completions are rejected | Real underlay handover, which remains C1 |
| **A2-5 UID allow/drop admission ledger** | Does allow cross the real downstream seam while a fresh dropped canonical key creates no downstream work? | Allow control creates, bind/protects, and settles a real socket; the dropped key has no prior PCB/socket/ledger and its stage has zero admission/broker/socket events | External connect and transport failures, which remain B2 |
| **A2-6 replay and settlement aggregate** | Does the APK/plugin schema retain A1 wrong-owner/generation/duplicate/stale rules and settle resources? | Registered replay passes; Java and native pending/cache ledgers are bounded; broker/socket ledgers settle; no VPP/TUN/socket residue | Production capacity and long lifecycle |

A2 is complete only when A2-0 through A2-6 all pass at their registered scope.
Narrow historical cells may support diagnosis but cannot substitute for a
missing required cell.

#### A2-1 successor gap from S155

S155's controlled A2-1 rerun fixed the old POC oracle and then exposed a
deeper resolver/correlation boundary:

- IPv4/IPv6 UDP tuples can produce correct UID miss/completion/cache-hit joins;
- IPv6 TCP tuples repeatedly complete with terminal `uid=-1` from Android owner
  lookup;
- IPv4 TCP tuples may have App runtime records without native resolver/contract
  joins;
- a delayed resolver query can be logged under the next stage because native
  code samples a process-global current stage rather than carrying a per-flow
  stage identity.

A2-1 therefore needs a repaired production-valid TCP owner lookup contract and
per-flow/per-request stage correlation before another full eight-tuple rerun.
The verifier must distinguish no query, terminal `uid=-1`, Java completion
without native hit, wrong UID, and delayed query logged under another stage.

#### A2-2 concurrency cohort rule

A2-1 owns the complete eight-tuple matrix: two Apps × IPv4/IPv6 × TCP/UDP.
A2-2 is a separate cache-capacity cohort and must register exactly four fresh
tuples, one each for AppA/IPv4, AppA/IPv6, AppB/IPv4, and AppB/IPv6. The
cohort may use UDP for all four members or a deterministic protocol mix, but
source ports must be unique and must not reuse the A2-1 ports. This is
intentional: the native contract declares pending capacity 4 and cache
capacity 4, so all four fresh keys can remain resident and each can prove its
own `MISS_SUBMITTED -> COMPLETION_ACCEPTED -> CACHE_HIT` sequence without
normal eviction. Eviction is a valid bounded-state observation, but it cannot
be used to pair a hit with a different token, flow, generation, or scope.

The traffic fixture uses two evidence-gated waves rather than an in-Activity
`repeat=2` loop. Wave 1 submits the four fresh tuples concurrently with one
operation per launch (`repeat=1`). Within each wave, IPv4 AppA/AppB and then
IPv6 AppA/AppB are submitted as pairs; the native contract gate for one pair
gates the next pair. Wave 1 requires correct-UID `COMPLETION_ACCEPTED` for
both keys in each family. Only then does wave 2 submit the same four exact
tuples once each and require a new correct-UID `CACHE_HIT` for both keys in
each family. The runner snapshots the pre-wave-2 hit counts so a duplicate
hit emitted during wave 1 cannot satisfy the wave-2 barrier. This native
family barrier is evidence-based and prevents the Android `singleTop` Activity
from intentionally racing two same-package workers, which previously made a
second fixed-port UDP send return `EPERM` before entering VPP.

Within each AppA/AppB pair, the runner starts AppA and then waits a short,
configurable 250 ms fixture stagger before starting AppB. This is an intent
delivery guard against Android `singleTop`/ADB launch loss, not a native
serialization barrier: both sockets remain alive for the positive owner-lookup
retention interval, so native pending overlap is still required and measured.

The UDP adapter keeps its socket alive through the asynchronous Android owner
lookup using the existing positive post-send observation delay (A2-2 uses
`timeoutMillis=1200`). Runtime JSONL is captured after the native gates as
final evidence, not polled as the launch barrier; the delay is socket
retention, not a cache-readiness signal.
Wave evidence uses `s139-a2-2-two-wave/v2` with separate `nativeGates` and
diagnostic final `runtimeGates`. A missing native gate or same-identity runtime
sequence is `INCONCLUSIVE`, not an architecture interruption, and the raw
contract/runtime evidence is retained.
The launch-window bounds use Python's process-monotonic
`time.monotonic_ns()`, never wall-clock `date +%s%N`, so host clock rollback
cannot invalidate an otherwise complete run.

The A2-2 verifier therefore requires exactly four registered tuples and exact
App × IP-family coverage. It groups sequence events by stable `(token,
flow_id)` identity, accepts any complete ordered chain within one identity,
and treats a missing same-identity hit or incomplete wave gate as
`INCONCLUSIVE`; a wrong UID or cross-App hit is `FAIL`. A passing result
reports `passedSequences == 4`, verifies both wave key/UID maps, and retains
the durable cleanup wait showing that `CLEANUP` was observed before any normal
force-stop. If the bounded cleanup wait times out, the runner may use a
separately marked emergency force-stop after the wait to prevent residue, but
it must retain the failed wait evidence and the verifier must return `INVALID`
without a post-cleanup final contract.

## Lifecycle event definition

The old `uidContractRefresh*` intents remain fault/control adapters, not the
sole lifecycle proof. A2-4 uses bounded real events:

- **app epoch:** replace or reinstall one POC traffic package, capture the new
  package/UID mapping, and invalidate the affected identity scope;
- **VPN/network epoch:** restart the VPN session and require a new VPN network
  handle; this is not a Wi-Fi/mobile handover claim;
- **runtime generation:** stop/start the attribution runtime and reject a
  deliberately late old-generation completion;
- **provider unavailable/restore:** suppress Android owner lookup, observe no
  admission, restore it, then use the same tuple twice to prove a
  stage-correlated miss/completion/hit sequence.

Each stage uses either a unique tuple or explicit pre/post sequence markers.
The cache-hit retry intentionally reuses the same tuple but must be bracketed by
distinct stage markers and native counter snapshots.

Stage persistence is off the FlowOwner hot path. The control plane publishes a
bounded stage marker; owner/native packet code carries only fixed metadata or a
bounded event record, and a monitor drains it to durable storage. Evidence I/O
must never make UID lookup or FlowOwner execution blocking.

## Verdict semantics

Cell status is no longer overloaded into one `INSUFFICIENT` label:

- `PASS` -- all registered assertions for this cell's exact claim pass.
- `FAIL` -- a registered behavioral falsifier is observed.
- `INVALID` -- provenance, instrumentation, fixture isolation, or cleanup
  prevents interpreting the run.
- `INCONCLUSIVE` -- the run is valid but produces no decisive event before its
  bounded deadline.

`A2_INCOMPLETE` is an aggregate state meaning one or more required cells have
not passed. It is not a per-cell behavioral result. Each runner always attempts
cleanup and writes `result.json`; after raw evidence is preserved, automation
returns nonzero for every non-`PASS` cell. `INVALID` is reserved for
provenance/instrumentation/fixture isolation failure, `INCONCLUSIVE` for a valid
run without a decisive event by its bounded deadline, and `FAIL` for an
observed behavioral falsifier.

The throwaway
[`a2_cell_verdict`](prototypes/a2_cell_verdict/README.md) logic prototype is the
primary source for this status-priority decision. Its in-memory seven-cell
model demonstrates `A2_INCOMPLETE -> PASS` aggregation, keeps an empty volatile
logcat diagnostic from invalidating durable evidence, and separates provenance
or instrumentation failure from a valid bounded run without a decisive event.
It is not the production evidence verifier.

## Existing evidence disposition

Reusable as historical/narrow support:

- corrected UID-12629 IPv4/IPv6 TCP/UDP boundary cells;
- Chrome/Maps IPv4 concurrent observations;
- the latest lifecycle unavailable/restore/repeat window;
- the UID-12629 VPP owner-drop window;
- A1 Host/model and Android live replay artifacts.

Required fresh execution after the harness correction:

- A2-0 durable VpnService configuration and session provenance;
- the deterministic two-App eight-cell matrix;
- stage-correlated concurrent/cache/bounds and lifecycle joins;
- actual Flow Stack return-seam controlled reverse traffic;
- per-flow allow/drop ledger at the real broker/socket seam;
- the final A2 aggregate and cleanup audit.

The historical Wi-Fi-bypassing UID-12620 fixture, overwritten IPv4 raw,
Chrome gateway reverse attempt, S124 local echo, SOCKS, and HEV-only paths are
not decisive substitutes.

## Serial execution order

1. Implement the traffic adapters, stage marker, durable evidence readers, and
   verifier; run Host/static validation and commit a clean checkpoint.
2. Run A2-0. Stop only to correct an invalid fixture or if an architecture
   interruption is observed.
3. Repair `VPN-F061`, rerun A2-1, and checkpoint.  Run A2-2 only after A2-1
   can decisively join the base two-App matrix or the A2-1 claim is explicitly
   revised.
4. Run A2-3 controlled reverse, then A2-4 lifecycle native join.
5. Run A2-5 admission ledger and A2-6 replay/settlement aggregate.
6. Perform the final requirement-by-requirement A2 audit, update the evidence
   artifact/journal/Finding Ledger, and only then unblock B1 in Plane.

No ordinary POC correction requires a discussion stop. A contradictory
architecture finding still interrupts immediately under the preserved rules
above.
