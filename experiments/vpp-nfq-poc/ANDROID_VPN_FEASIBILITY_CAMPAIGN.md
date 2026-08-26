# Android VPN Implementation Feasibility POC Campaign

Execution safety and evidence discipline are defined by
[`ANDROID_VPN_POC_EXECUTION_GUARDRAILS.md`](ANDROID_VPN_POC_EXECUTION_GUARDRAILS.md).
Every device POC must satisfy that runbook's provenance, fixture-validity,
classification, bounded-retry, and hotspot-stop gates. Plane owns open work;
this campaign document records scope and evidence rather than a parallel
backlog.

Status: research contract, 2026-08-23
Updated: 2026-08-26 (S140 Pixel real-network validity gates; S156 hotspot; S157 TUN re-arm correction; S158 topology implementation; S159 D3 submit hotspot; S160 overload/recovery execution and ambient-flow hotspot; S161 timed D3 recovery closure; S163 E1/E2 execution; S169 F045/F046 closure; S170 post-F046 E1 resource trend; S171 bounded E2 sample and F047 TCP idle-timeout closure; S172 matched HTTP baseline comparison-APK, admission, and request-shape closure; S173 foreground HTTP staircase owner-capacity closure; S174 bounded 8-request HTTP staircase execution; S175 bounded 16-request HTTP staircase execution; S176 UDP multi-flow route-pinning closure; S177 final resource short slice and ADB harness closure; S178 final B1 dual-stack DNS dataplane/lifecycle split; S179 current-artifact controlled B2 failure-semantics regression; S180 B1 forced DNS fallback fixture; S181 real no-reply and closed TCP timeout fixture; S182 representative target-IP policy drop; S183 representative AppA UID drop; S184 bounded real LAN TCP RST propagation closure; S185 bind/protect/broker infrastructure failure separation; S141 B2 final closure audit; S152 A2 UID matrix design gap; S156 A2 resolver/correlation closure; S199--S223 E2 write-interest, owner handoff, TCP owner lifecycle, and device-state correction; S224 current F072-candidate E1 resource trend; S225--S229 E2 CPU-budget and HEV-baseline hotspot isolation; F074 Android VPP barrier-held idle CPU closure; S231/S232 post-F074 Direct/OI3 foreground CPU-budget reruns)
Tracker: SAKAMOTO-131
Scope: non-root Android VPN/TUN Runtime Profile

This document defines the bounded research campaign that precedes formal Android
VPN implementation. It records what remains stable while preserving room for
the evidence-guided roadmap to change. It is not a production specification,
release gate, capacity sizing decision, or POC implementation source.

## 1. Objective and completion level

The campaign asks:

> Can the accepted Android VPN architecture be implemented correctly on the
> target arm64 Android environment with bounded resources, explicit failure and
> overload behavior, and convergent network/runtime lifecycle semantics?

The completion level is **Android VPN Engineering Feasibility**. Reaching it
requires more than a one-shot connection: the campaign must show a working
minimum complete VPN dataplane, real network and lifecycle behavior, application
UID attribution sufficient for per-app policy foundations, bounded ownership and
teardown, and no architecture-level resource or performance failure.

The final feasibility audit is claim-family based. The following required
families must each have valid Pixel evidence for the Android-specific portion,
with Host/model evidence allowed to complete deterministic subcoverage:

- minimum full-device VPN dataplane: real IPv4/IPv6 TCP and UDP, including DNS
  as ordinary TCP/UDP traffic, policy allow/drop separation, and TUN return;
- application identity: distinct real App UIDs, cache hit/miss and refresh,
  non-blocking lookup, and no FlowOwner-key contamination;
- network and lifecycle: real underlay creation, bind/protect, network/epoch
  change, stop, fault, restart, stale-event rejection, and teardown settlement;
- ownership and failure: owner-local execution, representative multi-owner
  isolation, bounded overload behavior, and no cross-owner state or callback
  pollution;
- engineering envelope: bounded flow/socket/buffer/timer resources, no
  increasing FD/thread/RSS trend in the tested envelope, and no
  architecture-level performance cliff.

An `INCONCLUSIVE`, `INVALID`, or `INSUFFICIENT_EVIDENCE` result in any required
family blocks campaign completion; an `INVALID` family is treated as
insufficient evidence rather than as a passing omission. A `FAIL` either drives an `ADJUSTMENT_REQUIRED`
continuation or, when it contradicts a baseline invariant, `REOPENS_ARCHITECTURE`.
Claims explicitly outside this contract remain non-claims rather than hidden
completion failures, but must be listed in the final audit.

This level does not require final production constants, release-budget proof,
OEM compatibility, product UI, persistent storage, or a release artifact.

## 2. Product and architecture boundary

The campaign covers the non-root VPN/TUN Runtime Profile:

- Android `VpnService` TUN ingress and return.
- The shared VPP graph, canonical FlowOwner selection, and VPN provenance.
- Owner-inline HEV/lwIP Flow Stack execution and owner-local Direct Egress.
- Android bind/protect broker behavior before socket connect or first send.
- Original-destination IPv4/IPv6 TCP and UDP, including DNS as ordinary TCP or
  UDP traffic.
- Minimum policy allow/drop behavior sufficient to prove that policy drop does
  not enter transport.
- Application UID attribution needed by the per-app policy foundation:
  distinct real App UIDs, cache hit/miss, non-blocking lookup, and lifecycle
  refresh. Full Application Catalog and UI identity presentation are outside
  this campaign.
- Underlay/network epoch changes, stop, injected fault, bounded restart,
  stale-event rejection, resource settlement, and representative engineering
  envelope evidence.

Root/NFQUEUE is a parallel Runtime Profile with an already evidenced basic
route. Its evidence may be reused for shared VPP, ownership, and completion
principles, but Root hooks, queue placement, and verdict behavior are not
reopened or re-run by this campaign.

## 3. Evidence-backed Architecture Baseline

The current baseline is the owner-inline external-driver topology selected by
the bounded OI1–OI5 evidence and recorded in
`docs/adr/0007-owner-local-lwip-direct-egress.md` and
`experiments/vpp-nfq-poc/OI_REQUIREMENT_AUDIT.md`.

The baseline means:

- The canonical FlowOwner is the only executor of its HEV/lwIP mutable
  callbacks.
- A FlowOwner-local Flow Stack shard is fixed for the lifetime of a live flow;
  live migration, alternate-owner spill, and a second egress hash are not the
  default design.
- A wait-only helper may observe fd/timer readiness and publish an opaque,
  generation-tagged wake. It cannot execute Flow Stack callbacks or own
  transport state.
- The Android broker performs platform-only underlay bind and
  `VpnService.protect()`. The owner consumes the directional completion and
  alone continues, fails, or tears down transport state.
- Protected sockets have an underlay epoch fixed at creation. There is no
  unprotected retry or implicit Direct/SOCKS fallback.
- TUN-origin and Flow-Stack-origin packets use one shared graph and immutable
  provenance; provenance is not inserted into the canonical flow key.
- Generation/epoch gates cover packet, wake, timer, broker, socket, output,
  ownership token, and teardown events.
- VPP workers do not wait for socket I/O, Android APIs, timers, name
  resolution, or capacity. Overload is explicit runtime/transport evidence,
  not a policy verdict or a bypass.

This is a revisable baseline, not an immutable freeze. Ordinary harness or
implementation-seam corrections do not reopen it. Contradictory higher-
fidelity evidence, a material platform constraint, a safety failure, or a
clearly superior route may reopen the affected decision explicitly.

## 4. Evidence roles and target environment

### Pixel 6a

The dedicated Pixel 6a arm64 Android device is the highest-fidelity and final
device-level feasibility environment for this campaign. It is the required
decision environment for Android-specific behavior: TUN, `VpnService`, Android
socket protection, Network/underlay behavior, UID attribution, bionic/NDK
integration, scheduler interaction, lifecycle, real network, and target-device
resource measurements.

The device is dedicated to this project. Real whole-device IPv4/IPv6 VPN
routing is allowed for network POCs, including traffic from the terminal and
other controlled applications. Narrow routes or per-App isolation may be used
for a diagnostic cell, but cannot replace final full-device network evidence.

Pixel evidence proves this target environment, not all third-party OEM systems.
OEM-specific compatibility is outside the current campaign and is a later
post-release concern.

### Host and deterministic model

Host x86 and deterministic models remain valid evidence where they answer a
platform-neutral question more completely or reproducibly:

- state transitions and scheduler order;
- stale/duplicate event matrices;
- exact resource ledgers and fault injection;
- ownership tripwires and cross-owner isolation;
- bounded model coverage that is impractical to enumerate on-device.

Host evidence does not substitute for Pixel on Android-specific behavior,
real arm64 integration, underlay/network transitions, UID APIs, or target
capacity. If Host and Pixel appear to conflict, first verify that the same
question, artifact, scope, and evidence semantics were used; the Pixel result
decides Android-specific behavior.

## 5. Stable rules and revisable roadmap

Stable for the campaign:

- the engineering-feasibility objective;
- VPN-only scope and Root/NFQUEUE non-reopening boundary;
- evidence roles and Pixel final-device rule;
- the Evidence-backed Architecture Baseline and its reopen rule;
- the distinction between POC Correction and formal implementation;
- the Finding Ledger and Evidence Gap Map as separate inputs;
- lightweight evidence discipline and two-level conclusion vocabulary;
- continuous execution unless an interruption condition is met.

Revisable from evidence:

- the number, order, and grouping of POCs;
- Evidence Batch membership and blocking edges;
- exact traffic cells, endpoint fixtures, network conditions, and durations;
- worker/shard counts, queue/credit/buffer sizes, timer budgets, and load
  levels;
- the concrete Android harness, monitoring, and artifact layout;
- which gaps can be closed by Host/model and which must be repeated on Pixel.

The roadmap is therefore an **Evidence-Guided POC Roadmap**, not a fixed
checklist. A change to it must state which finding or gap caused the change.

## 6. Continuous execution rule

POCs are organized into Evidence Batches by their shared upper-level
engineering question, not by a fixed count. A planned chain runs continuously:

1. Finish the registered cells and exploratory follow-ups for the current POC.
2. Record ordinary findings, apply the smallest POC Correction needed to make
   the question observable, and rerun affected cells.
3. Continue to the next POC or batch when the current question is settled; do
   not hold a decision meeting after each cell or partial result.
4. After the planned campaign chain, combine all evidence and perform the
   feasibility audit.

Execution stops early only when one of these conditions holds:

- a core invariant of the Evidence-backed Architecture Baseline is contradicted;
- correctness requires paired-thread transport execution, global mutable
  authority, live migration/spill, an unprotected fallback, or a second packet
  path;
- the remaining POC premise is invalid, so continuing cannot produce an
  interpretable result;
- a registered multi-owner POC has no corresponding multi-owner artifact,
  owner registry, or tuple-to-shard dispatch (S158); running it against a
  single-owner artifact would be invalid evidence;
- the device safety boundary or controlled-network scope is violated;
- new authority, external infrastructure, or an irreversible operation is
  required;
- a materially superior architecture makes the remaining old-route work
  unreasonable.

Build, deploy, harness, timing, logging, FD lifetime, cleanup, and similar
ordinary defects are findings. They receive a POC Correction and continue the
chain unless they expose one of the interruption conditions above.

## 7. Lightweight POC Protocol

Before a POC, register only:

- its main question and current working assumption;
- the decisive counter-evidence;
- the safety boundary;
- the minimum facts required for a supported conclusion;
- Host/model/Pixel responsibilities and known non-claims;
- for a Pixel real-network cell, transitive source→stage→APK→installed-runtime
  artifact identity plus the exact package UID, Android permission/compat state,
  active underlay snapshot, and same-UID endpoint control needed to establish
  that the run is valid.

Shell network controls do not establish an application's Android network
eligibility. A LAN fixture must pass a direct control from the UID that owns the
protected socket before a missing reply is interpreted as Flow Stack evidence.
The broker must also record and select a non-VPN physical Network: after a VPN
is established, `ConnectivityManager.getActiveNetwork()` is UID-scoped and may
return the VPN itself. A bind/protect API success on that VPN Network does not
prove wlan0/underlay egress and is invalid real-network evidence.
Likewise, an APK is not identified only by its outer hash when multiple staged
plugin spellings can overwrite the same packaged runtime member. These are
preflight validity gates, not new architecture claims or a new Evidence Batch.
The S142 B1 cell added a datapath validity boundary: a full-route TCP connector
must preserve multiple application writes.  S143 initially reproduced the
short-segment ACK/owner-progress hotspot, then closed it by adding the missing
owner-context ACK-only output path (`tcp_output_ctx()` previously returned when
the delayed-ACK PCB had no unsent segment).  Fresh Pixel separate/coalesced
IPv4 DNS-over-TCP arms now both return the complete 61-byte response with exact
TUN settlement and zero residue.  The stream hotspot is therefore closed for
this artifact.  S146 then reproduced a separate B2 design defect: the first
full-TUN refusal cell satisfied the native expected-transport-failure invariant
but the shared positive-path cleanup verdict emitted `result=FAIL`, while the
app probe emitted an ambiguous zero-byte `result=OK`.  S147 corrected and
reran the cell-aware negative-result contract, so B2 is unblocked for its
controlled claim.  IPv6 and the remaining engineering envelope remain open
and cannot be substituted by the paired positive regression.

S147 corrected and reran the B2 negative-result contract; S149 then passed the
controlled OI5 normal/fault/restart lifecycle seam with zero residue.  S150
subsequently reproduced a real Pixel Wi-Fi handle loss/replacement while an
AppA TCP flow was active and recorded the missing callback/epoch seam as
`VPN-F033`.  S151 added that seam, demonstrated owner-side invalidation and
zero-residue settlement, and verified fresh IPv4/IPv6 traffic after one
bounded explicit VPN-session restart.  C1 is therefore unblocked for the
selected Pixel artifact under the explicit restart contract; seamless Android
VPN migration is not claimed.  S152 then ran the first real AppA stop cell and
found a new C2 lifecycle-design hotspot: the active socket was aborted and
resources settled, but native cleanup emitted `FAIL outcome=EXPECTED_DIRECT_REPLY`
because explicit normal stop has no distinct terminal classifier.  C2 is
paused until that contract is corrected and rerun.  S153 corrected the
  classifier and reran the same real AppA cell with `PASS_EXPECTED_STOP`,
  `EXPECTED_STOP`, and zero residue.  S155 then showed that the first fresh
  IPv4 flow after formal stop/start passes, but a second IPv6 flow in the same
  session sees no `TRANSPORT_VPN` because ordinary OI3 completion closes the
  detached TUN.  S156 recorded that lifecycle/design hotspot; S157 corrected
  it by retaining/re-arming the TUN between successful positive generations
  and reran real same-session IPv4→IPv6 DNS plus an active-flow fault with
  zero residue.  S158 then audited the final D topology and found that the
  selected OI3 artifact still exposes one global owner/context/queue/TUN and
  one Android worker, with no tuple-to-shard dispatcher. D1 is therefore
  `BLOCKED_BY_DESIGN`, D2/D3 are dependent, and E1/E2 are paused; this is a
  design/spec decision point rather than an Android connectivity or fixture
  retry. Arbitrary concurrency and seamless Android migration remain
  non-claims.

During execution, exploratory cells, random schedules, fault injection,
additional observations, and harness corrections are allowed. Additions must
remain visible and must not silently weaken a gate. At completion, seal the
artifact identity, raw evidence, environment, findings, supported conclusion,
and non-claims.

## S158 D1-D3 design interruption (historical; superseded by S159)

[`S158_D_FINAL_TOPOLOGY_OWNER_OVERLOAD_HOTSPOT.md`](S158_D_FINAL_TOPOLOGY_OWNER_OVERLOAD_HOTSPOT.md)
records the final-topology audit. The S157 artifact is valid for the corrected
single-owner C2 contract, but the OI3 implementation has one process-global
owner state and the Android launcher fixes `workers 1`/`target-thread 1`.
There is no final owner registry, tuple-to-shard dispatch, or independent
per-owner resource/overload ledger. Consequently the registered Pixel D1
question is not executable against this artifact; D2/D3 and E1/E2 are paused.
The campaign must either implement the final multi-owner route and rerun the
dependent batches, or explicitly narrow its feasibility claim to single-owner
operation.

## S159 D3 submit/backpressure interruption (2026-08-24)

The final multi-owner route is now present and D1/D2 have bounded Pixel
evidence. The single permitted corrected D3 pressure rerun exposed a second
runtime seam: after 15 successful HEV submits, 49 same-owner submits returned
`-5`. They are now explicitly classified and settled without VPP residue, but
the accepted flow produced no reply and timed out. This is recorded in
[`S159_D3_HEV_SUBMIT_BACKPRESSURE_HOTSPOT.md`](S159_D3_HEV_SUBMIT_BACKPRESSURE_HOTSPOT.md).

Roadmap status is `ADJUSTMENT_REQUIRED`, not architecture replacement:
recover the pinned HEV submit contract, define bounded retry/admission and
credit release, then rerun D3 once and prove a normal-flow recovery. E1/E2
remain paused until that D3 gate closes. No further pressure attempts are
authorized against the current artifact.

## S160 D3 overload/recovery execution interruption (2026-08-24)

[`S160_D3_OVERLOAD_RECOVERY_EXECUTION_JOURNAL.md`](S160_D3_OVERLOAD_RECOVERY_EXECUTION_JOURNAL.md)
records the matched same-tree core/plugin/APK rerun. The arm64 HEV
disassembly maps submit return `-5` to category-1 inflight-pbuf credit
exhaustion. The corrected adapter settled the current packet, preserved the
owner, and produced three bounded multi-owner UDP generations with
`PASS_EXPECTED_OVERLOAD`, exact buffer settlement and TUN re-arm. The local
16-entry pending queue is now treated as owner-local UDP packet overload rather
than implicit flow termination.

The required post-pressure B1 recovery did not produce a valid DNS reply. A
fresh no-D3 multi-owner baseline also reproduced an ambient Android TCP/5228
flow consuming an owner, ending with `tun-flow-output-not-a-direct-return`, and
causing later tuples to receive `owner-stopped`. This is `VPN-F038`, separate
from HEV credit and from ADB/UID/permission validity. D3 is therefore
`PAUSED_BY_AMBIENT_FLOW_HOTSPOT`; E1/E2 remain paused. The next execution must
isolate/classify ambient full-route traffic or use a controlled no-ambient route
before another pressure/recovery attempt.

## S161 D3 timed recovery closure (2026-08-24)

[`S161_D3_TIMED_RECOVERY_EXECUTION_JOURNAL.md`](S161_D3_TIMED_RECOVERY_EXECUTION_JOURNAL.md)
adds the missing pressure-completion barrier. Four concurrent AppA stages
offered 64 packets; the runner waited until all four `repeat=16` sequences had
finished before issuing B1 recovery. The final artifact produced four
`PASS_EXPECTED_OVERLOAD` generations with exact credit/buffer settlement and
TUN re-arm, followed by a valid WSL2 DNS response on generation 6
(`direct=1`, `rewritten=1`, `buffers=113/113`, `residue=0`).

The S160 recovery timeout was therefore a harness ordering error, not a new
runtime hotspot. The Android 16 LAN return preflight and the ambient TCP/5228
classification are recorded as run-validity boundaries. D3 is now
`SUPPORTED_FOR_TESTED_UDP_ENVELOPE`; E1/E2 are unblocked and proceed with their
own registered resource/performance gates.

## S163 E1/E2 execution (2026-08-24)

[`S163_E1_E2_EXECUTION_JOURNAL.md`](S163_E1_E2_EXECUTION_JOURNAL.md) records
the first final-artifact engineering-envelope run. E1's clean 40-sample
unique-port window, fault/recovery, epoch apply, stop/restart and resource
snapshots remain valid. The corrected paired OI3 artifact also passed IPv4 DNS
and Direct HTTP, and the restored canonical APK (without the temporary
`tun_poc` plugin) passed a controlled HTTP smoke with exact cleanup.

S163 found no new runtime hotspot. Two loader stops were incompatible
source/stage members (dirty conditional-wake OI3 plugin versus clean VPP core,
then old HEV versus owner-context HEV); VPN-F039 records the preflight defect
and the corrected hashes. A stable WSL2 endpoint produced Direct restart
latencies of 364/386/585 ms and successful screen-off/forced-Doze cells. The
existing public HEV loop remains a useful 8/6/9 ms baseline, but HEV could not
use the controlled LAN endpoint while the same-UID no-VPN control succeeded.
The public repeated-flow Direct sample also contained a remote read timeout.
These endpoint/fixture boundaries make the ADR-0007 Direct-vs-HEV comparison
`INCONCLUSIVE`; they are not grounds for another blind retry or an architecture
pause.

E2's remaining work is a matched HEV-compatible endpoint/traffic arm, complete
throughput/CPU/RSS/FD/thread/thermal and IPv4/IPv6 TCP/UDP/DNS measurements,
multi-owner load, and the final evidence audit. Until those cells pass, the
campaign supports the tested E1 envelope but not the full Android VPN
Engineering Feasibility claim.

## S168 multi-owner teardown hotspot (2026-08-24)

[`S163_E1_E2_EXECUTION_JOURNAL.md`](S163_E1_E2_EXECUTION_JOURNAL.md) records
the final-topology multi-owner teardown result. The first bounded lifecycle
correction drained thread-local HEV work before lwIP invalidation; the
follow-up expanded the drain, retried OI3 `NOT_READY`, and guarded destroy
until stop was ready. A narrow 2-flow regression passed, but the registered
4-flow Pixel/WSL2 cell still emitted the same Scudo owner-context
`invalid chunk state`/SIGABRT. This is the fourth valid recurrence of VPN-F042,
not a new ADB, UID, endpoint, or permission hotspot.

The campaign stop rule is active: multi-owner pressure and dependent E2
resource/performance cells are paused, and no further blind retry is allowed.
VPN-F042 remains `OPEN_RISK`; remaining work is a fundamental owner-lifecycle
redesign or explicit disposition, followed by one approved regression before
resuming the matched E2 matrix and final audit.

Follow-up diagnosis identified the missing owner-thread affinity guard as the
concrete lifecycle design flaw.  OI3 now treats owner finish/destroy as an
owner-thread-only operation: a foreign worker must re-enqueue the finish token
to the owner's `target_thread`, because the finish path drains HEV thread-local
tasks and destroys the owner lwIP/HEV context.  The Android preflight also now
requires a single VPP runtime/plugin build closure and native-library
`name-filter` plugin loading; this fixed the earlier live-VPP-but-no-OI3-CLI
state.  Current Pixel preflight evidence loads
`libhev_external_driver_poc_plugin.so`, accepts `sakamoto-oi3 underlay`, and
executes the `sakamoto-oi3 multi tun fd 3` startup command.  A follow-up APK
rebuild briefly regressed to the legacy HEV stage and made OI3 multi fail at
`dlsym(hev_socks5_owner_config_default)` with `active=0 owners=0`; this is now
covered by `build-debug-apk.sh`, which rejects OI3 APKs unless the packaged HEV
member exports the required owner-context API.  Rebuilding with
`work/android-hev-poc7-stage` restored Pixel startup to `success=true rc=0`,
`hev-loaded`, and `oi4 multi active=1 owners=2`.  The approved
2026-08-25 4-flow rerun did not reproduce the Scudo/SIGABRT heap boundary, but
the initial echo result was invalid because the WSL2 endpoint lacked a
same-package direct preflight.  That fixture hotspot is now corrected for the
current LAN endpoint: with stale `RESTRICT_LOCAL_NETWORK` disabled, direct
same-package UDP `42185` and TCP `42186` controls to `192.168.4.5` both pass.

The follow-up 4-flow attempt exposed a separate closed POC-harness defect:
fixed UDP source ports `40000`--`40003` collided with ambient Android traffic
(`EADDRINUSE`).  The app, runner, manifest, and parser now carry a configurable
`sourcePortBase`; the validated reruns used explicit source port bases.  Later
2026-08-25 minimization fixed the return tuple rewrite, pending-generation
loss, and same-generation UDP inflight guard.

S169 then closed VPN-F045 for the tested two-owner UDP closed-echo envelope by
patching HEV's UDP connector to stay persistent across protected responses.  A
fresh 1-flow run passed (`runId=86632836943396`, `sent=834 received=834
errors=0`) and a fresh two-owner run passed (`runId=139608275148756`,
`sent=1702 received=1702 errors=0`).  The next active blocker was VPN-F046:
the registered 4-flow closed echo cell exceeded the implemented topology of two
owners with one active UDP hash per owner.  The two-owner 4-flow run
`83202807976373` produced exactly 20 app timeouts and exactly 20 matching VPP
`owner-busy` admission rejects, while the two admitted flows passed.

F046 is now closed for the selected bounded four-owner design.  The follow-up
APK `96726fa8e56d74e731105c71568735af338f74fcb06cc067eff00b7525b07179`
packaged OI3 plugin
`b97c57a853a31e0bd7451dd4216519553091954ba45412b3b3def0825dda5951`, started
`vpp-oi3-multi` with four owners, and passed run `127931250090287` with
`sent=3698 received=3698 errors=0`, zero `owner-busy`/multi-admission rejects,
and four clean owner teardowns.  VPN-F042 is closed for the corrected
four-owner UDP regression; E2 performance, soak, and production capacity
constants remain unclaimed.

S170 then reran the minimum post-F046 E1 repeat window.  Five four-owner UDP
closed-echo cycles passed on the same artifact (`20260825-112255-922529`):
all cycles had exact app echo, four clean owner teardowns, no residual VPP or
`tun0`, fixture ownership `12762/12762`, stable app/VPP FD counts `120/41`, and
bounded RSS deltas `648/480 KiB`.  This supports the bounded corrected
four-owner repeat/stop resource window; it does not close matched Direct/HEV
E2 performance, Doze/screen-off, thermal behavior, or production capacity.

S171 then ran a bounded direct-vs-OI3 E2 sample.  The initial corrected-artifact
TCP cell exposed VPN-F047: OI3 multi-owner TCP treated the five-second TUN flow
deadline as an absolute generation lifetime, so active `tcp:1:1400 steady=6`
streams were cleaned up and same-tuple tail packets were rejected.  Refreshing
the deadline on TCP activity and treating FIN/RST as terminal closed the
hotspot.  Rebuilt APK
`3ba6f24260e2e2dc417e3f150f04ad7a67e6458c26e630e369e623e0dc8f14e4` then passed
the targeted three-repeat TCP regression and the full S171 sample
`20260825-122707-906865`: Direct and OI3 cells for UDP 64B, UDP 4x1400B and TCP
1400B all passed, with zero `owner-busy`, `tcp-tail` or non-tail multi rejects
in the OI3 TCP cell.  This closes the bounded S171 sample only; matched HEV
baseline performance and device-state E2 gates remain open.

S172 then fixed the matched-baseline construction hotspots. The canonical OI3
APK remains valid without `tun_poc`, but the legacy `vpp-hev` baseline is a
tun-poc mode and therefore cannot be run from that APK; the new S172 runner
preflights this before ADB and records VPN-F048. The comparison APK runs then
exposed VPN-F049: OI3 multi-owner TCP could admit a FIN/ACK tail before the
completed tuple tombstone was published, and the duration-only HTTP stream was
a throughput/capacity shape rather than a matched request-count baseline. OI3
now closes owner-local admission during teardown and reopens it after tombstone
publication; the app HTTP probe is Content-Length aware; and S172 defaults
`MAX_REQUESTS=1`. Accepted run `20260825-131542-644207` passed Direct/HEV/OI3
with one GET each, `contentLengthCompletions=1`, OI3 `cleanup=5/0`, and
`failureCount=0` using comparison APK
`67f16c3a045c0a786e49ecb1f99a7a6496080ea0761404447c04434617880a94`. This
repairs the repeated baseline-construction failure and closes only the bounded
HTTP baseline slice; it does not close the full E2 matrix.

S173 then exposed and closed VPN-F050 in the foreground HTTP staircase. Raw
FNV owner selection first collapsed request hashes onto one owner; adding
`fnv1a+mix` improved distribution but still left successor SYNs failing as
`owner-busy` when a deterministic canonical owner held a completed-but-not-yet
rearmed TCP generation. OI3 now keeps busy successor SYNs on their canonical
owner through bounded owner-local deferred admission and clears stale TCP
pending tail at re-arm. Final APK
`441b0279e2685d0d89b6092ce00f64e49742a1fcfaaf691611c826a20fca97c4` with OI3
plugin `9282f8c82c5223e2c7b144f85a2533100df646ec821ff0ef91737b9ef8a85186`
passed OI3 repeat=5 `4/4` cells and a matched Direct/HEV/OI3 `4/4` staircase
with `failureCount=0`.

S174 reused that artifact and extended the same foreground HTTP construction to
eight unpaced requests. OI3-only run `20260825-144710-417439` passed three
`8/8` cells with cleanup `12/0` and `failureCount=0`; matched run
`20260825-145127-375231` passed Direct `8/8`, HEV `8/8`, and OI3 `8/8`, also
with `failureCount=0`. OI3 latency remains materially higher than the Direct
and HEV controls in this deferred-owner path, so EG-17 stays inconclusive until
the broader performance/resource/device-state matrix runs.

S175 extended the same construction to sixteen unpaced requests. OI3-only run
`20260825-150115-968569` passed three `16/16` cells with cleanup `20/0` and
`failureCount=0`; matched run `20260825-150431-029771` passed three repeats of
Direct/HEV/OI3, all nine cells at `16/16` with `failureCount=0`. This confirms
the S173 deferred-successor correction across a higher bounded request-count
ladder, but it leaves EG-17 open for broad performance, resource, thermal,
power, Doze, and soak evidence.

S176 then exposed a separate concurrent-UDP hotspot and closed it for the
selected four-owner topology. The initial S175 artifact failed OI3 UDP4 twice
with `ownerBusy=11` and ten missing replies because `hash % owner_count` mapped
one UDP flow to an already active primary owner while another owner was idle.
The corrected OI3 plugin adds UDP-only bounded flow-route pinning to idle
owners and leaves TCP on the S173 canonical-owner deferral path. Clean-ABI APK
`f4e350c6478ce9f495afa9b1b97f174c79915592a461aeb25d7e8cdd803e1541` with OI3
plugin `5012eeecb16828edca58f3dc98ddd52330a3b09b26394a3baa94b7c39604cc72`
passed the minimal UDP4 regression, full Direct/OI3 IPv4 UDP/TCP S176 sample
`20260825-155427-072214` with all 12 cells valid and `failureCount=0`, and an
OI3-only HTTP16 regression `20260825-160228-023067` with both cells `16/16`.
This supports continuing E2, but EG-17 still requires the broader
performance/resource/device-state campaign.

S177 closes the immediate E1 resource-runner harness hotspot and adds a short
final-artifact foreground resource slice.  The initial S177 attempts were
invalid because S170 still hard-coded old S169 expected hashes, directly read
VPP log paths that can block, and exited on transient WSL/ADB
`UtilAcceptVsock: accept4 failed 110` failures before producing a manifest.
After the runner correction, accepted run `20260825-163352-816347` in
`evidence/s177-e1-final-resource-short3-20260825/` completed two four-flow UDP
cycles on the S176 artifact with `763/763` and `784/784`, cleanup `4/0` in
both cycles, fixture `2008/2008`, stable fd/thread counts, thermal status `0`,
and `failureCount=0`.  This is useful resource evidence, but not a replacement
for matched throughput/CPU, screen-off/Doze, or soak coverage.

S178 then reran the B1 dual-stack DNS matrix on the same current final artifact
and exposed a POC verdict-design hotspot rather than a new dataplane failure.
The runner had to stop treating `tun0` exit-code behavior, late cleanup-marker
visibility, and repeated TCP source-port reuse as the same failure class as
IPv4/IPv6 DNS routing.  Accepted run `20260825-170934-541913` in
`evidence/s178-b1-final-dualstack-dns-20260825/` completed six IPv4/IPv6
UDP/TCP DNS cells with valid 61-byte DNS responses, native direct/broker/
TUN-output markers, `appValidCount=6`, `nativeValidCount=6`, zero post-run
`vpp`/`tun0` residue, and `failureCount=0`.  The run status is
`PASS_DATAPLANE_WITH_CLEANUP_MARKER_GAPS` because three TCP rows missed late
cleanup markers.  This supports the current-artifact B1 DNS dataplane, but it
does not close lifecycle cleanup timing, large-response DNS fallback, or the
remaining performance/resource/device-state campaign.

S179 adds a current-artifact B2 controlled negative-semantics regression.  The
current AppA B1 helper does not implement resolver UDP-to-TCP fallback, so a
large-response forced-fallback B1 claim would require additional helper/runner
design instead of simply sending independent UDP and TCP DNS payloads.  The
next executable bounded slice was therefore the existing S146/S147 controlled
failure contract.  Accepted run `20260825-172718-237536` in
`evidence/s179-b2-final-controlled-failure-20260825/` passed refused,
no-reply, and policy-drop cells on the current final VPN APK with
`verifierRc=0`, native `PASS_EXPECTED_FAILURE`, `failureCount=0`, and zero
post-run `vpp`/`tun0` residue.  This preserves the negative-outcome contract
on the final artifact, but it is not the complete external/default-route B2
claim.

S180 closes that fallback POC-design gap for one bounded IPv4 fixture cell.
AppA now has an explicit `b1FallbackTcpOnTruncated` seam, and runner
`android-run-s180-b1-dns-fallback.sh` starts a WSL2/LAN DNS fixture that
returns UDP `TC=1` and a TCP full response for the same query ID.  Accepted run
`20260825-173925-730529` in
`evidence/s180-b1-dns-fallback-20260825/` recorded UDP query `1234`, UDP
truncated response `1234`, TCP query `1234`, TCP full response `1234`, AppA
`fallback_attempted=true`, `fallback_reason=udp_tc`,
`return_outcome=dns_tcp_fallback_response_received`, native
`brokerSuccess=2`, cleanup `1/0`, and `failureCount=0`.  This supports B1
forced fallback for the WSL2/LAN fixture; public resolver fallback, IPv6
fallback, arbitrary large DNS responses, and repeated resolver behavior remain
future extensions.

S181 closes the next B2 real-transport fixture-design gap for the selected
full-device AppA -> VpnService -> OI3 multi-owner path.  The runner first
proved that `oi3ExpectedFailure=real-refused` reached the service and OI3, but
the unbound WSL2 TCP port did not produce a deterministic native refusal signal:
AppA observed `tcp_connect_succeeded/dns_response_timeout`, while native saw
broker/protect, TUN output and return rewrite with zero transport-failure
events.  The accepted design therefore treats that fixture as
`closed-tcp-timeout`, not real refusal.  Accepted run
`20260825-183033-563849` in
`evidence/s181-b2-full-device-transport-explore-20260825/` passed positive UDP
DNS, real UDP no-reply, and closed TCP timeout with `pass_count=3`,
`failure_count=0`, zero design gaps, and zero post-run `vpp`/`tun0` residue.
This supports bounded real no-reply/timeout separation on the full-device
fixture; it does not close real RST/`ECONNREFUSED`, policy drop, bind/protect
failure, infrastructure failure, public Internet behavior, or production
timeout constants.

S182 adds the representative real policy-drop slice for the same full-device
OI3 multi path.  Android app exclusion was rejected as a substitute because it
would bypass the VPN.  The accepted POC seam passes `blockIp4Dst` into OI3 as
`SAKAMOTO_OI3_POLICY_DROP_IP4` and drops matching IPv4 packets in the multi
dispatcher before owner lookup/admission, TUN queueing, FlowStackOwner
creation, bind/protect broker use, or protected socket transport.  Accepted
run `20260825-190147-303631` in
`evidence/s182-b2-real-policy-drop-20260825/` passed positive UDP DNS and
`policy-drop-udp-dns` with `pass_count=2`, `failure_count=0`, zero design gaps,
and zero post-run `vpp`/`tun0` residue.  The policy observer on port `53544`
received no packet; native logged `stage=pre-owner ... no-transport=1 broker=0
socket=0`.  This supports target-IP policy/drop separation, not per-App UID
drop, bind/protect failure, infrastructure failure, RST/refusal, or production
policy behavior.

S183 adds the representative per-App UID-drop slice for the same full-device
OI3 multi path.  The hotspot was not ADB or fixture reachability: the first
valid run proved that the native gate was present but forwarded on
`ownerUid=-1`, because the existing UID contract returns an async sentinel on
the first lookup.  The accepted correction reuses the native TUN gate for
`vpp-oi3-multi + blockOwnerUid>=0` and adds a bounded completion/cache barrier
before UID policy is applied.  Accepted run `20260825-192207-202830` in
`evidence/s183-b2-real-uid-drop-20260825/` passed positive UDP DNS and
`uid-drop-udp-dns` with `pass_count=2`, `failure_count=0`, zero design gaps,
and zero post-run `vpp`/`tun0` residue.  The UID contract recorded
`MISS_SUBMITTED -> COMPLETION_ACCEPTED uid=12630 -> CACHE_HIT uid=12630`;
native logged `gate drop ... ownerUid=12630 ... lookup-attempts=2`; the
fixture observer on port `53545` received no packet.  This supports a bounded
AppA UID-drop POC seam before OI3 broker/socket creation, not VPP-internal UID
policy, production nonblocking/capacity design, or complete UID lifecycle
convergence.

S184 closes the next B2 real-transport reset slice by replacing S181's
unbound-port timeout with a WSL2/LAN TCP listener that accepts AppA's
connection and closes with `SO_LINGER(1, 0)`.  The fixture side is valid:
accepted run `20260825-193618-437793` in
`evidence/s184-b2-real-rst-20260825/` recorded `tcp_rst_connection` and
`tcp_rst_sent`, while the positive UDP DNS control passed.  A bounded
owner-event correction rerun
`20260825-203915-342533` in
`evidence/s184-b2-real-rst-owner-event-20260825/` observed exactly one
owner-local `READ_ERROR errno=104` with no infrastructure failure and exact
buffer settlement.  It closed the original observation seam and isolated a
second design seam: owner-context teardown silently purged the client PCB and
emitted no downstream RST/FIN.  The narrow `tcp_send_reset_ctx()` correction
now maps only an exact owner-observed `ECONNRESET` to one owner-local downstream
`RST|ACK`, leaving ordinary teardown semantics unchanged.  The bounded rerun
`20260825-210129-290257` in
`evidence/s184-b2-real-rst-downstream-reset-20260825/` recorded one upstream
reset, one rewritten downstream reset, AppA
`tcp_payload_sent/dns_response_reset`, `PASS_EXPECTED_REAL_RESET`, one
transport failure, zero infrastructure failure, exact `buffers=7/7`
settlement, and zero post-run VPP/tun0 residue.  Its old wrapper returned `1`
only because the summarizer counted the same event in both
`native-combined.log` and its embedded `vpp-stdout.log`; the verifier is
corrected to deduplicate mirrored presence markers while retaining once-only
cleanup gates.  S184 is `CLOSED_FOR_BOUNDED_REAL_RST_SLICE` and no longer
freezes the campaign.  Pre-connect refusal, public-Internet behavior,
arbitrary teardown mapping, and production timeout constants remain non-claims
unless separately registered.

S185 closes the bounded B2 infrastructure-failure branch for the same
full-device AppA -> VpnService -> OI3 multi path.  The correction keeps
bind/protect/broker failure at the broker boundary instead of relabelling App
timeouts as transport or policy evidence.  Accepted run
`20260825-213903-524622` in
`evidence/s185-b2-infrastructure-failures-20260825-run1/` passed positive UDP
DNS plus forced bind failure, forced protect failure, and broker unavailable
cells.  Each failure recorded the exact expected broker result and phase
accounting (`BIND_FAILURE` `1/0`, `PROTECT_FAILURE` `1/1`,
`BROKER_UNAVAILABLE` `0/0`), one infrastructure failure, zero transport
failure, no fixture query, no TUN output, no Direct send, and zero post-run
VPP/tun0 residue.  This supports bounded infrastructure-failure separation;
it does not close post-connect transport failure, pre-connect
`ECONNREFUSED`, public-Internet behavior, production capacity, or production
timeout constants.

S141 performs the final B2 closure audit for Plane `SAKAMOTO-141`. The audit
bundle `evidence/s141-b2-final-closure-audit-20260826/b2-closure-audit.json`
and [`S141_B2_FINAL_CLOSURE_AUDIT.md`](S141_B2_FINAL_CLOSURE_AUDIT.md) map
each B2 acceptance item to S178/S179/S181/S182/S183/S184/S185 plus OI2/OI3/OI5
host/model support. The result is `CLOSABLE_FOR_BOUNDED_B2_POC` for the
selected Pixel 6a AppA/VpnLite/OI3 multi path and WSL2/LAN fixtures. The audit
does not upgrade EG-07 to global support: pre-connect `ECONNREFUSED`,
public-Internet behavior, arbitrary teardown mapping, production timeout and
capacity constants, complete distinct-App matrices, Doze, soak and OEM
variation remain explicit non-claims. S184's preserved CSV/manifest still show
the known verifier-only double-count `FAIL`; the accepted oracle is the raw
downstream-reset evidence plus corrected verifier/source tests.

S152 attempted the residual A2 two-App UID lifecycle matrix after S185 and
paused as an explicit POC design gap.  The authorized rerun
`evidence/s152-a2-1-two-app-20260825-dualplugin-rerun1/` was
`INCONCLUSIVE`: setup, dual UID scope, APK/native provenance, eight App
runtime records, and cleanup were valid, but only 5/8 tuples had resolver
joins.  AppA IPv4/TCP `45641`, AppA IPv6/TCP `45643`, and AppB IPv4/TCP
`45651` failed in the App socket layer before native resolver evidence; the
manifest used public `1.1.1.1` / Cloudflare IPv6 endpoints, which are invalid
as a controlled UID resolver oracle.  The runner also omitted an A2-1
`uidContractStage`, so native/Java resolver logs were labelled
`A2-4/startup`.  Do not rerun S152 until the POC uses controlled WSL2/LAN
fixtures and stage-specific UID contract logging.

S155 implemented that POC correction and closed the original
public-endpoint/startup-stage oracle defect (`VPN-F060`).  S156 then closed the
successor resolver/correlation hotspot (`VPN-F061`) for the A2-1 base matrix.
Run5 `evidence/s156-a2-1-correlation-20260825-run5/` passed all eight
registered two-App IPv4/IPv6 TCP/UDP tuples with runtime, resolver, and
UID-contract verdicts all `PASS`.  The closure depends on immutable resolver
`cell/stage/request` metadata, APK artifact gates, TCP `sourcePort=0` with
durable actual-source-port capture, TCP repeat `4`, and manifest selection of a
repeat with a decisive positive resolver UID.  Dependent A2 cells may continue
from this checkpoint only if they inherit those guardrails.

S199--S223 refine the S193 E2 performance audit.  The diagnosis rejected the
TCP payload timer-kick candidate (`0/4` OI3 requests, four app
`SocketTimeoutException`s), then validated `connector_write_pending` as the
correct fix for the missing protected write-interest stall.  S205--S211 moved
TUN/completion delivery onto explicit owner handoff paths and added the guarded
post-Direct-send read observer.  S215--S218 isolated the final foreground
outlier to the TCP owner lifecycle/admission seam around completed response,
tail tombstoning, finish/rearm, and successor SYN admission.  S219/S220
introduced the owner-local finish/rearm and deferred successor-SYN owner-fd
candidate.  S221 then passed the matched foreground Direct/HEV/OI3 8-request
comparison with `failureCount=0`: Direct p95 `59ms`, HEV p95 `11ms`, OI3 p95
`24ms`, and OI3 cleanup `12/0`.

S222/S223 reran the S192 device-state shape with the same candidate and
comparison APK.  Screen-off passed Direct `8/8` p95 `15ms`, HEV `8/8` p95
`10ms`, OI3 `8/8` p95 `27ms`, OI3 cleanup `12/0`.  Forced-Doze passed Direct
`8/8` p95 `18ms`, HEV `8/8` p95 `16ms`, OI3 `8/8` p95 `78ms`, OI3 cleanup
`12/0`.  Both manifests recorded `failureCount=0`.

S224 then reran the E1 resource trend on the same F072-candidate comparison
artifact (`20260826-071025-774914`).  Five four-flow UDP cycles all passed:
app/fixture counts matched from `4485/4485` through `4592/4592`, cleanup was
`16/0` per cycle, App/VPP fd stayed `120/49`, threads stayed `33--34/7`, and
manifest `failureCount=0`.  This supports current-artifact repeated resource
stability after the lifecycle correction; it is not a substitute for matched
throughput, CPU, thermal, power, Doze soak, or the S223 latency-tolerance
decision.

S225--S229 then tried to close the remaining E2 CPU-budget slice and found two
hotspots.  First, the HEV/tun-poc matched baseline is not clean above the small
request-count envelope: after the S172 HEV arm was corrected to pass
`allowedPackage`, S227 still failed at `66/64`, and S228 failed at `64/63`,
with app `SocketTimeoutException`s.  Second, OI3 correctness is no longer the
main issue, but idle CPU was: S227/S228 OI3 passed `128/128` and `64/64` with
cleanups `132/0` and `68/0`, yet recorded aggregate VPP sched deltas around
`32s`.  S229 isolated the hotspot without any app traffic; tuning
`poll-sleep-usec` was negative.  The first worker-idle correction
(`ee57b9d`) was incomplete, but Android-only idle counters (`b797629`) showed
the real cause was repeated VPP recent-barrier holdoff.  The accepted Android
idle-profile correction (`0324f92`) lets workers sleep across that holdoff.
S229 barrier-fixed reduced the 10-second idle window to `cpuTicksDelta=89` and
`schedRuntimeNsDelta=887122393`, with worker `skip_barrier_recent=0`; a
bounded OI3 UDP wake smoke then passed Direct `554/554` and OI3 `414/414`.
S231/S232 then reran the foreground count-bounded HTTP budget without HEV:
Direct/OI3 count64 passed `64/64` and OI3 dropped to `cpuTicksDelta=198` /
`schedRuntimeNsDelta=1773100641`; Direct/OI3 count128 passed `128/128` and
OI3 dropped to `cpuTicksDelta=302` / `schedRuntimeNsDelta=2644077026`.

The campaign remains `ADJUSTMENT_REQUIRED_E2_PERFORMANCE`, but the F074
VPP/OI3 worker CPU hotspot is closed for the selected Android idle scope and
the tested foreground count64/count128 Direct/OI3 scope. Full ADR-0007 closure
still needs thermal/power/soak evidence, broader OI3 throughput/capacity CPU
budget evidence, a HEV-baseline decision, and pre-registered decisions on the
S223 forced-Doze and S231/S232 p99 absolute/relative latency deltas.

## 8. Conclusion vocabulary

Cell-level result:

- `PASS`: the registered cell produced the expected evidence.
- `FAIL`: the registered cell contradicted its expected behavior.
- `INCONCLUSIVE`: the cell ran but evidence cannot decide the question.
- `INVALID`: the cell did not exercise the registered question.

Roadmap meaning:

- `SUPPORTS_BASELINE`: bounded evidence supports continuing the current route.
- `ADJUSTMENT_REQUIRED`: a real issue requires local correction or redesign,
  but does not reopen the architecture.
- `REOPENS_ARCHITECTURE`: a core assumption is contradicted and the campaign
  must pause for a route decision.
- `INSUFFICIENT_EVIDENCE`: the experiment was valid but does not cover enough
  of the claim.

Every conclusion must say in plain language what the evidence supports and what
it does not support. A cell `PASS` is never by itself a campaign `SUPPORTS_BASELINE`.

## 9. Campaign outputs and next planning step

The campaign uses two linked but semantically separate records:

- `POC Finding Ledger`: observed problems, including already repaired problems,
  their evidence, POC Corrections, formal invariants, and status.
- `Evidence Gap Map`: important claims and the Host/model/Pixel evidence and
  non-claims for each, including unproven gaps that are not observed defects.

The concrete POC design is produced only after these records are complete. The
design must group related gaps into Evidence Batches, define each POC and its
true blockers, and specify Pixel evidence, exploratory latitude, conclusion
rules, and interruption conditions. It is then converted into execution tickets
for the continuous POC chain.

## 10. Non-goals and explicit non-claims

This contract does not claim:

- production readiness, release approval, or final capacity constants;
- throughput, latency, power, thermal, or soak budgets already passing;
- third-party OEM compatibility;
- complete Android Product UI, policy authoring, catalog, or persistence;
- Root/NFQUEUE revalidation;
- arbitrary external/default-route behavior before the future real-network POCs
  produce it;
- four-worker Android evidence merely because Host or a two-owner Host runner
  passed;
- that a POC correction is a production implementation.

## References

- [Project glossary](../../CONTEXT.md)
- [ADR-0007: Owner-local lwIP direct egress](../../docs/adr/0007-owner-local-lwip-direct-egress.md)
- [OI requirement audit](./OI_REQUIREMENT_AUDIT.md)
- [S126 OI1 journal](./S126_OI1_EXECUTION_JOURNAL.md)
- [S127 OI2 journal](./S127_OI2_EXECUTION_JOURNAL.md)
- [S128 OI3 journal](./S128_OI3_EXECUTION_JOURNAL.md)
- [S129 OI4 journal](./S129_OI4_EXECUTION_JOURNAL.md)
- [S130 OI5 journal](./S130_OI5_EXECUTION_JOURNAL.md)
- [S149 C2 lifecycle journal](./S149_C2_REAL_TRAFFIC_LIFECYCLE_EXECUTION_JOURNAL.md)
- [S150 C1 underlay epoch hotspot](./S150_C1_UNDERLAY_EPOCH_HOTSPOT.md)
- [S151 C1 underlay epoch execution journal](./S151_C1_UNDERLAY_EPOCH_EXECUTION_JOURNAL.md)
- [S152 C2 real-stop classification hotspot](./S152_C2_REAL_STOP_CLASSIFICATION_HOTSPOT.md)
- [S153 C2 real-stop correction execution journal](./S153_C2_REAL_STOP_CORRECTION_EXECUTION_JOURNAL.md)
- [S156 C2 one-flow-per-VPN-session hotspot](./S156_C2_ONE_FLOW_PER_VPN_SESSION_HOTSPOT.md)
- [S157 C2 TUN re-arm correction execution journal](./S157_C2_TUN_REARM_EXECUTION_JOURNAL.md)
- [S157 C2 TUN re-arm correction execution journal](./S157_C2_TUN_REARM_EXECUTION_JOURNAL.md)
- [S158 D1-D3 final-topology owner/overload hotspot](./S158_D_FINAL_TOPOLOGY_OWNER_OVERLOAD_HOTSPOT.md)
- [S160 D3 overload/recovery execution journal](./S160_D3_OVERLOAD_RECOVERY_EXECUTION_JOURNAL.md)
- [S161 D3 timed recovery execution journal](./S161_D3_TIMED_RECOVERY_EXECUTION_JOURNAL.md)
- [S163 E1/E2 execution journal](./S163_E1_E2_EXECUTION_JOURNAL.md)
- [S169 UDP persistent connector and capacity closure](./S169_UDP_PERSISTENT_CONNECTOR_AND_CAPACITY_EXECUTION.md)
- [S170 E1 four-owner resource trend execution](./S170_E1_RESOURCE_TREND_EXECUTION.md)
- [S171 E2 OI3 direct sample and TCP idle-timeout hotspot](./S171_E2_OI3_DIRECT_SAMPLE_AND_TCP_IDLE_TIMEOUT_HOTSPOT.md)
- [S172 E2 matched HTTP baseline comparison APK hotspot](./S172_E2_MATCHED_HTTP_BASELINE_COMPARISON_APK_HOTSPOT.md)
- [S173 E2 HTTP staircase owner-capacity hotspot](./S173_E2_HTTP_STAIRCASE_OWNER_CAPACITY_HOTSPOT.md)
- [S174 E2 HTTP 8-request staircase execution](./S174_E2_HTTP_8REQUEST_STAIRCASE_EXECUTION.md)
- [S175 E2 HTTP 16-request staircase execution](./S175_E2_HTTP_16REQUEST_STAIRCASE_EXECUTION.md)
- [S176 E2 UDP multi-flow route-pinning hotspot](./S176_E2_UDP_MULTI_FLOW_ROUTE_PINNING_HOTSPOT.md)
- [S177 E1 final resource short and ADB harness hotspot](./S177_E1_FINAL_RESOURCE_SHORT_AND_ADB_HARNESS_HOTSPOT.md)
- [S178 B1 final dual-stack DNS execution and cleanup-marker hotspot](./S178_B1_FINAL_DUALSTACK_DNS_EXECUTION.md)
- [S179 B2 final controlled failure-semantics regression](./S179_B2_FINAL_CONTROLLED_FAILURE_EXECUTION.md)
- [S180 B1 DNS fallback execution](./S180_B1_DNS_FALLBACK_EXECUTION.md)
- [S181 B2 full-device transport fixture execution](./S181_B2_FULL_DEVICE_TRANSPORT_FAILURE_EXECUTION.md)
- [S182 B2 real policy-drop execution](./S182_B2_REAL_POLICY_DROP_EXECUTION.md)
- [S183 B2 real per-App UID-drop execution](./S183_B2_REAL_UID_DROP_EXECUTION.md)
- [S184 B2 real LAN TCP RST hotspot](./S184_B2_REAL_RST_HOTSPOT.md)
- [S185 B2 infrastructure failure execution](./S185_B2_INFRASTRUCTURE_FAILURE_EXECUTION.md)
- [S141 B2 final closure audit](./S141_B2_FINAL_CLOSURE_AUDIT.md)
- [S152 A2 UID lifecycle design gap](./S152_A2_UID_LIFECYCLE_DESIGN_GAP.md)
- [POC Finding Ledger](./POC_FINDING_LEDGER.md)
- [Android VPN Evidence Gap Map](./ANDROID_VPN_EVIDENCE_GAP_MAP.md)
- [Evidence-Guided Android VPN POC Campaign Specification](./ANDROID_VPN_POC_CAMPAIGN_SPEC.md)
