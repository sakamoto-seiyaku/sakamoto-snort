# S245 Android VPN main-stack import readiness

Date: 2026-08-26
Status: `NINETEENTH_FLOW_STACK_BACKEND_SELECTION_LANDED_KERNELSU_AUTH_PENDING_PRODUCT_DRIVER_IMPORT_BLOCKED`

## Question

After S237--S244 closed the post-F074 count64 OI3 tail for the tested shape,
should the Android VPN POC be imported into the product/main stack now?

## Answer

No direct product-code import yet.

The POC evidence is ready to be imported as a main-stack design constraint:
same-owner Flow Stack re-arm must be driven locally and bounded on the
canonical owner.  It is not ready to import the throwaway OI3 plugin, vpn-lite
APK, Android runner, or generated VPP stage as product code.

## Current main-stack state inspected

Authoritative active docs:

- `docs/ANDROID_VPP_CURRENT_STATE_HANDOFF.md`
- `docs/IMPLEMENTATION_ROADMAP.md`
- `docs/product/ANDROID_L4_PRODUCT_PLAN.md`
- `docs/decisions/PER_WORKER_FLOW_OWNERSHIP.md`
- `docs/adr/0006-vpp-native-packet-io-adapters.md`
- `docs/adr/0007-owner-local-lwip-direct-egress.md`

Active source seams:

| Area | Current state | Import implication |
| --- | --- | --- |
| `src/core/flow/FlowGraphIngress.*` | Parses complete L3 bytes into shared `PacketFacts`. | Keep parser ownership in the shared graph; do not reintroduce a VPN-only parser. |
| `src/core/flow/FlowGraphInjection.*` | Performs owner enqueue, Owner Guard, policy evaluation, and completion in a bounded packet transaction. | Needs to expose enough accepted-packet/owner provenance for VPN egress handoff. |
| `src/datapath/tun/VpnTunFlowAdapter.*` | Normalizes VPN/TUN packets into the shared FlowGraph and records policy-vs-transport outcome counters. | Correct seam for VPN profile ingress, but it does not yet own a Flow Stack shard interface. |
| `src/datapath/tun/VpnFlowStackBoundary.*` | Defines the VPN Flow Stack seam, the fd-backed compatibility Adapter and the owner-local host Adapter. | Product Direct Egress continues behind this Interface; HEV/lwIP details must not leak into `VpnTunFdRuntime`. |
| `src/datapath/tun/VpnHevLwipFlowStack.*` | Defines the product facade for a HEV/lwIP-backed Flow Stack Adapter using an injected internal driver. | The pinned HEV/lwIP implementation should satisfy the driver slot without changing the public Flow Stack Interface. |
| `src/datapath/tun/VpnTunFdRuntime.hpp` | Admits outbound packets and receives return packets through an injected `VpnFlowStackBoundary`; the default constructor remains the fd compatibility Adapter. | The runtime no longer needs to know whether the selected backend is fd-backed or HEV/lwIP-backed. |
| `src/main/RuntimeFactory*` | Plans VPN runtime construction as either `vpn-tun-fd-compat` or `vpn-tun-hev-lwip` based on backend preference and driver availability. | Startup selection can now prefer the product facade when a real driver exists, while making fallback explicit. |

## What can be imported now

### Owner-local re-arm invariant

When execution is already on the packet's canonical FlowOwner and the owner has
deferred Flow Stack work for the same owner, the implementation must make
bounded local progress immediately.  It must not self-enqueue through the
cross-owner frame/queue path and then depend on a future scheduling turn.

This is the S237 hotspot fixed by S244.

Required product invariant:

1. same-owner admission/re-arm stays owner-local;
2. local progress is bounded by an explicit quantum/budget;
3. owner lifecycle finish is attempted before yielding;
4. cross-owner scheduling remains the only reason to enqueue to another owner;
5. generation/epoch tokens remain mandatory across asynchronous wakes and
   teardown.

### Provenance discipline

The S238/S239 packaging failures are also importable as a product guardrail:
VPP core, external plugin or Adapter, HEV/lwIP member, APK/runtime artifact and
installed device copy must share explicit provenance before any Android result
is interpreted.

## What must not be imported

- `experiments/vpp-nfq-poc/android/vpn-lite/` as a product app.
- `experiments/vpp-nfq-poc/overlay/src/plugins/hev_external_driver_poc/owner_inline_oi3.c`
  as production datapath code.
- POC shell runners as release tests without rewriting them around product
  runtime control and artifact identity.
- Generated `work/vpp` or historical OI3 stage artifacts as product runtime
  stages.
- HEV/SOCKS child-process topology as proof of the selected ADR-0007 Direct
  Egress path.

## Main-stack import shape

The next product slice should introduce a deep VPN Flow Stack Packet Boundary
inside the main stack, not copy OI3 implementation details.

The Interface should hide:

- lwIP/HEV PCB/session lifecycle;
- protected socket creation, bind/protect status, connect/send/receive state;
- fd/timer wake handling;
- pbuf/copy/adoption details;
- same-owner deferred work and local drive;
- teardown generation and cleanup.

Callers should only need to know:

- canonical FlowOwner / Worker Layout identity;
- immutable packet provenance: TUN-origin or FlowStack-origin;
- normalized `PacketFacts` and accepted policy result;
- bounded admission result or transport outcome;
- return-packet delivery back into the shared graph.

This keeps the module deep: FlowGraph/VpnTun callers exercise a small Interface,
while Flow Stack complexity remains local to the VPN transport implementation.

## Required implementation slices

1. Define the main-stack Flow Stack Boundary Interface and a host fake.
   This should compile and test without HEV/lwIP.  The fake must model
   same-owner deferred re-arm and cross-owner wake separately.
2. Extend the accepted VPN packet result path so VPN egress receives canonical
   owner/provenance without reparsing or re-hashing outside the shared graph.
3. Replace the current transport-fd placeholder behind the new Interface.
   Keep existing fd tests as adapter-level tests, but stop treating the fd as
   the product Direct Egress boundary.
4. Add host regression tests for the S244 invariant:
   same-owner re-arm drives local bounded progress and does not enqueue to
   itself; cross-owner wake still queues with generation protection.
5. Only after the Interface and fake pass host tests, wire the pinned HEV/lwIP
   fork behind that Interface and re-run Android Direct/OI3-style evidence.

## Remaining blockers before product closure

S244 closes the tested count64 tail candidate, but it does not close the whole
ADR-0007 product acceptance surface.  Remaining blockers:

- HEV-baseline disposition for EG-17;
- formal p99/tail tolerance over the corrected S231--S244 evidence range;
- broader throughput/capacity CPU beyond count64/count512 bounded samples;
- thermal, power, and soak evidence;
- repeat-start lifecycle regression for the S241 VPP initial worker barrier
  abort, even though S243/S244 did not reproduce it.

## Recommendation

Proceed with main-stack design import, starting from the Flow Stack Boundary
Interface and fake host tests.  Do not import POC runtime code directly.

## 2026-08-26 first import slice

The first main-stack design-import slice landed the Flow Stack seam without
importing POC runtime code:

- `src/datapath/tun/VpnFlowStackBoundary.hpp`
- `src/datapath/tun/VpnFlowStackBoundary.cpp`
- `tests/host/vpn_flow_stack_boundary_tests.cpp`

The new Interface accepts canonical owner, immutable packet provenance,
accepted packet facts, generation and policy revision.  It intentionally hides
HEV/lwIP PCB/session state, protected sockets, pbuf/copy handling and wake
implementation details.

The host fake regression encodes the S244 invariant:

- same-owner deferred re-arm calls bounded local owner drive and finish;
- same-owner drive fault still does not self-enqueue through the cross-owner
  wake path;
- cross-owner deferred work uses only a generation-tagged wake.

Validated locally:

- `vpn_flow_stack_boundary_tests`: 4 passed.
- `vpn_tun_flow_adapter_tests`: 21 passed.
- `vpp_graph_injection_tests`: 10 passed.
- `flow_steering_tests`: 18 passed.

This moves implementation slice 1 from planned to landed.  The next slice is
to extend the accepted VPN packet result path so VPN egress receives canonical
owner/provenance from the shared graph without reparsing or re-hashing.

## 2026-08-26 second import slice

The second main-stack design-import slice landed the accepted-packet handoff
facts needed by a future VPN Flow Stack egress adapter:

- `FlowGraphIngressResult.acceptedOwner` now carries the canonical owner
  selected by the shared graph for accepted packets.
- `VpnTunFlowAdapter::lastAcceptedPacketHandoff()` exposes the last accepted
  VPN packet's normalized facts, canonical owner, policy revision and immutable
  packet provenance.
- `VpnTunPacketDirection::Outbound` maps to
  `VpnFlowStackPacketProvenance::TunOrigin`.
- `VpnTunPacketDirection::TransportReturn` maps to
  `VpnFlowStackPacketProvenance::FlowStackOrigin`.
- Policy drop, parse failure, capacity failure and fragment buffering clear the
  last accepted handoff instead of leaving stale egress facts.

This keeps owner selection inside the shared graph.  A later VPN egress slice
can consume `VpnTunAcceptedPacketHandoff` directly instead of reparsing packet
bytes or re-running `OwnerSelector` in the VPN transport adapter.

Validated locally:

- `vpn_tun_flow_adapter_tests`: 22 passed.
- `flow_graph_fragment_ingress_tests`: 7 passed.
- `vpn_flow_stack_boundary_tests`: 4 passed.

The next slice is to replace the current transport-fd placeholder behind the
Flow Stack Boundary Interface while preserving the existing adapter-level fd
tests as compatibility evidence.

## 2026-08-26 third import slice

The third main-stack design-import slice moved the existing transport-fd
placeholder behind the Flow Stack Boundary Interface:

- `VpnFdFlowStackBoundary` now implements `VpnFlowStackBoundary` for the
  current fd-backed host/runtime placeholder.
- `VpnTunFdRuntime` no longer writes allowed outbound packets directly to the
  transport fd.  It asks `VpnTunFlowAdapter` for the accepted handoff facts,
  builds a `VpnFlowStackAdmissionRequest`, and admits the packet through the
  Flow Stack seam.
- The fd-backed placeholder only accepts `TunOrigin` packets; `FlowStackOrigin`
  admission is rejected as a loop guard.
- Existing transport-fd counters remain stable:
  no transport fd still records `transportUnsupported`, and fd backpressure
  still records `transportFailed` rather than policy drop.

Validated locally:

- `vpn_flow_stack_boundary_tests`: 7 passed.
- `vpn_tun_flow_adapter_tests`: 22 passed.

## 2026-08-26 fourth import slice

The fourth main-stack design-import slice moved the existing transport-return
poll/read path behind the Flow Stack Boundary Interface:

- `VpnFlowStackBoundary::receiveReturnPacket()` now models return-packet
  delivery as an Interface result instead of exposing the transport fd to the
  runtime.
- `VpnFdFlowStackBoundary` implements the current fd-backed host/runtime
  placeholder for return packets.
- `VpnTunFdRuntime` no longer polls or reads `transportFd_` directly on the
  return path.  It asks the Flow Stack seam for a return packet, then runs that
  packet through the shared `VpnTunFlowAdapter` graph path before writing
  accepted packets back to TUN.
- Return status remains explicit: no packet, missing transport, transport
  failure, oversized buffer and EOF are separated at the seam.

This keeps the Adapter completion point narrow: the runtime still owns the
final TUN write for the fd-backed placeholder, but fd readiness and packet
receipt are no longer part of the runtime's direct transport knowledge.

Validated locally:

- `vpn_flow_stack_boundary_tests`: 10 passed.
- `vpn_tun_flow_adapter_tests`: 22 passed.

The next slice is to replace the fd-backed placeholder implementation behind
`VpnFlowStackBoundary` with a product-shaped HEV/lwIP fake/adapter while
preserving the current seam tests and fd compatibility tests.

## 2026-08-26 fifth import slice

The fifth main-stack design-import slice introduced a product-shaped,
owner-local host Adapter behind the same Flow Stack Interface:

- `VpnOwnerLocalFlowStackBoundary` models the VPN Userspace Flow Stack as
  owner-local egress shards, not as a transport fd.
- Admission is keyed by canonical owner and generation.  Stale generations,
  invalid owners, unsupported protocols, FlowStack-origin loop attempts and
  per-owner capacity exhaustion are explicit seam outcomes.
- Same-owner drive remains local and budgeted.  It materializes bounded return
  packets that are later received through `receiveReturnPacket()`.
- Cross-owner work is represented only as generation-tagged wakes.  The host
  Adapter queues valid cross-owner wakes, rejects stale wakes and applies a
  bounded wake depth.
- Generation changes clear pending owner packets, return packets and queued
  wakes so stale work cannot be driven after teardown/epoch replacement.
- The existing `VpnFdFlowStackBoundary` remains as compatibility evidence for
  the current fd handoff tests, but it is no longer the only implementation
  behind the seam.

This is not the HEV/lwIP product implementation.  It is the main-stack test
shape that the real Adapter must satisfy before Android Direct/OI3-style
evidence is rerun against product code.

Validated locally:

- `vpn_flow_stack_boundary_tests`: 16 passed.
- `vpn_tun_flow_adapter_tests`: 22 passed.
- `runtime_profile_tests`: 9 passed.
- `control_server_contract_tests`: 44 passed.
- `snort-host-tests`: 25/25 passed.

The next slice is to wire a real HEV/lwIP-backed implementation, or the
smallest compilable production facade for it, behind `VpnFlowStackBoundary`
while preserving the owner-local host Adapter tests and fd compatibility tests.

## 2026-08-26 sixth import slice

The sixth main-stack design-import slice landed the smallest compilable
HEV/lwIP production facade behind the existing Flow Stack Interface:

- `VpnHevLwipFlowStackBoundary` now implements `VpnFlowStackBoundary` while
  depending only on an injected `VpnHevLwipDriver`.
- The facade owns product-facing validation: TUN-origin only, canonical owner
  range, current generation, TCP/UDP direct-egress eligibility, available
  ports and bounded packet size.
- The driver slot is where the pinned Sakamoto HEV Fork/lwIP implementation
  will later own PCB/session/protected-socket/pbuf details.
- Driver admission outcomes map back to the existing Flow Stack Interface
  vocabulary, preserving runtime counters and policy-vs-transport separation.
- Return packets, owner drive, owner finish, cross-owner wake and generation
  reset are delegated through the facade without exposing HEV/lwIP internals
  to `VpnTunFdRuntime`.

This still does not import POC OI3/vpn-lite code or link a real HEV/lwIP
library into the product.  It creates the production-shaped slot into which
the real implementation can be wired.

Validated locally:

- `vpn_hev_lwip_flow_stack_tests`: 5 passed.
- `vpn_flow_stack_boundary_tests`: 16 passed.
- `vpn_tun_flow_adapter_tests`: 22 passed.
- `runtime_profile_tests`: 9 passed.
- `control_server_contract_tests`: 44 passed.
- `snort-host-tests`: 26/26 passed.

The next slice is to make VPN runtime construction select the HEV/lwIP facade
behind `VpnFlowStackBoundary` when a real driver is available, while keeping
the fd-backed Adapter as explicit compatibility/test fallback rather than the
product Direct Egress boundary.

## 2026-08-26 seventh import slice

The seventh main-stack design-import slice moved VPN backend selection into
runtime construction:

- `RuntimeFactoryPlan` now distinguishes
  `VpnFlowStackRuntimeBackend::FdCompatibility` from
  `VpnFlowStackRuntimeBackend::HevLwipFacade`.
- `RuntimeFactoryAction::CreateVpnTunHevLwip` is selected only when the
  caller prefers the HEV/lwIP facade and a driver is actually available.
- If the caller asks for HEV/lwIP without a driver, the plan falls back to the
  fd compatibility Adapter and records `usingCompatibilityFallback=true`.
- `VpnTunFdRuntime` now accepts a `VpnTunFlowStackRuntimeConfig` containing an
  injected `VpnFlowStackBoundary`, adapter name and readiness semantics.
- The default fd path is renamed to `vpn-tun-fd-compat`; the product facade
  path is named `vpn-tun-hev-lwip`.
- `VpnTunFdRuntime::start()` starts the automatic drain loop when the selected
  Flow Stack is ready without a transport fd, fixing the construction-time
  readiness gap for injected HEV/lwIP backends.
- Control attach responses now report the runtime's actual adapter name
  instead of hard-coding the historical `vpn-tun-hev` label.
- The Android NDK daemon source set now includes
  `src/datapath/tun/VpnHevLwipFlowStack.cpp`, so the facade is compiled into
  the arm64 main-stack daemon artifact.

This slice still does not import a real HEV/lwIP driver implementation.  It
only closes the runtime seam so the real driver can be supplied without
expanding `VpnTunFdRuntime` or the control protocol around fd-specific
transport details.

Validation notes:

- `runtime_profile_tests`: 13 passed.
- `vpn_tun_flow_adapter_tests`: 22 passed.
- `control_server_contract_tests`: 44 passed when run outside the sandbox.
- `snort-host-tests`: 26/26 passed when run outside the sandbox.
- `snort-build-ndk`: passed and linked `build-output/sucre-snort-ndk`.

Operational pitfall recorded: `control_server_contract_tests` uses Unix
socket/SCM_RIGHTS behavior.  In the managed sandbox it can fail every case
with `connection closed`; that failure mode is not useful datapath evidence.
Run it outside the sandbox with explicit approval before treating the control
contract as failed.

Remaining product work after this slice:

1. Supply the real pinned HEV/lwIP driver behind `VpnHevLwipDriver`.
2. Re-run Android Direct Egress evidence against product runtime construction,
   not the historical OI3/vpn-lite harness.

## 2026-08-26 eighth import slice

The eighth main-stack design-import slice synced the Android production
runtime contract with the seventh slice's adapter names:

- `RuntimeSnapshot` now exposes `ADAPTER_VPN_TUN_FD_COMPAT =
  "vpn-tun-fd-compat"` and `ADAPTER_VPN_TUN_HEV_LWIP =
  "vpn-tun-hev-lwip"`.
- `RuntimeSnapshot.adapterForRunningProfile()` now reports
  `vpn-tun-fd-compat` for the current VPN product runtime because the daemon
  default still uses the fd compatibility Flow Stack backend.
- `ProductPacketAdapterContract.VPN_ADAPTER` now points at
  `RuntimeSnapshot.ADAPTER_VPN_TUN_FD_COMPAT`.
- `RuntimeService` running-state logs now use the fd compatibility adapter
  token instead of the historical `vpn-tun-hev` token.
- Android static contract tests were updated to assert the new production
  tokens and the reserved HEV/lwIP facade token.

Historical evidence records still contain `vpn-tun-hev` because they describe
the pre-S245 child/SOCKS/HEV evidence frontier.  The active device matrix
scripts must use `vpn-tun-fd-compat` until a real HEV/lwIP facade driver is
selected by product runtime construction.

Validated locally:

- `tests/android/android-runtime-contract-test.sh`: passed.
- `tests/android/runtime-contract-test.sh`: passed, including Android runtime
  contract, NDK daemon build, debug APK build and static device-matrix
  contracts.

Remaining product work after this slice:

1. Supply the real pinned HEV/lwIP driver behind `VpnHevLwipDriver`.
2. Rewrite and rerun Android Direct Egress/device evidence against product
   runtime construction and the new adapter tokens, not the historical
   OI3/vpn-lite harness.

## 2026-08-26 ninth import slice

The ninth main-stack design-import slice synced active Android device matrix
runner expectations with the current product runtime adapter token:

- S55 VPN transport matrix now expects `adapterReadiness=vpn-tun-fd-compat`,
  `vpn_tun_control_attach=ok adapter=vpn-tun-fd-compat` and
  `packet-adapter-vpn-tun-fd-compat`.
- S56 VPN attribution matrix now expects the fd compatibility packet adapter
  capability.
- S58 VPN L4 workflow matrix now expects fd compatibility adapter readiness
  and capability.
- S61 disabled-LPI provider matrix now runs VPN status checks against
  `vpn-tun-fd-compat`.
- S69 product VPN runtime matrix now expects fd compatibility adapter
  readiness, attach logs and capabilities across repeat-start cycles.
- Corresponding Android static contract tests now assert the same token.

This does not claim new device evidence.  It only prevents the next device
run from failing before datapath validation because the product runtime now
reports the fd compatibility Flow Stack backend explicitly.

Validated locally:

- `tests/android/runtime-contract-test.sh`: passed, including NDK daemon build,
  debug APK build and active static device-matrix contracts.
- Active device/android script search has no remaining
  `adapterReadiness=vpn-tun-hev`, `packet-adapter-vpn-tun-hev` or
  `vpn_tun_control_attach=ok adapter=vpn-tun-hev` expectation.

Remaining product work after this slice:

1. Supply the real pinned HEV/lwIP driver behind `VpnHevLwipDriver`.
2. Rerun Android Direct Egress/device evidence against product runtime
   construction and the new adapter tokens.

## 2026-08-26 tenth import slice

The next S55 real-device run reached a device/start precondition before any
native datapath evidence:

- Result directory:
  `build-output/s55-product-vpn-transport-matrix/20260826-121334`.
- APK build/install and the Android SOCKS5 smoke server setup passed.
- `start_vpn` returned `FAIL`, but no runtime snapshot was created under
  `files/runtime-state/snapshot.properties`.
- `runtime-service.log` showed profile/query activity only; it did not show
  VPN running state, native daemon startup, control attach, transport attach or
  HEV/lwIP/fd Flow Stack activity.
- `dumpsys activity` showed `com.android.vpndialogs/.ConfirmDialog` on top,
  launched from `DebugControlActivity`.

Interpretation: the runner stopped at Android VPN consent after APK install or
profile start.  This is not UID/drop seam evidence, not a Flow Stack backend
selection failure, and not a native runtime crash; the POC had not yet reached
the product datapath.

Runner pitfall fix:

- S55 now captures `activity.after-start-failure.log`,
  `window.after-start-failure.log`, `power.after-start-failure.log`,
  `files.after-start-failure.log` and
  `runtime-service.after-start-failure.log` when startup does not reach the
  expected runtime snapshot.
- If the Android VPN consent dialog is present, S55 reports
  `start.failureReason=vpn_authorization_required` and
  `start.vpnConsentDialog=present` instead of leaving the failure as an opaque
  empty snapshot.
- If lock/sleep state is visible in the captured dumps, S55 also reports
  `start.deviceBlockedByLockOrSleep=possible`.
- S55 now records `start.notBeforeMillis` and only accepts a running snapshot
  whose `updatedAtMillis` is at or after that device timestamp.  This prevents
  a stale pre-existing `snapshot.properties` from making a rerun pass
  `start_vpn` before the current start attempt has actually reached native
  runtime startup.

Operational rule: authorize the VPN dialog on the test device, then rerun S55
without reinstalling the APK when possible; reinstalling can re-trigger the
platform consent precondition and prevent the run from reaching native runtime
evidence.

Remaining product work after this slice is unchanged:

1. Clear the device VPN authorization precondition and rerun S55 against the
   current product runtime token `vpn-tun-fd-compat`.
2. Supply the real pinned HEV/lwIP driver behind `VpnHevLwipDriver`.
3. Rerun Android Direct Egress/device evidence against product runtime
   construction and the new adapter tokens.

## 2026-08-26 eleventh import slice

S55 passed on the real device after the device authorization preconditions were
cleared and the runner was guarded against stale startup snapshots.

Evidence:

- Result directory:
  `build-output/s55-product-vpn-transport-matrix/20260826-1231-s55-current-apk`.
- Installed APK:
  `app/android-runtime/build/outputs/sakamoto-runtime-debug.apk`,
  SHA-256 `3caf5fcf1b92274143034eaaad7b39a873a3969fe33a766680f4ab4b403545ed`.
- `start.notBeforeMillis=1787718449343`.
- `snapshot.updatedAtMillis=1787718451264`, proving the accepted running
  snapshot came from the current start attempt rather than a stale previous
  runtime.
- Runtime reached
  `state=running profile=vpn health=ok coreHealth=ok adapterReadiness=vpn-tun-fd-compat`.
- Runtime log contained:
  - `vpn_tun_control_ready=ok`;
  - `vpn_tun_control_attach=ok adapter=vpn-tun-fd-compat`;
  - `vpn_hev_transport=ok`.
- Control `HELLO` passed with the current fd compatibility VPN packet adapter
  capability.
- Real traffic passed through the VPN profile:
  - IPv4 TCP connect to `1.1.1.1:80`;
  - IPv6 TCP connect to `2606:4700:4700::1111:80`;
  - UDP DNS relay to `1.1.1.1:53` with 45 response bytes.
- Transport counters increased independently of policy drop:
  - `packetsSeenDelta=19`;
  - `forwardedPacketsDelta=18`;
  - `transportSucceededPacketsDelta=19`;
  - `transportReturnPacketsDelta=9`;
  - `allowed.totalRecordsDelta=18`;
  - `policyDrop.notUsedForTransportFailure=PASS`.
- Cleanup passed and returned the product projection to stopped/unavailable
  adapter readiness.

Interpretation:

- This is valid product-runtime S55 evidence for the current
  `vpn-tun-fd-compat` backend path.
- It proves the Android RuntimeService, VPN/TUN control attach, HEV/SOCKS
  transport placeholder, protect callback, control socket, nominal IPv4/IPv6
  TCP and UDP DNS transport, Flow Activity ingest and cleanup are coherent
  enough for the fd compatibility product path.
- It does not prove the final ADR-0007 Direct Egress implementation, because
  the real pinned HEV/lwIP driver is still not supplied behind
  `VpnHevLwipDriver`.
- `allowed.lastUidKnown=False` and `allowed.lastUid=0` remain evidence for this
  nominal transport matrix only; UID attribution/parity is covered by the
  dedicated VPN attribution and closure matrices, not by S55 alone.

Remaining product work after this slice:

1. Supply the real pinned HEV/lwIP driver behind `VpnHevLwipDriver`.
2. Run the remaining VPN/product matrices that cover attribution, L4 workflow,
   repeat lifecycle and dual-profile closure against the current product
   runtime tokens.
3. Rerun Android Direct Egress/device evidence after a real HEV/lwIP driver is
   selected by product runtime construction.

## 2026-08-26 twelfth import slice

S69 passed on the real device against the current fd compatibility product VPN
runtime path.

Evidence:

- Result directory:
  `build-output/s69-product-vpn-runtime-matrix/20260826-1235-s69-current-apk`.
- Installed APK:
  `app/android-runtime/build/outputs/sakamoto-runtime-debug.apk`,
  SHA-256 `3caf5fcf1b92274143034eaaad7b39a873a3969fe33a766680f4ab4b403545ed`.
- Initial VPN start reached:
  - `snapshot.state=running`;
  - `snapshot.profile=vpn`;
  - `snapshot.adapterReadiness=vpn-tun-fd-compat`;
  - `snapshot.pid=20381`.
- Android VPN network evidence passed:
  - `tun0.running=PASS`;
  - `connectivity.vpnNetwork=PASS`.
- Runtime startup log evidence passed:
  - `vpn_tun_control_ready=ok`;
  - `vpn_tun_control_attach=ok adapter=vpn-tun-fd-compat`;
  - `vpn_hev_transport=ok`;
  - `runtime_state=running profile=vpn health=ok`.
- Control socket evidence passed:
  - `control.HELLO=PASS`;
  - `control.VPN_TUN.STATUS=PASS`;
  - `control.POLICY.STATUS=PASS`.
- VpnService protect anti-loop evidence passed:
  - `protect.callback=PASS`;
  - `protect.fdResult=PASS`.
- Cleanup passed, and two restart/cleanup cycles passed:
  - `cleanup.result=PASS`;
  - `restart.1.result=PASS`;
  - `restart.2.result=PASS`;
  - `restart.result=PASS`.

Interpretation:

- S69 adds product RuntimeService lifecycle and Android VPN/tun0 residue
  evidence that S55 does not cover.
- Together, S55 and S69 now prove the current fd compatibility backend can
  start, expose control status, move nominal traffic, protect upstream sockets,
  stop cleanly and repeat VPN lifecycle on the test device.
- This still does not close the final Direct Egress product path because the
  real pinned HEV/lwIP driver is not yet supplied behind `VpnHevLwipDriver`.

Remaining product work after this slice:

1. Run the VPN attribution and L4 workflow matrices against the current product
   runtime tokens.
2. Supply the real pinned HEV/lwIP driver behind `VpnHevLwipDriver`.
3. Rerun Android Direct Egress/device evidence after a real HEV/lwIP driver is
   selected by product runtime construction.

## 2026-08-26 thirteenth import slice

The first S56 run against the current product VPN runtime did not expose a
datapath failure.  It exposed a known POC harness design hotspot:

- Result directory:
  `build-output/s56-vpn-attribution-matrix/20260826-1238-s56-current-apk`.
- VPN start, control `HELLO` and `POLICY.APPLY` passed.
- The first attribution probe failed before the target evidence condition:
  `first.probe.result=tcp_connect_failed`.
- The probe result message was:
  `Debug traffic probe failed: bind failed: EADDRINUSE (Address already in use)`.
- Device socket state showed the fixed source port `45656` in TCP
  `FIN-WAIT-1`.

Interpretation: this is not policy drop, attribution, transport, or Flow Stack
backend evidence.  S56 was still using fixed TCP source-port reuse as its
same-tuple UID oracle, which directly conflicts with the existing execution
guardrail: Android VPN TCP probes must not reuse fixed TCP source ports to
force determinism.

Design correction:

- S56 now uses the existing Debug UDP probe seam for the same-tuple late
  attribution matrix.
- The attribution tuple and L4 policy use `ipProtocol=17`.
- The debug probe uses `debugUdpTraffic`, `debugUdpHost`, `debugUdpPort`,
  `debugUdpSourcePort` and `debugUdpTimeoutMillis`.
- The first unknown packet expects `udp_datagram_sent` rather than
  `tcp_connect_succeeded`.
- S56 static contracts now reject `debugTrafficSourcePort` in this matrix, so
  the TCP fixed-port oracle does not silently return.

The product runtime is unchanged by this correction.  The corrected S56 matrix
must still be rerun on the device before claiming attribution evidence.

Validated locally:

- `tests/android/runtime-contract-test.sh`: passed, including the updated S56
  static/runtime contracts and NDK/APK build.

Remaining product work after this slice:

1. Rerun corrected S56 against the rebuilt current APK.
2. Run the VPN L4 workflow matrix against the current product runtime tokens.
3. Supply the real pinned HEV/lwIP driver behind `VpnHevLwipDriver`.
4. Rerun Android Direct Egress/device evidence after a real HEV/lwIP driver is
   selected by product runtime construction.

## 2026-08-26 fourteenth import slice

The corrected S56 UDP same-tuple attribution matrix passed on the real device.

Evidence:

- Result directory:
  `build-output/s56-vpn-attribution-matrix/20260826-1246-s56-udp-current-apk`.
- APK build and install passed before the run.
- VPN start and control setup passed:
  - `start.result=PASS`;
  - `control.HELLO=PASS`;
  - `policy.apply=PASS`.
- First unknown UDP packet:
  - `first.forwardedPacketsDelta=1`;
  - `first.uidUnknownFallbackPacketsDelta=2`;
  - `first.droppedPacketsDelta=0`;
  - `first.probe.result=udp_datagram_sent`;
  - `first.noRecognitionHold=claimed`.
- Late attribution:
  - `attribution.apply=PASS`;
  - `attribution.resolvedUid=12629`;
  - `attribution.attributionUpdatesDelta=1`;
  - `attribution.retroactiveDroppedPacketsDelta=0`;
  - `attribution.completedVerdictNotRetroactive=claimed`.
- Second same-tuple UDP packet after attribution:
  - `second.droppedPacketsDelta=1`;
  - `second.attributionResolutionsDelta=1`;
  - `matrix.s56LateAttributionEvidence=claimed`.
- Cleanup passed.

Interpretation:

- S56 now proves the intended product attribution semantics without relying on
  invalid fixed TCP source-port reuse:
  first unknown packet is not held for recognition, completed verdicts are not
  retroactively modified, a later attribution update is applied to the existing
  FlowEntry, and the next same-tuple packet is re-evaluated under the resolved
  UID policy.
- This is VPN attribution evidence for the current fd compatibility backend.
  It still does not supply the real HEV/lwIP Direct Egress driver.

Remaining product work after this slice:

1. Run the VPN L4 workflow matrix against the current product runtime tokens.
2. Supply the real pinned HEV/lwIP driver behind `VpnHevLwipDriver`.
3. Rerun Android Direct Egress/device evidence after a real HEV/lwIP driver is
   selected by product runtime construction.

## 2026-08-26 fifteenth import slice

S58 exposed the same fixed TCP source-port reuse design hotspot as S56, but
with an additional product UI constraint:

- S58's existing runner used a repeated fixed TCP source port to create the
  same tuple for first-unknown, late-attributed drop and restored allow probes.
- The product prefill seam was named and shaped as
  `ActivityL4RuleDraft.fromTcpPolicyDropActivity`, so a direct UDP runner
  migration would have bypassed the product L4 prefill behavior S58 is meant
  to prove.

Design correction:

- `ActivityL4RuleDraft` now exposes a generic
  `fromPolicyDropActivity(host, port, ipProtocol, ...)` factory.
- TCP remains supported through the existing compatibility method.
- UDP policy-drop Activity evidence is now supported with `ipProtocol=17`.
- `DebugControlActivity.formatActivityL4Prefill()` reads
  `policyDropActivity.lastIpProtocol` instead of hard-coding TCP.
- S58 now uses UDP same-tuple probes for the product L4 workflow:
  - product-authored L4 drop uses `debugSetL4RuleIpProtocol 17`;
  - attribution applies `ipProtocol=17`;
  - debug probes use `debugUdpTraffic` and `debugUdpSourcePort`;
  - prefill must render `ipProtocol=17`;
  - restored allowed FlowEntry must report `lastIpProtocol=17`.
- S58 static contracts reject `debugTrafficSourcePort` in this matrix so fixed
  TCP source-port reuse cannot silently return.

This is a small product-facing seam improvement, not just a test workaround:
Basic L4 product prefill should be protocol-aware for both TCP and UDP, and
the Interface should not force a TCP-only proof for a protocol-neutral L4
workflow.

Validated locally:

- `tests/android/runtime-contract-test.sh`: passed, including Android runtime
  contract, S58 app-first Activity UI contract, S58 VPN L4 product workflow
  static contract, NDK daemon build and debug APK build.

Remaining product work after this slice:

1. Rerun corrected S58 against the rebuilt current APK.
2. Supply the real pinned HEV/lwIP driver behind `VpnHevLwipDriver`.
3. Rerun Android Direct Egress/device evidence after a real HEV/lwIP driver is
   selected by product runtime construction.

## 2026-08-26 nineteenth import slice

The next main-stack import slice landed the product runtime selection control
point for the VPN Flow Stack backend.  This does not supply the real
HEV/lwIP driver yet; it makes the startup path explicit so that a future driver
can be selected by configuration instead of being unreachable behind the
existing fd-compat default.

Changes:

- `RuntimeFactoryPlan` now parses stable VPN Flow Stack backend tokens:
  - `fd-compat` / `vpn-tun-fd-compat`;
  - `hev-lwip` / `vpn-tun-hev-lwip`.
- Missing backend env defaults to `fd-compat` for existing launchers.
- Unknown explicit backend env is rejected with
  `vpn_flow_stack_backend_unknown`.
- `daemon_main` reads `SAKAMOTO_VPN_FLOW_STACK_BACKEND` and forwards the
  selected backend into `createStartedRuntime(...)`.
- Android `RuntimeService` now exports
  `SAKAMOTO_VPN_FLOW_STACK_BACKEND=vpn-tun-fd-compat` explicitly when launching
  the current VPN product runtime.
- The existing HEV/lwIP facade selection remains gated on both:
  1. preferred backend is HEV/lwIP; and
  2. a `VpnHevLwipDriver` is actually supplied.

Interpretation:

- This closes a startup-path seam gap: before this slice, the product daemon
  always used the default fd compatibility backend even though the C++
  `VpnHevLwipFlowStackBoundary` and factory plan existed.
- The Android product path intentionally remains on `vpn-tun-fd-compat` until
  the RuntimeService lifecycle is updated to skip the old separate
  HEV/SOCKS transport fd handoff and a real `VpnHevLwipDriver` is supplied.
- S70/S71 root-profile closure is still waiting on the external KernelSU app
  authorization precondition recorded in the eighteenth slice.

Validated locally:

- `cmake --build --preset dev-debug --target runtime_profile_tests`: passed.
- `build-output/cmake/dev-debug/tests/host/runtime_profile_tests`: 16 passed.
- `tests/android/android-runtime-contract-test.sh`: passed.
- `tests/android/runtime-contract-test.sh`: passed, including NDK daemon build,
  debug APK build and active device-matrix static contracts.
- `git diff --check`: passed.

Remaining product work after this slice:

1. Clear the KernelSU app authorization precondition and rerun S70/S71.
2. Supply the real pinned HEV/lwIP driver behind `VpnHevLwipDriver`.
3. Update Android RuntimeService VPN lifecycle for the HEV/lwIP backend so it
   does not require the historical separate HEV/SOCKS transport fd handoff.
4. Rerun Android Direct Egress/device evidence after the real HEV/lwIP driver
   is selected by product runtime construction.

## 2026-08-26 eighteenth import slice

The current-head S71 dual-profile closure gate progressed past the earlier UID
drop, fixed TCP source-port, and S58 Activity-prefill hotspots, then stopped at
a device authorization precondition before the S70 product root profile
lifecycle evidence could start.

Evidence:

- Result directory:
  `build-output/s71-dual-profile-closure-gate/20260826-1330-s71-current-head`.
- Host/runtime contract passed.
- Host VPP graph and conformance gate passed.
- Root daemon build and deploy passed.
- Direct root NFQUEUE matrix passed:
  - Root OUTPUT app UID verdict evidence passed;
  - Root INPUT app-UID seam was correctly recorded as
    `UID_UNAVAILABLE`;
  - Root INPUT Unknown Application policy evidence passed;
  - restart, SIGKILL fault/recovery and final no-residue checks passed.
- Product VPN matrix passed against the current `vpn-tun-fd-compat` backend.
- S71 stopped when it invoked the S70 profile lifecycle matrix:
  - `profile_lifecycle_matrix.result=FAIL`;
  - `errorCode=root_authorization_required`;
  - `errorMessage=KernelSU/root execution is unavailable to this app process`;
  - the runtime projection remained `state=stopped` and
    `adapter=unavailable`.

Device authorization diagnosis:

- ADB shell root still works on the same device:
  `su 0 sh -c id` reports `uid=0(root)` with KernelSU context.
- The KernelSU allowlist contains only `com.android.shell` and Shizuku entries;
  it does not contain `com.sakamoto.snort.androidruntime`.
- Therefore shell root availability is not sufficient evidence that the
  product app process is authorized to launch the root runtime.
- The Android runtime manifest now declares KernelSU package visibility through
  `<queries><package android:name="me.weishu.kernelsu" /></queries>`, and S54
  static contract checks this.  This removes an app-visibility pitfall but does
  not itself grant root authorization on the device.

Interpretation:

- This is not a dataplane failure and not a regression of the UID seam
  decision.  It is an operational KernelSU app-authorization precondition for
  product root profile lifecycle testing.
- The correct next action is to grant KernelSU Superuser authorization to the
  installed `com.sakamoto.snort.androidruntime` app, then rerun S70/S71.
- Do not treat a passing `adb shell su` check as sufficient for S70/S71.  The
  app package must be authorized separately.
- Do not hand-edit KernelSU's binary `.allowlist` as part of normal POC
  automation.  If manual grant is unavailable, S70/S71 should fail fast with
  `root_authorization_required` and record the missing app authorization.

Remaining product work after this slice:

1. Clear the KernelSU app authorization precondition and rerun S70/S71.
2. Supply the real pinned HEV/lwIP driver behind `VpnHevLwipDriver`.
3. Rerun Android Direct Egress/device evidence after a real HEV/lwIP driver is
   selected by product runtime construction.

## 2026-08-26 seventeenth import slice

The corrected S58 UDP/product Activity workflow passed on device after native
policy-drop tuple evidence was added.

- Result directory:
  `build-output/s58-vpn-l4-product-workflow-matrix/20260826-1320-s58-tuple-current-apk`.
- APK build and install passed:
  - `apk.sha256=964377be9620659d5468a6aafd18a3921c51174891ec1639fcf264949626a8c4`.
- VPN start/control passed:
  - `start.result=PASS`;
  - `control.HELLO=PASS`.
- Product-authored UDP L4 block passed:
  - `policy_evaluate_block.evaluateWinner=DROP/L4/rule=5963268475143753088`;
  - `block.revision=2`.
- First unknown UDP packet was forwarded rather than held/dropped:
  - `first.forwardedPacketsDelta=1`;
  - `first.uidUnknownFallbackPacketsDelta=2`;
  - `first.droppedPacketsDelta=0`;
  - `first.probe.result=udp_datagram_sent`;
  - `first.noRecognitionHold=claimed`.
- Late attribution and next same-tuple drop passed:
  - `attribution.apply=PASS`;
  - `second.droppedPacketsDelta=1`;
  - `second.attributionResolutionsDelta=1`;
  - `second.policyDropActivity.uid=12629`;
  - `second.policyDropActivity.stage=L4`;
  - `second.policyDropActivity.remote=198.51.100.58:443`;
  - `second.policyDropActivity.sourcePort=45658`;
  - `second.policyDropActivity.protocol=17`;
  - `second.policyDropActivity.deviceDirection=output`.
- Activity-derived L4 prefill passed:
  - `drop.l4Prefill.result=available`;
  - summary includes `subject=android.uid:12629`,
    `destinationCidr=198.51.100.58/32`, `destinationPort=443` and
    `ipProtocol=17`;
  - `drop.activityPrefill=PASS`.
- Product-authored restore and allowed FlowEntry evidence passed:
  - `policy_evaluate_open.evaluateWinner=PASS_NEXT/None/rule=0`;
  - `open.forwardedPacketsDelta=1`;
  - `open.droppedPacketsDelta=0`;
  - `open.allowedFlowActivity.uid=12629`;
  - `open.allowedFlowActivity.remote=198.51.100.58:443`;
  - `open.allowedFlowActivity.protocol=17`;
  - `open.allowedFlowActivity.deviceDirection=output`;
  - `open.restoreAllowedFlowEntry=PASS`.
- Cleanup passed and `matrix.result=PASS`.

Interpretation:

- S58 now proves the intended VPN-side product workflow without relying on
  invalid fixed TCP source-port reuse:
  product-authored L4 block, first-unknown no-hold behavior, late attribution,
  next-packet L4 drop, Activity-derived L4 prefill and product-authored restore
  are all evidenced through the current APK.
- The hotspot was a POC/product evidence seam issue, not a new dataplane drop
  failure.
- This is still evidence for the current `vpn-tun-fd-compat` backend. It does
  not close the real HEV/lwIP Direct Egress driver import.

Remaining product work after this slice:

1. Supply the real pinned HEV/lwIP driver behind `VpnHevLwipDriver`.
2. Rerun Android Direct Egress/device evidence after a real HEV/lwIP driver is
   selected by product runtime construction.
3. Run the dual-profile closure gate if the remaining import plan still wants a
   full current-head closure bundle before the real driver lands.

## 2026-08-26 sixteenth import slice

The first corrected UDP S58 device run progressed past the original TCP
source-port hotspot and then exposed a second, narrower product evidence seam
gap:

- Result directory:
  `build-output/s58-vpn-l4-product-workflow-matrix/20260826-1300-s58-udp-current-apk`.
- APK build/install, VPN start, control HELLO and product-authored UDP L4 drop
  passed.
- First unknown UDP packet evidence passed:
  - `first.forwardedPacketsDelta=1`;
  - `first.uidUnknownFallbackPacketsDelta=3`;
  - `first.droppedPacketsDelta=0`;
  - `first.probe.result=udp_datagram_sent`.
- Late attribution and next same-tuple drop evidence passed:
  - `attribution.apply=PASS`;
  - `second.droppedPacketsDelta=1`;
  - `second.attributionResolutionsDelta=1`;
  - `second.policyDropActivity.uid=12629`;
  - `second.policyDropActivity.stage=L4`;
  - `second.policyDropActivity.rule=5963268475143753088`;
  - `second.policyDropActivity.revision=1`.
- The run failed at Activity-derived L4 prefill:
  - `drop.l4Prefill.result=unavailable`;
  - `drop.l4Prefill.summary=L4 prefill: unavailable`.

Root cause:

- Native `policyDropActivity` recorded the UID/rule/revision drop metadata, but
  did not expose the dropped packet tuple:
  `lastSourceAddress`, `lastDestinationAddress`, `lastIpProtocol`,
  `lastSourcePort`, `lastDestinationPort`, `lastPortsAvailable`,
  `lastDeviceDirection`.
- The prior TCP-only prefill design hid this gap because protocol was
  hard-coded as TCP and host/port were supplied by the debug request rather than
  by the Activity evidence itself.
- After S58 became UDP/protocol-aware, the missing `lastIpProtocol` defaulted
  to `0`, so `ActivityL4RuleDraft.fromPolicyDropActivity(...)` correctly
  rejected the draft as unsupported.

Design correction:

- `PacketPolicyDropActivityCounters` now records the relevant `PacketFacts`
  tuple alongside UID/rule/revision metadata.
- NFQUEUE and VPN/TUN adapters pass the actual policy-drop `PacketFacts` into
  that counter.
- Control vnext status now exposes the drop Activity tuple fields.
- Android `ProductNativeActivityIngestor.NativePolicyDropRecord` carries the
  tuple into product Activity rows, so drop rows can include remote/protocol/port
  evidence instead of only rule metadata.
- `DebugControlActivity.formatActivityL4Prefill()` now derives host, port and
  protocol from `policyDropActivity` itself.
- S58 runner now asserts the second drop Activity contains
  `lastIpProtocol=17`, the expected remote host/port, source port and
  `lastDeviceDirection=output` before accepting the prefill evidence.

Validated locally:

- `tests/android/android-runtime-contract-test.sh`: passed.
- `cmake --build --preset dev-debug --target snort-host-tests`: passed outside
  the sandbox; the sandboxed run failed only on control-server socket/bind
  restrictions, and the same control-server lane passed outside the sandbox.
- `tests/android/runtime-contract-test.sh`: passed, including NDK daemon build,
  debug APK build, S58 static contract and runtime service lifecycle contract.

Remaining product work after this slice:

1. Rerun corrected S58 against the rebuilt current APK.
2. Supply the real pinned HEV/lwIP driver behind `VpnHevLwipDriver`.
3. Rerun Android Direct Egress/device evidence after a real HEV/lwIP driver is
   selected by product runtime construction.
