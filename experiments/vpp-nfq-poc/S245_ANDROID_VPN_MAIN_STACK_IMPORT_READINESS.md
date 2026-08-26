# S245 Android VPN main-stack import readiness

Date: 2026-08-26
Status: `TENTH_DEVICE_START_AUTH_PITFALL_RECORDED_PRODUCT_DRIVER_IMPORT_BLOCKED`

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
