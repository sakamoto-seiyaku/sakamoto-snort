# S245 Android VPN main-stack import readiness

Date: 2026-08-26
Status: `DESIGN_IMPORT_READY_PRODUCT_CODE_IMPORT_BLOCKED`

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
| `src/datapath/tun/VpnTunFdRuntime.hpp` | Writes allowed outbound packets to a transport fd and writes transport-return packets back to TUN. | This is a test/adapter placeholder. Product Direct Egress must replace it behind a deep Flow Stack interface. |

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
