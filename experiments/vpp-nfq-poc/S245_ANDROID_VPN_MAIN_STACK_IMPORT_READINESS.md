# S245 Android VPN main-stack import readiness

Date: 2026-08-26
Status: `SUPERSEDED_BY_ADR_0008_CXX_MAINLINE_REMOVAL`

## Disposition

ADR-0008 removed the entire Snort C++ mainline, including every source file,
host test, NDK/APK daemon artifact, C++ Flow Stack facade, backend selector,
and archived source. The former C++ import-slice plan is void. It must not be
recreated, ported, used as a fallback, or treated as a source of product module
shape.

The Android RuntimeService deliberately reports `c_vpp_mainline_required`.
S55--S71 and the old `vpn-tun-fd-compat` path are historical evidence only;
they cannot be rerun or claimed for current head.

## Evidence retained from OI1--OI5

The following are design constraints for a future, newly specified
VPP-native C Module. They are not permission to import OI3 or any other POC
source file:

- One canonical FlowOwner exclusively drives its opaque Flow Stack shard.
- HEV/lwIP callbacks are owner-local; no global mutable transport authority,
  shard migration, or overload spill is allowed.
- Scheduler work is bounded and returns to VPP; HEV must not take over a VPP
  worker.
- Same-owner deferred work makes bounded local progress; only cross-owner work
  creates a generation-tagged wake.
- The Android broker may bind/protect sockets but cannot own transport state.
- Packet provenance, bounded ownership settlement, and generation-safe
  quiesce/teardown remain mandatory.
- Return packets re-enter the shared VPP graph before TUN completion.

## Next work

Create a specification and implementation tickets for the VPP-native C Flow
Stack Module. That work must define the real C Interface, VPP buffer ownership,
external-driver scheduler contract, Android protected-socket broker contract,
RuntimeService lifecycle, and current-head product evidence. It must not start
with a C++ port or a direct POC import.
