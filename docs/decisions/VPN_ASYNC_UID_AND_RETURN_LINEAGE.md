# Product VPN identity and return lineage (2026-09-28)

SAKAMOTO-289 makes the ordinary Android VPN profile launch the VPP-native
TUN/Flow Stack path. This decision records the first-version boundary accepted
for application identity and return-flow accounting. It refines the existing
nonblocking attribution rule in [CONTEXT.md](../../CONTEXT.md) and the
[Product plan](../product/ANDROID_L4_PRODUCT_PLAN.md); it does not change
canonical owner selection or Root NFQUEUE behavior.

Android's TUN fd supplies no per-packet UID. Each Product VPN owner therefore
uses a bounded, generation-scoped asynchronous `getConnectionOwnerUid` broker.
Only an admitted FlowEntry can cause a request. A cold packet continues with
Unknown Application; a completed policy verdict is never revised or replayed.
A result enriches only the same still-live FlowEntry incarnation. A conflicting
resolved UID retires that incarnation so a later device-origin packet can
establish the replacement. A broker miss or timeout makes the affected current
packet Unknown without clearing a previously enriched FlowEntry UID or closing
the live flow merely because identity is unavailable.

The accepted limit is rapid reuse of a *live UDP tuple* by another Android app.
UDP has no SYN or socket cookie in TUN bytes. During the bounded asynchronous
lookup/cache window, either app's packet can receive the other's UID and thus
an incorrect ALLOW or DROP. There is no strict cross-app isolation or
one-packet upper bound for this window. TCP new SYN invalidates the cached UID;
it is not a claim of absolute TCP identity certainty. Users who need strict
per-app isolation should not infer it from the current VPN profile.

HEV copies the full 64-bit admitted FlowEntry incarnation into its owner-local
session facts. A return receives a full-width incarnation through the existing
Flow Stack output callback. The Adapter associates it with the return's exact
token and generation in a 128-slot-per-owner ledger, the same capacity and
lifetime as existing return credits. It holds no packet, UID, pointer, or
second attribution cache. The graph reads the stamp before terminal completion;
the origin frees the buffer, releases the stamp, then returns the credit. A
return can update only its still-live exact incarnation. An old return may
still reach TUN under normal policy, but cannot create or mutate a new
FlowEntry. VPP `pre_data` remains packet headroom; platform network context
is preserved for policy and telemetry.

Product HEV UDP idle retirement is derived from the shortest bidirectional
FlowEntry timeout (30 seconds) with a five-second scheduler margin. This makes
normal idle rollover create a fresh protected session before the old flow
expires. A delayed owner timer or remote-only activity can still leave an old
HEV session when a new incarnation's first datagram arrives. HEV rejects that
trigger, closes the old session, and accepts a later datagram. The first
version does not promise loss-free UDP under such scheduling or return-policy
interleavings. It keeps the old return's lineage rather than relabeling it as
the new flow.

Android `VpnService.Builder` DNS servers are captured from the selected
underlay at TUN establishment. `dnsRestartRequired` is a separate dashboard
status when that underlay or its DNS set changes; `running` and
`protectionRunning` continue to describe the native VPN path, and an offline
underlay has its own availability status. Restarting VPN refreshes the Builder
DNS configuration. This status does not claim live DNS roaming.

Device and Host evidence is in
[SAKAMOTO-289 acceptance](../testing/2026-09-28_S289_VPN_NORMAL_START.md).
