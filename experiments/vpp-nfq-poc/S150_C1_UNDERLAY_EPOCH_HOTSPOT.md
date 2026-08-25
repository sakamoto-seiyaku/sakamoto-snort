# S150 C1 Underlay Epoch Hotspot

Date: 2026-08-24
Device: Pixel 6a (`28201JEGR0XPAJ`), Android 16
VpnLite APK: `720a844bef4049a5e0e564655be4ffa82dd8db32d9f2fd8ce283018b62d83099`
OI3 plugin: `8adefc0c9e7a32e00f50ac3b10405a41d1b734873734ec3c45649e7f7dbeb671`

## Finding

C1 is **paused at a design hotspot**.  The selected Android path chooses a
physical non-VPN Network only when a broker request arrives.  It does not
register a `ConnectivityManager.NetworkCallback`, publish `onLost`/`onAvailable`
or handle changes as an OI3 underlay epoch, invalidate old FlowOwner state, or
reject late events against that platform epoch.  Native `generation/epoch`
currently advances with a flow/run, not with the real physical Network
identity.

This is not a missing permission or endpoint fixture.  The source path is
`SnortVpnService.findNonVpnUnderlayNetwork()` plus
`bindAndProtectSocketForNative()`; both are request-time selection/bind
operations and there is no callback registration or epoch publication in the
service.

## Runtime reproduction

The Pixel had no cellular data available, but did have a real Wi-Fi loss and
replacement path.  A full-route OI3 VPN was started with only AppA UID 12630
allowed.  The physical and VPN handles before the first toggle were:

```text
physical Wi-Fi Network 100  handle=432902426637  wlan0 192.168.4.151/24
VPN Network 148          handle=639060856845  underlying=[100]
```

After `svc wifi disable`, Android reported:

```text
Active default network: none
VPN Network 148 handle=639060856845 underlying=[]
```

After `svc wifi enable`, Android created a replacement physical network:

```text
physical Wi-Fi Network 149 handle=643355824141
VPN Network 148 handle=639060856845 underlying=[149]
```

A later cleanup/recovery toggle produced another replacement Wi-Fi handle
`651945758733`, confirming that the handle is not stable across loss/rejoin.
The AppA runtime JSONL is `files/debug/b1-runtime.jsonl` (SHA-256
`36dbb2403b49da85ba32537ad45e9e9ae988bac8a3e0f2667af16e1a70fe9e7b`).

The active-flow cell used a real AppA TCP socket from
`10.111.0.2:46404` to the WSL2 endpoint `192.168.4.5:42083`; its record was:

```text
stage=C1-active-transition
bind_result=bound vpn_network_handle=647650791437
send_connect_outcome=tcp_connect_failed error="Software caused connection abort"
```

The corresponding native stdout (`files/vpp/logs/vpp-stdout.log`, SHA-256
`2716289b483355cd7ea30306dcd8d1a246337e4cc8636a12689342507d817dfd`) shows
the flow admitted at `generation=1 epoch=1`, broker `1/1`, then a Wi-Fi-loss
RST and `connector-wake cause=2 generation=1`.  It contains no
`epoch-invalidated`, old-generation rejection, or platform-handle transition
record; cleanup remained on `generation=1 epoch=1`.

The Java logcat does show request-time reselection: before loss it selected
`432902426637`; only a later new broker request, after recovery, selected
`643355824141`.  There is no `onLost`/`onAvailable` callback emitted by the
VpnLite service between those observations.

## Why this stops the campaign

The C1 minimum claim requires a real underlay transition while old TCP/UDP
state is active, old state invalidation, late-event rejection, and fresh-flow
binding on the new snapshot.  The current artifact can observe Android's VPN
underlying-network list changing, but it has no owner-local event/epoch seam
that makes the transition part of FlowOwner correctness.  Continuing to D/E
with synthetic OI5 generations would therefore test a different contract and
would overstate C1/C2 lifecycle coverage.

This meets the campaign's stop standard for a reproducible design defect:
underlay identity changes are real, but the selected design has no
Network→epoch propagation/invalidation boundary.  The Wi-Fi state was
restored and the VPN/test processes were stopped after collection; no
temporary WSL endpoint remains listening.

## Required plan revision before resuming

1. Add a bounded `ConnectivityManager.NetworkCallback` for non-VPN validated
   underlays, with monotonic handle/epoch records for `onAvailable`, `onLost`,
   and replacement selection.
2. Add an explicit Java→native underlay-epoch control seam.  OI3 must publish
   the new epoch on its owner thread, close admission for the old epoch, and
   reject stale broker/completion/wake/output/TUN events.
3. Make fresh broker requests bind/protect only the current snapshot and log
   the physical handle alongside the FlowOwner generation/epoch.
4. Rerun the smallest active AppA TCP+UDP transition matrix before resuming
   C2, then rerun C2's real-traffic cells.  Only after C1 is closed should D/E
   resume.

The issue is recorded as `VPN-F033` in the Finding Ledger; no production fix
is applied in this paused turn.
