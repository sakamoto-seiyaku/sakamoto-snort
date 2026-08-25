# S156 C2 one-flow-per-VPN-session hotspot

Date: 2026-08-24
Device: Pixel 6a (`28201JEGR0XPAJ`), Android 16
Artifact: the corrected S153 OI3 APK/plugin (the real-path artifact used for
the C2 fault/restart cells)

## Finding

The current real OI3 TUN lifecycle is effectively **one real AppA flow per
VPN session**. The first full-route flow can pass, but after that flow reaches
the ordinary positive terminal path, the native owner closes the detached TUN
fd. Android consequently removes the VPN Network. A second AppA flow in the
same Java/VpnService session waits for a `TRANSPORT_VPN` and settles as
`vpn_unavailable` without attempting its tuple.

This is a lifecycle/design boundary, not a DNS-family or underlay-connectivity
failure. It prevents a single session from carrying a registered sequence of
multiple fresh real flows (for example IPv4 followed by IPv6), which matters
to the remaining D/E campaigns unless each flow is preceded by an explicit
bounded VPN stop/start.

## Reproduction

### S153 sequence

After the real fault and explicit bounded restart:

1. AppA IPv4 UDP DNS `1.1.1.1:53`, source `46424`, bound to VPN handle
   `746435039245`, received a valid 61-byte DNS response.
2. AppA IPv6 UDP DNS `2606:4700:4700::1111:53`, source `46425`, in the same
   session recorded `bind_result=unavailable`, `vpn_network_handle=-1`,
   `tuple_attempted=false`, `send_connect_outcome=vpn_unavailable`,
   `error=no_active_transport_vpn`.

The inverse isolated order also works: a fresh session with IPv6 as its first
flow passed in S154 (`fd00:111:111::2`, handle `750730006541`, valid 61-byte
response). Thus IPv6 itself is not the failing cell.

### S155 sequence (formal stop/start, same Java service)

The fault was injected while real AppA TCP DNS traffic was active, then the
registered recovery sequence was used: explicit VPN teardown followed by a
fresh `vpp-oi3` start in the existing service process.

| Stage | AppA result | VPN handle | Native/result |
| --- | --- | ---: | --- |
| `S155-real-fault-same-service` IPv4 TCP to `192.168.4.5:42086` | `bound`, stop-side `Software caused connection abort` | `755024973837` | fault cleanup was error-free |
| `S155-post-restart-ip4` IPv4 UDP DNS | `bound`, valid DNS response | `763614908429` | `PASS`, `EXPECTED_DIRECT_REPLY`, buffers settled |
| `S155-post-restart-ip6` IPv6 UDP DNS in the same session | `unavailable`, no tuple attempt | `-1` | no second native `tun-flow`; VPN Network absent |

The S155 AppA JSONL is hashed as
`141f3f29119b36a1d5127fe747e5c0daf352bdb2c0c122ba90af23a8b6bde6e9`.
The corresponding native files are:

- `vpp-stdout.log`: `0be3c2fee25b9b86c2f2b5ea9267ba424a38c54e601a7b814bcd3f6ba9d22874`
- `vpp-cli.log`: `e516faac8bd33b06e73c7e853c78cfe982f6e6f7880e5bb540c9c43f5bb82677`
- `vpp-oi3-broker.log`: `3922501694e0de476c743a44dfc44409e9f73bef1d93256dd1a6bc97cf871527`

Native S155 terminal evidence contains one complete flow and then cleanup:

```text
oi3_cleanup result=PASS outcome=EXPECTED_DIRECT_REPLY generation=1 epoch=1
  output=1 direct=1 rewritten=1 broker=1/1 buffers=4/4 residue=0
```

After that cleanup, `dumpsys connectivity` contained the physical Wi-Fi
NetworkAgentInfo but no `TRANSPORT_VPN` NetworkAgentInfo. The Java adapter's
bounded lookup (`TrafficAdapterActivity.findVpnNetwork`, lines 950--975)
therefore correctly returned no active VPN; this is not a false negative from
the tuple sender.

## Source cause

`owner_inline_oi3.c:1845` closes `tm->tun_fd` from `oi3_finish()` for the normal
positive terminal path. Because this fd is the detached `VpnService.Builder`
TUN fd, closing it ends the Android VPN network. The Java service's
`stopVpn()` path separately calls `nativeStopVppProbe()` and closes its
retained VPN descriptor, but ordinary OI3 flow completion does not recreate the
VPN or keep the TUN owner alive for another flow.

The same-service fault attempt also showed the existing native
`g_vpp_pid` guard (`nativeStartVppProbe rc=-4`) when a new VPP was requested
before an explicit VPN stop. That rejection is expected and protects against
two VPP children; the supported recovery remains explicit stop/start. It is
not the one-flow hotspot itself.

## Impact and required decision

This hotspot was **OPEN / STOPPED FOR DESIGN REVIEW** during S156. It is now
closed for the registered POC contract by the lifecycle correction and real
same-session rerun in
[`S157_C2_TUN_REARM_EXECUTION_JOURNAL.md`](S157_C2_TUN_REARM_EXECUTION_JOURNAL.md).
The corrected contract keeps the detached TUN alive after a successful
positive flow, starts each next packet in a fresh generation, and still closes
the VPN on explicit stop/fault/underlay invalidation/negative cells. S157
carried real IPv4 UDP DNS followed by IPv6 UDP DNS on one VPN handle, with two
`PASS` cleanups and zero residue. This closes the one-flow boundary for the
registered POC; it does not claim arbitrary concurrent multi-owner capacity or
seamless Android underlay migration.

Two valid directions exist:

1. **POC contract adjustment (narrow):** register one real flow per VPN
   session and perform an explicit bounded stop/start between IPv4/IPv6 or
   repeated flows. D/E evidence then measures the restart cost and must state
   this boundary; this does not claim a persistent VPN dataplane.
2. **Lifecycle correction (broader):** keep the detached TUN fd and the OI3
   owner service alive after a completed flow, add an explicit per-flow
   settlement/re-arm state, and only close the VPN TUN on service stop/fault.
   That requires a new design/rebuild/rerun before claiming multiple real
   flows per session.

The campaign interruption is cleared for C2/D/E continuation under the
corrected re-arm contract. This record remains the historical hotspot handoff;
it is not a claim that the owner-inline architecture as a whole is overturned.
