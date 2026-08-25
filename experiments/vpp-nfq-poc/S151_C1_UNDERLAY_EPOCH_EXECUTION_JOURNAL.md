# S151 C1 underlay epoch execution journal

Date: 2026-08-24
Device: Pixel 6a (`28201JEGR0XPAJ`), Android 16, Wi-Fi `Openwrt_5G`
C1 execution APK: `3971879faed7d6b34584bfdd08252cdc18f88f8d992ad221327061c5271d8214`
Current C2-control APK (same C1 seam plus bounded `show/stop/fault` JNI control): `272f860012307d021f5a97800f73727e486e13150dc6d5fbd5f58081d1393b2e`
OI3 plugin: `fbfeabfb29f650fd237ac6839148091c233b6ca107cf656219b681c4449dfdf1`
HEV library: `88cc920e6aca9bf1b999372d40fc895077208ea545d918ac2b22471eeabffc04`

## Purpose

Close the S150 `VPN-F033` hotspot by carrying a real Android physical-network
snapshot through `NetworkCallback → JNI/CLI → FlowStackOwner`. The owner must
invalidate an active generation on a real underlay transition, settle it once,
and a bounded VPN-session restart must carry fresh traffic on the replacement
underlay.

## Correction

- `SnortVpnService` registers a `ConnectivityManager.NetworkCallback` with
  `INTERNET + NOT_VPN`, publishes a monotonically increasing epoch, physical
  `Network.getNetworkHandle()`, and availability through
  `nativeSetVppUnderlayEpoch`.
- `vpn_fd_probe.c` serializes the CLI publication and records the JNI/CLI
  result; `owner_inline_oi3.c` consumes one immutable pending snapshot on the
  FlowStackOwner and never mutates owner state from the callback thread.
- An epoch change while a flow is active closes admission, marks the flow
  `EXPECTED_UNDERLAY_INVALIDATION`, and rejects late broker/wake/output/TUN
  work during the normal cleanup path.
- The startup race was corrected: an initial callback snapshot arriving before
  `sakamoto-oi3 tun` is retained instead of being overwritten by a synthetic
  `epoch=1, handle=-1` default.
- The short POC VPN service now enters Android foreground mode. This prevents
  Android 16's idle-service reaper from unregistering the callback during a
  bounded lifecycle cell. It is an execution-lifecycle correction, not an
  owner or transport authority change.

## Pixel evidence

### Active-flow invalidation

The corrected callback/owner artifact was run with AppA TCP already connected
to the WSL2 LAN fixture. The physical handle changed from `682010529805` to
unavailable while generation 1 was active. The owner log contained:

```text
oi3 underlay epoch published epoch=2 handle=-1 available=0
oi3 underlay-epoch owner-apply old-epoch=1 new-epoch=2 old-handle=682010529805 new-handle=-1 available=0
oi3 epoch-invalidated reason=underlay-transition generation=1 old-epoch=1 new-epoch=2 old-handle=682010529805 new-handle=-1 old-tcp-reconnect=0 old-udp-reuse=0
oi3_cleanup result=PASS_EXPECTED_UNDERLAY_INVALIDATION outcome=EXPECTED_UNDERLAY_INVALIDATION generation=1 epoch=2 fault-injected=0 output=1 handshake=1 direct=0 rewritten=1 endpoint=0/0 accepted=0 broker=1/1 duplicate-close=0 underlay-invalidated=1 underlay-handle=-1 underlay-available=0 transport-failures=0 infrastructure-failures=0 buffers=6/6 residue=0 error=
```

AppA recorded `C1-active-transition`, IPv4/TCP, source port `46406`,
`tcp_connect_succeeded`, and a real VPN bind. No transparent reconnect or
old-UDP reuse was observed. The owner/plugin/native source used here is the
same corrected C1 seam packaged in the final APK; the final APK adds only the
foreground-service lifecycle correction described above.

### Final APK callback recovery and bounded session restart

With the final APK, the service published:

```text
OI3 underlay epoch reason=initial epoch=1 physicalHandle=694895431693 available=true
OI3 underlay epoch reason=lost epoch=2 physicalHandle=-1 available=false eventHandle=694895431693
OI3 underlay epoch reason=available epoch=3 physicalHandle=707780333581 available=true
```

Each JNI publication returned `cliRc=0`. Android disconnected the old VPN
Network while Wi-Fi was absent; therefore callback recovery alone does not
recreate the Android VPN Network. The registered bounded recovery action was
to stop/start one fresh VPN session. The new session had physical handle
`707780333581`, VPN handle `712075300877`, epoch 1, and AppA IPv4/UDP
`C1-session-restart-udp` completed through broker/direct/TUN with:

```text
oi3_cleanup result=PASS outcome=EXPECTED_DIRECT_REPLY generation=1 epoch=1 fault-injected=0 output=1 handshake=0 direct=1 rewritten=1 endpoint=0/0 accepted=0 broker=1/1 duplicate-close=0 underlay-invalidated=0 underlay-handle=707780333581 underlay-available=1 transport-failures=0 infrastructure-failures=0 buffers=4/4 residue=0 error=
```

The fresh AppA record has `vpn_network_handle=712075300877`,
`udp_datagram_sent`, and the exact replacement physical handle is present in
the Java/native epoch records.

The same final APK session also ran a fresh IPv6 AppA datagram after the
bounded restart:

```text
stage_id=C1-session-restart-ip6-udp
family=ip6 protocol=udp source=fd00:111:111::2:46412
destination=[2606:4700:4700::1111]:53
vpn_network_handle=724960202765
send_connect_outcome=udp_datagram_sent
```

OI3 parsed the IPv6 TUN ingress, selected the current physical handle
`716370268173`, completed the broker request, and emitted `direct-send`. The
external IPv6 DNS reply did not arrive before the five-second direct-flow
deadline (`tun-flow-timeout-no-reply`, `residue=0`); this is retained as a
transport-response boundary and is not promoted to an IPv6 reply claim. The
C1 requirement is the fresh bind/protect and owner-path epoch identity, while
the already recorded S148 IPv6 DNS controls cover the separate external
response claim.

### Invalid timing control retained

One final-APK attempt started AppA from a cold task and then disabled Wi-Fi in a
separate host command. Android delivered `onLost` after the fixed 5-second
OI3 flow deadline, so that row is a fixture-timing `FAIL` (no active VPN at the
later recovery probe), not C1 invalidation evidence. It is retained rather
than silently treated as a pass; the bind-gated sequence above is the deciding
control.

## Static regression

```text
test_verify_s151_c1.py + test_verify_s146_b2.py: 7 tests OK
git diff --check: PASS
build-debug-apk.sh with HEV_STAGE_DIR and VPP_POC_PLUGIN: PASS
```

## Conclusion

`VPN-F033` is closed for this POC artifact. Real physical-network loss is
propagated to the owner epoch, active state is invalidated and settled once,
and a bounded explicit VPN-session restart carries fresh traffic on the new
physical snapshot. This does not claim seamless Android VPN migration or
automatic session recreation for every OEM/network transition. C2 must use
the same callback/epoch evidence and the bounded restart rule; D/E may resume
after C2's real-traffic lifecycle gate.
