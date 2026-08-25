# SAKAMOTO-140 B1 Protected-socket Return Hotspot Diagnosis

Date: 2026-08-24
Status: hotspot fixed; controlled and original regressions passed
Scope: diagnose and fix the first B1 protected-socket return failure only

## Outcome

The current failure is bounded to the interval after HEV has successfully
written the App payload to the Android-protected connector socket and before
HEV observes returned bytes on that socket. It is not an A2 UID-attribution
failure and is not yet evidence against ADR-0007.

This revision replaces broad B1 reruns with a staged, observable feedback
loop. It does not weaken the final B1 real-network matrix, introduce a second
datapath, permit an unprotected fallback, or continue into later POCs after
the hotspot is fixed.  A subsequent default-route TCP cell exposed a separate
underlay-selection failure; that finding and correction are recorded in
[`S141_B1_TCP_UNDERLAY_NETWORK_HOTSPOT.md`](S141_B1_TCP_UNDERLAY_NETWORK_HOTSPOT.md).

## Registered symptom

The valid S139 B1 runs share this sequence:

```text
App UDP send
-> VPN TUN ingress
-> VPP policy/owner path
-> Android broker completion SUCCESS
-> HEV connector socket creation/connect
-> kernel send() succeeds
-> oi3 direct-send
-> no readiness wake from returned data
-> no oi3 direct-recv
-> no TUN return
-> App receive timeout
```

Four App triggers timed out. Three reached the native `direct-send` boundary;
one run was invalid because the plugin did not load. Controlled local endpoint
runs have previously completed `direct-send -> direct-recv -> TUN output`, so
the failure is specific to the real protected-socket return interval.

## Preserved contracts

- UID remains an asynchronous policy fact selected after canonical FlowOwner.
- Only the canonical owner executes HEV/lwIP mutable callbacks.
- The Android broker may bind/protect an SCM_RIGHTS duplicate but never owns
  transport state.
- Every Direct socket must bind to an explicit non-VPN underlay and be
  protected before connect/first send.
- Diagnostic controls never retry unprotected, use SOCKS, or bypass the normal
  Flow Stack/VPP/TUN return path.
- A WSL2/LAN endpoint is a diagnostic oracle only. Final B1 Internet and DNS
  claims remain outside this hotspot fix.

## Ranked falsifiable hypotheses

1. **No network round trip.** If the protected socket request or reply does not
   traverse the LAN, the controlled server will not record the request or the
   Pixel will not observe the server reply.
2. **Wrong exact-fd underlay state.** If the B1 fd is not bound/protected as
   claimed, its joined Network handle, `SO_MARK`, local address, or kernel route
   will not identify the physical Wi-Fi network for the same stage/token/fd.
3. **Readiness/re-entry loss.** If the reply reaches the connector socket but
   OI3/HEV misses it, the Pixel/server boundary will prove the reply while the
   connector observer records `POLLIN` without a corresponding
   `direct-recv`, or HEV task re-entry will make no progress.
4. **Public DNS fixture failure.** If only the uncontrolled `1.1.1.1:53`
   fixture is failing, a controlled UDP echo round trip through the exact B1
   route will pass without a runtime change.

The discarded hypothesis is that `connector.input` must perform the first
socket send. The pinned HEV TCP and UDP implementations call `writev()` or
`send()` before invoking that callback; adding another send duplicates data.

## Staged feedback loop

Every stage uses a unique `stage_id` and joins App, VPP, broker, fd, server,
return, and cleanup evidence.

### D0 -- Environment and artifact provenance

Record Pixel/WSL2 addresses, APK hash, plugin hash, overlay source hash,
installed package/UID, VPN network handle, and the exact runtime start result.
The plugin embedded in the APK must be built from the recorded overlay source.

### D1 -- Direct LAN controls

With the VPN runtime stopped, prove Pixel-to-WSL2 TCP/HTTP and UDP echo
round trips. This validates the LAN server, firewall, and reply oracle only.
On Android 16 devices with `RESTRICT_LOCAL_NETWORK` enabled, also prove the
VPN package that owns the protected underlay socket has the temporary
`NEARBY_WIFI_DEVICES` runtime grant. A shell-UID LAN probe is not an adequate
substitute: the local-network policy is enforced per application UID.

### D2 -- Full-path protected-socket transmit

Run one IPv4 UDP echo payload from the controlled App through the default-route
VPN and owner-inline path. Join:

```text
stage_id -> canonical_key -> broker token -> connector fd
         -> Android Network handle/capabilities -> SO_MARK
         -> local/peer tuple -> server receive
```

Server absence localizes the failure before or at physical egress.

### D3 -- Protected-socket return readiness

For the server reply, record server send, Pixel interface counters/capture when
available, connector `poll()` result/revents, `SO_ERROR`, and the owner wake.
The observer remains wait-only and never reads connector bytes.

### D4 -- HEV/VPP/TUN/App return

Require `direct-recv`, HEV output, VPP return provenance, terminal TUN write,
and exact App payload receipt. Any missing consecutive boundary identifies the
fix seam.

### D5 -- Original symptom regression

After the root-cause fix, rerun the same controlled UDP cell and the original
IPv4 UDP DNS trigger. The controlled cell is the regression gate; the public
DNS result is reported separately because it remains externally variable.

## Decision table

| Last proven boundary | First missing boundary | Diagnosis seam |
| --- | --- | --- |
| connector `send()` | server receive | Android underlay/mark/route/egress |
| server reply | Pixel reply ingress | LAN/device network ingress |
| Pixel reply ingress | connector `POLLIN` | socket demux/bind/mark |
| connector `POLLIN` | HEV `direct-recv` | OI3 observer/HEV task reactor |
| HEV `direct-recv` | VPP/TUN output | Flow Stack return/VPP graph |
| TUN output | App receipt | return tuple/checksum/App fixture |

## Fix and stop rule

Change only the first implementation seam contradicted by the evidence. Add a
regression assertion at the deepest real seam available, rerun the original
minimized loop, remove tagged temporary instrumentation, and prove zero
process/TUN/socket/fd residue.

Once this protected-socket return hotspot passes its controlled regression,
stop. Do not proceed to the remaining B1 dual-stack/DNS matrix, B2, or any
later campaign POC without a new user instruction.

## Execution result

The registered symptom no longer reproduces. The investigation found two POC
execution defects and one diagnostic-fixture defect; it did not find a new
contradiction in the owner-local HEV/VPP datapath.

### Root cause chain

1. The staged plugin/APK was not source-identical to the current OI3 overlay,
   and the default HEV stage did not export the owner API required by OI3. A
   run with that pair failed at HEV API load and was not a valid B1 attempt.
2. The Android APK packager accepted both the canonical VPP plugin name and an
   Android linker-prefixed alias. Injecting a fresh `VPP_POC_PLUGIN` updated
   only the canonical file; a stale `libhev_external_driver_poc_plugin.so`
   later overwrote it inside the APK. The packager now updates both names from
   the same input artifact.
3. Pixel had Android 16 local-network protection enabled for the VpnLite test
   package. A shell-UID UDP control passed, but both an ordinary VpnLite UID
   socket and the protected OI3 fd lost the LAN reply. Pixel `tcpdump` proved a
   checksum-valid reply entered `wlan0`; `ss -uapmne` showed the exact OI3 fd
   with `Recv-Q=0`, a normal 327680-byte receive buffer, and `drops=1`.
   `netd` exposed `map_netd_local_net_blocked_uid_map`. The POC APK now declares
   Android 16's temporary `NEARBY_WIFI_DEVICES` permission, the test package was
   granted it, the stale `RESTRICT_LOCAL_NETWORK` compat override was disabled,
   and the device was rebooted so netd/BPF state was rebuilt.

The pre-existing OI3 readiness implementation was then rebuilt from the exact
overlay source. No unprotected fallback, second datapath, or duplicate socket
send was added.

### Boundary evidence

- Direct Pixel shell -> WSL2 TCP and UDP controls passed.
- Before the local-network fix, the controlled server received and replied to
  the exact tuple, Pixel `wlan0` captured the reply, and the OI3 socket recorded
  one kernel drop with no `POLLIN`.
- After the fix, the VpnLite-UID direct UDP control changed from a 5009 ms
  timeout (`received=0`) to a 25 ms reply (`received=1`).
- Controlled full-path stage `B1-LAN-UDP4-20260824-FINAL2` passed:
  App `dns_response_received`, exact 29-byte response valid, OI3
  `connector-wake cause=1`, one Direct return, one rewritten TUN output, cleanup
  PASS, VPP buffers `4/4`, residue `0`.
- Original public stage `B1-PUBLIC-DNS-UDP4-20260824-FIX` also passed against
  `1.1.1.1:53`: App received a valid 61-byte DNS response and OI3 cleanup was
  PASS with residue `0`.

### Planning consequence

The owner-inline architecture and the B1/B2 blocker order remain unchanged.
Subsequent continuation under the user's explicit instruction to complete the
remaining POCs reached a separate multi-write TCP framing hotspot; it is
recorded in [`S142_B1_TCP_STREAM_FRAMING_HOTSPOT.md`](S142_B1_TCP_STREAM_FRAMING_HOTSPOT.md)
and is now the active stop condition.  S140's protected-socket return fix is
not being used to waive that later stream gate.
The campaign protocol now has an explicit run-validity preflight before B1 and
later Pixel real-network cells: transitive source/stage/APK/runtime provenance,
same-package-UID network eligibility, declared Android permission/compat state,
and endpoint readiness must pass before a timeout can be classified as
transport or datapath evidence. The controlled LAN and single public IPv4 UDP
DNS regressions above are scoped evidence only; they do not close the remaining
B1 IPv4 TCP, IPv6 TCP/UDP, DNS-over-TCP/fallback, or complete full-device matrix.

The canonical updates live in
[`ANDROID_VPN_POC_CAMPAIGN_SPEC.md`](ANDROID_VPN_POC_CAMPAIGN_SPEC.md),
[`POC_FINDING_LEDGER.md`](POC_FINDING_LEDGER.md),
[`ANDROID_VPN_EVIDENCE_GAP_MAP.md`](ANDROID_VPN_EVIDENCE_GAP_MAP.md), and the
[`android/vpn-lite` runbook](android/vpn-lite/README.md).

### Final artifact provenance

```text
OI3 overlay source SHA-256:
c1ff1370ab783d3f71e14930ccb5d8b15e93dd132518a207ffdd194a6d5eeafe

OI3 plugin SHA-256:
99646be96159f6e937ff48647bd412cfd043c32b5673b6ee17e0852fb53bc7b8

HEV arm64 SHA-256:
fe476e75c9ddc619c07df030f935dad36962cc40a4bc578866eb89d5c3ecedf9

Device-verified VpnLite APK SHA-256:
787bd9dede6da836034d5e85b5107000fc2960e7c74dfcc0be100c5564902caa

Current post-build-assertion APK SHA-256:
75e8e1837135c3a55709f2f8d1cb92553bbbdbfab0ca0b84df1ade400aa278a1
```

Both APK plugin spellings have the exact plugin hash above. Neither source,
plugin, nor final device runtime log contains the temporary tagged
instrumentation. The extracted member trees of the device-verified and current
APKs are byte-identical; the outer-file hash changed only because the APK was
repackaged after adding the packaging provenance assertion.
