# S148 B1 Dual-stack Execution Journal

Date: 2026-08-24
Device: Pixel 6a (`28201JEGR0XPAJ`), Android 16
VpnLite APK: `cb921108bf88b8a9ae77818378547bd11b3fa77fb7e0680191465e501820963e`
OI3 plugin: `b1a2f018180fb5b79d322c02b32340aa7e6bc924e038b345363ef1660cea8a6c`
HEV arm64: `88cc920e6aca9bf1b999372d40fc895077208ea545d918ac2b22471eeabffc04`
Allowed AppA: `com.sakamoto.snort.poc.appa`, UID `12630`

## Preflight

The exact APK was installed on the Pixel and each row used a fresh full-route
`vpp-oi3` VPN session with AppA as the sole allowed package and IPv6 enabled.
The VPN receipt recorded IPv4 `0.0.0.0/0` and IPv6 `::/0` routes. The Android
OI2 broker repeatedly selected physical Wi-Fi handle `432902426637` with
`vpn=false`, `notVpn=true`, `validated=true`, `internet=true`, then recorded
`Network.bindSocket=true` and `VpnService.protect=true`.

## Final external matrix

All AppA records report `bind_result=bound`, a valid 61-byte DNS response, and
`response_valid=true`. Native OI3 recorded direct send/receive, TUN return,
and exact buffer settlement for every row.

| Cell | Source port | App result | Native result |
| --- | ---: | --- | --- |
| IPv4 UDP DNS | `46313` | `udp_datagram_sent` → `dns_response_received`, 61 bytes | `PASS`, output/direct/rewritten `1/1/1`, buffers `4/4`, residue `0` |
| IPv4 TCP DNS separate | `46314` | `tcp_payload_sent` → `dns_response_received`, 61 bytes | `PASS`, output/handshake/direct/rewritten `4/1/4/4`, buffers `19/19`, residue `0`; direct sends `1` then `30` |
| IPv4 TCP DNS coalesced | `46315` | `tcp_payload_sent` → `dns_response_received`, 61 bytes | `PASS`, output/handshake/direct/rewritten `3/1/3/3`, buffers `16/16`, residue `0`; direct send `31` |
| IPv6 UDP DNS | `46316` | `udp_datagram_sent` → `dns_response_received`, 61 bytes | `PASS`, output/direct/rewritten `1/1/1`, buffers `4/4`, residue `0` |
| IPv6 TCP DNS separate | `46317` | `tcp_payload_sent` → `dns_response_received`, 61 bytes | `PASS`, output/handshake/direct/rewritten `4/1/4/4`, buffers `19/19`, residue `0`; direct sends `1` then `30` |

The IPv4 TCP control also completed the required SYN/ACK and close sequence;
the IPv6 TCP control did likewise. The AppA payload and response IDs were
preserved, and the native logs retained the original external destinations
(`1.1.1.1:53` and `[2606:4700:4700::1111]:53`) rather than a resolver or SOCKS
fallback path.

## B1 conclusion and boundary

The minimum Pixel full-route positive B1 matrix is **SUPPORTED for this exact
artifact/device/underlay cell**: external IPv4/IPv6 UDP/TCP DNS, separate and
coalesced TCP writes, protected non-VPN underlay selection, Direct send/recv,
TUN return, and zero residue all passed.

This does not close repeated-network/OEM behavior, large-response/fallback
stress, lifecycle/epoch, policy failure on a real App UID, or the remaining
C/D/E claim families.
