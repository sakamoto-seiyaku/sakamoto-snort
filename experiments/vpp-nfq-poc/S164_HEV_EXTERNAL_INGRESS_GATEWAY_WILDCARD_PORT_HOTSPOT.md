# S164 HEV external-ingress gateway wildcard-port hotspot (2026-08-24)

Status: `RESOLVED_BY_S165_DESIGN_CORRECTION`; E2 is reopened for the
remaining matched matrix and resource measurements.

This record covers only the owner-context HEV external-fd/LAN arm of E2.  It
does not invalidate the previously supported A2, B, C, D or E1 cells, and it
does not turn E2 into a performance result.

## Reproduction boundary

- Device: Pixel 6a, Android 16, serial `28201JEGR0XPAJ`.
- Device access: repository `./dev/adb` with the WSL platform-tools backend.
  The Windows interop path briefly returned a WSL vsock timeout; the WSL
  backend then reported the device as `device` and all diagnostic installs
  succeeded.
- Controlled endpoint: temporary WSL2 HTTP server
  `192.168.4.5:42083`; the same-UID no-VPN control was already known to work.
- The diagnostic APK intentionally included the temporary `tun_poc` plugin and
  must not be treated as the canonical product APK.
- The temporary HTTP service and device processes were stopped after the last
  run; port `42083` was verified free and no VpnLite/HEV process remained.

## Bounded attempts

The first baseline established that the fd seam itself was live: the HEV fd
was a `SOCK_SEQPACKET`, epoll returned `POLLIN`, and 14 packets were read.  The
baseline timed out at about 5010 ms with `shim-tx=14`, `shim-rx=0`.

Three subsequent, valid post-fix attempts all timed out without an HTTP
response.  They are counted as one stop-rule series, not as independent
environment failures:

| Attempt | Change in the stage | Result | Relevant evidence |
| --- | --- | --- | --- |
| 1 | External owner context enabled `accept_nonlocal` for the external fd | 5011 ms timeout | epoll/read healthy; no HEV session/connector event |
| 2 | TCP owner demux changed from `VERSION_MATCH_EXACT` to the standard ANY-aware version match | 5008 ms timeout | no TCP accept; `shim-tx=14`, `shim-rx=0` |
| 3 | Same TCP change with bounded TCP-input trace | 5008 ms timeout | SYN reaches TCP input and passes checksum, but listener match is null |

The third run's decisive trace was:

```text
s164_trace stage=owner-config accept-nonlocal=1 fd=108
s164_trace stage=tcp-input p-len=40 p-tot=40 src-type=0 dst-type=0 sport=54008 dport=42083 flags=0x2
s164_trace stage=tcp-check checksum=0
s164_trace stage=tcp-listen-match dport=42083 lpcb=0x0 ...
```

No `tcp-accept`, HEV session, connector, or second protect request followed
the SYN.  The three valid failures meet the campaign stop rule; no further
device retry was made.

## Root cause

The external ingress design has two separate missing boundaries:

1. The owner-context IPv4/IPv6 input paths originally accepted only the
   synthetic owner addresses (`10.0.0.1`/`fd00::1`).  Original-destination
   packets from the external VPN fd were read successfully and then dropped.
   The diagnostic `accept_nonlocal` opt-in isolated this behavior, but it is
   not sufficient by itself.
2. `gateway_init()` creates the transparent TCP/UDP gateway as an
   `IPADDR_TYPE_ANY` listener and binds it with port `0`:

   ```c
   tcp_new_ip_type_ctx(owner->lwip, IPADDR_TYPE_ANY);
   tcp_bind_ctx(owner->lwip, tcp_listener, &any, 0);
   udp_new_ip_type_ctx(owner->lwip, IPADDR_TYPE_ANY);
   udp_bind_ctx(owner->lwip, udp_listener, &any, 0);
   ```

   The owner TCP demux, however, only selects a listener when
   `lpcb->local_port == incoming_destination_port`.  Port `0` is therefore
   not a wildcard in this context.  Replacing the version comparison with an
   ANY-aware comparison fixed only the IPv4/IPv6 type boundary; it cannot make
   a port-0 listener match `42083`.  The equivalent UDP path also compares its
   local port exactly, so it has the same latent defect.

   This is a POC design defect in transparent external ingress, not an ADB,
   Android permission, WSL2 endpoint, socketpair, epoll, or packet-read issue.

## S165 correction and fresh regression (2026-08-24)

The design correction was implemented in the repository patch
[`hev-owner-context-external-ingress.patch`](patches/hev-owner-context-external-ingress.patch)
and compiled into the owner-context HEV stage.  The correction is deliberately
external-only:

1. External gateway initialization enables `accept_nonlocal` and the explicit
   `external_ingress` mode before creating listeners; ordinary owner contexts
   keep the original strict address/port behavior.
2. TCP demux treats the external gateway's port-zero listener as a wildcard;
   accepted TCP PCBs receive the actual incoming destination port.
3. UDP demux identifies the explicitly marked external UDP listener instead of
   assuming that `udp_bind(port=0)` leaves its PCB at port zero.  The incoming
   destination address/port is scoped to the synchronous callback and copied
   into the SOCKS5 UDP frame.
4. Context reset and gateway teardown clear the external mode, listener marker,
   and per-packet destination state.  The build script requires markers for the
   TCP/UDP seam and is idempotent on an already patched fixture.

The first valid post-correction device regression used the same Pixel 6a,
WSL2 endpoint `192.168.4.5:42083`, and one HTTP cycle:

```text
app-http-probe: ok bytes=40 elapsedMs=8 first=HTTP/1.0 200 OK
socks_connect_count=1
socks5 client tcp -> [192.168.4.5]:42083
GET /loop-1 HTTP/1.0
cycle 1 ok
```

VPP counters reported `parse-errors=0`, `read-errors=0`,
`shim-read-errors=0`, and `shim-write-errors=0`; cleanup completed without a
leftover VPP process.  The compact evidence is in
[`evidence/s165-hev-external-ingress/s165-http-loop-summary.txt`](evidence/s165-hev-external-ingress/s165-http-loop-summary.txt).
This closes the S164 design hotspot for the tested IPv4/TCP arm.  It does not
yet claim IPv6/UDP correctness, performance parity, or the final E2 result.

## Historical required design revision before resuming

Do not treat port `0` as a global lwIP semantic change.  Add an explicit
owner-context external-ingress/wildcard-listener mode and use it only for the
external fd gateway:

1. Enable the mode together with `accept_nonlocal` during external gateway
   initialization.
2. In the owner TCP demux path, allow the external port-zero listener to match
   any destination port only in that mode; identify the UDP gateway listener
   explicitly because UDP bind may allocate an ephemeral local port.  Keep
   ordinary owner contexts exact-port.
3. Preserve the incoming destination port/address on the newly accepted TCP
   PCB and on UDP session creation so the SOCKS connector receives the original
   destination.
4. Add per-packet/session evidence for IPv4 and IPv6 TCP/UDP, plus a negative
   strict-owner test proving that port `0` does not become a universal wildcard.
5. Move the correction into a repository HEV patch and make the build script
   require a marker for it.  Remove `s164_trace` from the canonical stage.

The design gate above is now satisfied for the tested IPv4/TCP correctness arm.
E2 remains `INCONCLUSIVE` until the matched HEV performance matrix, resource
measurements, full IPv6 TCP/UDP/DNS coverage and final audit are completed.
