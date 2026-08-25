# SAKAMOTO-143 B1 short-segment ACK/owner-drive hotspot

Date: 2026-08-24
Status: CLOSED_FOR_POC; owner-context ACK fix and paired Pixel regression passed

## Outcome

The bounded queue correction for SAKAMOTO-142 preserved multiple TUN ingress
segments, but it did not close the real stream gate.  The same AppA DNS-over-
TCP cell now has two sharply separated results:

| Fixture arm | AppA result | OI3 result |
| --- | --- | --- |
| `tcp_write_mode=separate` (two-byte length prefix and body written by separate `write` calls) | `tcp_connect_failed`, no response | `tun-submit` sequences 1--6 are accepted, then `direct-send length=1`; cleanup `FAIL`, `direct=0`, `residue=0` |
| `tcp_write_mode=coalesced` (length prefix + 29-byte DNS body in one write) | `tcp_payload_sent`, `dns_response_received`, `response_valid=true`, 61 bytes | `tun-submit` sequences 1--7, `direct-send length=31`, `direct-recv length=63`; cleanup `PASS`, `buffers=14/14`, `residue=0` |

This is a reproducible short-segment progress hotspot, not an underlay,
protected-socket, broker, UID, endpoint, or queue-overwrite failure.  The
campaign must remain paused until the owner/HEV seam explicitly makes progress
after a short TCP segment while preserving the same protected flow.

Follow-up result: the owner-context ACK-only output seam was corrected and the
same two arms were rerun on fresh VPN generations.  The separate arm now
returns the complete 61-byte DNS response after the first one-byte write; the
coalesced control continues to pass.  Both end with `oi3_cleanup result=PASS`
and zero VPP buffer residue.

## Reproduction and artifacts

- Device: Pixel 6a, Android 16; device serial `28201JEGR0XPA`.
- VpnLite UID `12628`; AppA UID `12630`; full-route `vpp-oi3`; allowed package
  `com.sakamoto.snort.poc.appa`; IPv6 enabled.
- Historical destination: `1.1.1.1:53`, IPv4 TCP, source ports `46305`
  (separate) and `46306` (coalesced).
- Corrected paired regression: source ports `46309` (separate) and `46310`
  (coalesced), same destination and payload.
- DNS-over-TCP payload: 29-byte hex
  `123401000001000000000000076578616d706c6503636f6d0000010001`.
- Historical fixed plugin SHA-256:
  `f8a32f27cb661326ac2e94ccd52e79840a9624f06d6c6f4db04233640164e271`.
- Historical fixed VpnLite APK SHA-256:
  `6e0dbc40d16b0c404075b062fae596eec6bb6bbac58ce6565176d649f2c326dc`.
- Corrected HEV arm64 SHA-256:
  `88cc920e6aca9bf1b999372d40fc895077208ea545d918ac2b22471eeabffc04`.
- Corrected OI3 plugin SHA-256:
  `648b33c8d5d9429e5e0bb39de29a6c4af5d9b0655aaea0b3775457a77eedbfbf`.
- Corrected VpnLite APK SHA-256:
  `cff40c3a838def2f6417c8bb04012839aba01efa1ea497aed5ec1fae76d72419`.

The separate-arm AppA record is durable `s139-b1-runtime/v1` with
`bind_result=bound`, `tuple_attempted=true`, `tcp_write_mode=separate`,
`send_connect_outcome=tcp_connect_failed`, `return_received=false`, and
`error=Software caused connection abort`.  The coalesced-arm record has
`tcp_write_mode=coalesced`, `send_connect_outcome=tcp_payload_sent`,
`return_outcome=dns_response_received`, `return_received=true`,
`response_valid=true`, and a 61-byte `received_payload_hex`.

The corrected separate-arm record (`B1-ip4-tcp-dns-separate-ownerack-20260824`,
source port `46309`) has `send_connect_outcome=tcp_payload_sent`,
`return_outcome=dns_response_received`, `return_received=true`,
`response_valid=true`, and a 61-byte response.  The corrected coalesced arm
(`B1-ip4-tcp-dns-coalesced-ownerack-20260824`, source port `46310`) has the
same successful result.

## Native evidence

The separate arm shows the queue correction working rather than silently
overwriting the stream:

```text
oi3 tun-queue enqueue sequence=1 length=60 depth=1 tcp-flags=0x02
oi3 tun-submit result=0 sequence=1 length=60 ...
oi3 tun-queue enqueue sequence=2 length=40 depth=1 tcp-flags=0x10
oi3 tun-submit result=0 sequence=2 length=40 ...
oi3 tun-queue enqueue sequence=3 length=41 depth=1 tcp-flags=0x18
oi3 tun-submit result=0 sequence=3 length=41 ...
oi3 direct-send length=1
oi3 tun-flow timeout steps=9 output=1 direct=0
oi3_cleanup result=FAIL ... direct=0 rewritten=1 buffers=11/11 residue=0
```

The coalesced control reaches the same connector and returns the complete
DNS response:

```text
oi3 tun-submit result=0 sequence=3 length=71 ... tcp-flags=0x18
oi3 direct-send length=31
oi3 tun-output length=103 result=OK
oi3 direct-recv length=63
oi3_cleanup result=PASS ... output=2 direct=2 rewritten=2 buffers=14/14 residue=0
```

The first result proves the prior one-slot pending-packet loss is not the only
failure: every observed TUN segment is submitted successfully, yet a one-byte
application segment does not produce the next stream byte or a Direct reply.
The second result proves that the same underlay and protected connector can
carry the complete frame when the first write is large enough.

The corrected separate trace closes that gap:

```text
oi3 direct-send length=1
oi3 short-send timer-before events=1 ticks=0 active-pcb=...
oi3 tun-output length=40 result=OK
oi3 short-send timer-tick events=1 ticks=1 active-pcb=...
oi3 direct-send length=30
oi3 tun-output length=103 result=OK
oi3 direct-recv length=63
oi3_cleanup result=PASS ... output=4 direct=4 rewritten=4 buffers=15/15 residue=0
```

The coalesced control on the corrected artifact shows the same ACK-only
output and complete response with `output=3`, `direct=3`, `rewritten=3`, and
`buffers=13/13 residue=0`.

## Working diagnosis

The pinned HEV TCP splice path writes the available pbuf chain to the
protected fd, calls `tcp_recved`, and relies on the owner task/timer machinery
to emit the resulting client ACK and continue the stream.  The exact defect
was in the owner-context lwIP output seam: `tcp_input_ctx()` correctly set
`TF_ACK_DELAY`, and `lwip_owner_context_tcp_tmr()` promoted it to
`TF_ACK_NOW`, but `tcp_output_ctx()` returned immediately when `pcb->unsent`
was empty.  Unlike the normal global `tcp_output()` path, it had no ACK-only
packet construction.  Therefore the timer tick was real but could not produce
the peer ACK.

The correction adds `tcp_send_empty_ack_ctx()` using the owner-local pbuf pool,
owner netif and owner IP output functions, and makes `tcp_output_ctx()` invoke
it for `TF_ACK_NOW`.  ACK flags are cleared only after a successful output and
remain retryable on allocation/output failure.  No unprotected retry, second
datapath, fixture packing, or SOCKS fallback was introduced.

## Required correction before resume

1. Keep the flow alive after a short `direct-send`; explicitly drive the
   owner/lwIP ACK/timer path until the Android TCP peer can send the next
   sequence range. **Met:** the corrected separate trace contains a 40-byte
   ACK-only TUN output followed by the remaining 30-byte send.
2. Preserve the queue's ordered multi-segment behavior and the original
   protected destination/underlay identity. **Met:** queue sequences remain
   ordered and broker/protect/underlay evidence is unchanged.
3. Rebuild and rerun both arms. **Met:** separate and coalesced arms both
   produce the full DNS response, `direct-recv`, rewritten TUN return, and
   exact allocated/freed buffer settlement with residue zero.

## Stop decision

The hotspot is closed for this Pixel/owner-context artifact.  The paired
separate/coalesced regression passed, so the campaign may resume with the
remaining B1 IPv6/DNS and B2 failure matrix.  The fix does not by itself claim
whole-device IPv6, lifecycle, overload, performance, or third-party OEM
coverage; those POCs remain open and must still be executed.
