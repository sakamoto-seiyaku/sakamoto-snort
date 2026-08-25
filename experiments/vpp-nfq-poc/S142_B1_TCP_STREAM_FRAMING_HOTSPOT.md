# SAKAMOTO-142 B1 TCP stream-framing hotspot

Date: 2026-08-24
Status: CLOSED_FOR_POC; short-segment ACK seam fixed in S143 and paired regression passed

## Outcome

The first full-route public IPv4 TCP controls are not a stable blocker: the
HTTP positive cell passed on two reruns after one transient timeout.  The
separate DNS-over-TCP cell is different and reproducible.  A valid App-UID
TCP connection to `1.1.1.1:53` completes the handshake, but the OI3 path emits
only the first byte of the DNS length prefix and settles the flow before the
remaining stream bytes reach `wlan0`.  The resolver therefore waits for a
complete two-byte length and the App gets an abort/timeout.

This is a real stream/segmentation design boundary, not the S140 LAN
permission issue or the S141 underlay-selection issue.  Per the campaign stop
rule, no IPv6, B2, C, D, or E POC is started until this seam is corrected and
regressed.

## Reproduction

- Device: Pixel 6a, Android 16; VpnLite UID `12628`; Traffic Adapter AppA UID
  `12630`.
- Full-route session: `vpp-oi3`, allowed package
  `com.sakamoto.snort.poc.appa`, IPv4/IPv6 default routes.
- Selected connector underlay: Wi-Fi handle `432902426637`, with
  `NET_CAPABILITY_NOT_VPN=true`, `TRANSPORT_VPN=false`; `bindSocket=true` and
  `protect=true`.
- Traffic cell: AppA source `10.111.0.2:46304` to `1.1.1.1:53`, TCP DNS query
  `123401000001000000000000076578616d706c6503636f6d0000010001` (29 bytes).
- Durable App record (`s139-b1-runtime/v1`): `bind_result=bound`,
  `tuple_attempted=true`, `send_connect_outcome=tcp_connect_failed`,
  `error=Software caused connection abort`.
- A prior identical cell reached `tcp_connect_succeeded` but then
  `dns_response_timeout`; both runs retained no DNS response.

## Packet and native evidence

The bounded rooted capture on Pixel `wlan0` recorded:

```text
192.168.4.151:48704 -> 1.1.1.1:53  SYN
1.1.1.1:53 -> 192.168.4.151:48704  SYN/ACK
192.168.4.151:48704 -> 1.1.1.1:53  ACK
192.168.4.151:48704 -> 1.1.1.1:53  PSH  seq 1:2  length 1
1.1.1.1:53 -> 192.168.4.151:48704  ACK  ack 2
... client FIN; server FIN; no DNS response payload ...
```

The corresponding OI3 log was:

```text
oi3 broker-request ... family=4 kind=1 endpoint-port=53
oi3 broker-completion result=SUCCESS
oi3 direct-send length=1
oi3 connector-wake cause=2 generation=1
oi3_cleanup result=FAIL ... direct=0 rewritten=1 buffers=11/11 residue=0
  error=tun-flow-output-not-a-direct-return
```

In the preceding run the native log also showed a second
`direct-send length=30`, but no second physical packet and no `direct-recv`.
This matches the App implementation, which writes the two-byte DNS-TCP
length prefix and the DNS body in separate `OutputStream.write` calls.  The
first write is treated as the terminal OI3 output; subsequent stream data is
not carried through the same protected connector flow.

## Controls that exclude the usual false causes

- Shell TCP connect controls to `1.1.1.1:53`, `8.8.8.8:53`, `9.9.9.9:53`, and
  the LAN resolver port all succeeded.
- Public IPv4 UDP DNS through the same full-route OI3 artifact passed with a
  valid 29-byte query, 61-byte response, and cleanup `PASS` (`buffers=4/4`,
  `residue=0`).
- Public IPv4 HTTP through the same artifact completed the SYN/ACK, request,
  127-byte response, `direct-recv`, and cleanup `PASS` on two reruns.  One
  earlier HTTP timeout was therefore treated as transient, not this hotspot.
- The connector did not select the UID-scoped VPN Network; S141's underlay
  defect is not present in this reproduction.

## Follow-up after the bounded queue correction

The owner-local pending queue was changed from one overwrite-prone packet slot
to an ordered bounded queue (capacity 16), then rebuilt and installed on the
same Pixel.  The queue now accepts and submits all observed separate-arm TUN
segments (`tun-submit` sequences 1--6), so the original silent pending-slot
overwrite is not the remaining explanation.

The paired regression exposed a deeper hotspot: the separate-write arm still
stopped after `direct-send length=1`, while the coalesced arm succeeded with
`direct-send length=31`, a 61-byte DNS response, and cleanup `PASS`.  S143 then
identified the exact owner-context defect: `tcp_output_ctx()` had no
ACK-only-output path when the delayed-ACK PCB had no `unsent` segment.  The
owner-local ACK-only fix produced the missing 40-byte TUN ACK, carried the
remaining 30-byte write, and made both separate and coalesced arms pass with
zero residue.  The detailed closure evidence is in
[`S143_B1_SHORT_SEGMENT_ACK_HOTSPOT.md`](S143_B1_SHORT_SEGMENT_ACK_HOTSPOT.md).
S142 is retained as the historical stream-framing finding; it no longer blocks
the campaign, while the broader B1 matrix remains open.

## Design correction required before continuation

1. Keep a TCP flow alive across multiple TUN ingress segments and multiple
   application writes; a first short write must not trigger terminal cleanup
   or leave the owner parked without an ACK/timer re-entry.  S143 tracks this
   short-segment progress condition.
2. Add a deterministic stream fixture with separate writes (length high byte,
   length low byte, body) and a coalesced-write control.  Both must produce a
   complete DNS-over-TCP request at the external endpoint.
3. Require capture of the full two-byte length plus body, App DNS response,
   OI3 `direct-recv`, rewritten TUN return, `buffers allocated/freed`, and
   `residue=0`.  Packing the fixture into one write alone is not sufficient to
   claim stream correctness.
4. Preserve the existing protected-socket and non-VPN-underlay gates; do not
   add an unprotected or SOCKS fallback.

## Stop decision

This hotspot is closed for the registered Pixel artifact.  Resume the campaign
with the remaining B1 IPv6/DNS and B2 failure cells; do not treat this paired
regression as proof of the broader whole-device matrix.
