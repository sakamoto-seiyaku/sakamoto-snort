# R3 proxy, VPN and remote-access recognition contract

The existing owner-identify/resolver is the only publication path. Tests use
already agreed owner lifecycle and compiler/matcher seams plus real management
API and endpoint outcomes. No new test seam is introduced.

Selected stable facts: 1011 openvpn, 1012 wireguard, 1013 socks4, 1014 socks5,
1015 rdp. SOCKS versions describe their wire negotiation; no duplicate generic
SOCKS label. RDP TCP/UDP share one fact.

All detectors borrow the current payload synchronously and use the existing
20-attempt / 32-KiB window. No packet holding, TCP byte cache, heap allocation,
second flow table, inner tunnel parsing or historical fact withdrawal. Partial
messages do not fabricate a result. Policy updates preserve state; Flow reuse
clears it. Provider output is resolved before mapping; historical facts accumulate.

Primary reference: ntop/nDPI 4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b,
protocols/openvpn.c, wireguard.c, socks45.c and rdp.c (LGPL-3.0-or-later).
Implementation is independently written from protocol framing and selected state
ideas; no nDPI source, module or flow object is imported. Fork evidence informs
nonstandard TCP ports; broad port-only or short-magic rules are excluded.

| Fact | Selected forms and limits |
| --- | --- |
| OpenVPN | TCP complete single length-prefixed record or UDP datagram on any port. Initial key-id-zero client/server V1/V2 resets; opposite resets and matching remote session ID (no-HMAC framing), or two consistent control records per direction. At most 1199 bytes per record; bounded session IDs/counters only. No tls-crypt/obfuscation claim or static-key data-only identification. |
| WireGuard | UDP any port; exact 148-byte initiation then opposite 92-byte response or 64-byte cookie with matching index. Also three transport messages (at least 32 bytes), both directions then a repeated same-direction receiver index. Reserved bytes must be zero. No retransmission-only shortcut, brand variants or cryptographic verification. |
| SOCKS4 | TCP any port; complete CONNECT/BIND request with bounded NUL-terminated user (and SOCKS4a hostname where present), then opposite exact 8-byte status 90–93 reply. |
| SOCKS5 | TCP any port; complete method list (1–32 offers), then opposite two-byte selection of an offered method or rejection 255. Recognition is negotiation evidence, not CONNECT success/authentication. No empty response shortcut or UDP association inference. |
| RDP | TCP any port: complete TPKT/COTP connection request with 8-byte RDP negotiation then opposite complete confirm response/failure. UDP port 3389: initial SYN plus opposite SYN/ACK matching full source-ack sequence and sensible MTUs. No generic TPKT, midflow-only UDP or tunneled TLS inference. |

Selected supplemental matches precede this attempt's base alias; existing QUIC,
mDNS and mail corrections retain their own supported contracts. No whole-engine
replacement or all-nDPI coverage claim.

## Executable coverage and resource closure

| Detector row | Positive cases | Relevant exclusions / regressions |
| --- | --- | --- |
| OpenVPN reset association | V1/V2 key-id-zero reset pair, opposite direction and matching full 8-byte remote session; TCP/UDP, 1194 and 1195, IPv4/IPv6 | Nonzero key ID/session mismatch, zero session, reset packet ID not 0, excessive/truncated ACK list, wrong direction, TCP length mismatch, trailing/truncated record; one-way retransmission never confirms. |
| OpenVPN session continuity | Valid no-HMAC reset from each peer then second same-session control from each direction | Changed session cancels the pair; no static-key/data-only, HMAC/tls-auth/tls-crypt, obfuscation or split/coalesced TCP-record claim. ACK array at most 8, records 14–1199 bytes. |
| WireGuard initiation/response | Exact 148/92-byte pair and receiver-index equality; both observed orientations and any UDP port | Each shortened initiation, reserved bytes, wrong type/length/index, same-direction response and TCP input; repeated initiation alone remains unavailable. |
| WireGuard cookie/transport | Exact 64-byte opposite cookie with matching initiation index; or two directions and third transport record with matching direction-specific index | No cookie decryption, nonstandard 204/100-byte brand forms, port-only inference or full-handshake claim from the detector. One direction alone / changed index do not confirm. |
| SOCKS4/4a | CONNECT/BIND, bounded complete user/hostname strings, opposite 90–93 reply, 1080/1088 and either observed orientation | Invalid version/command/zero destination port, missing NUL/4a hostname, short request/reply, wrong direction and UDP. At most 512 request bytes. |
| SOCKS5 | Complete 1–32-offer list, any offered method 0–254 or server rejection 255; private/common mixed offers; all method bit boundaries | Selected method not offered, invalid 255 offer, wrong count/length/direction, empty reply and UDP. Exact 256-bit membership lives in existing Flow state; no authentication or UDP-associate inference. |
| RDP TCP | Complete TPKT/COTP request, optional printable Cookie, exact 8-byte negotiation, opposite response or failure; 3389 and 3390, IPv4/IPv6 | Correlation-info flag 0x08 and its extended PDU are outside this subset; missing promised correlation bytes never confirm. Selected request flags 0–3; security bits RDP/TLS/Hybrid/HybridEx only. Inconsistent TPKT/COTP/negotiation lengths, generic X.224, invalid selected value, opposite HTTP, truncated records and same-direction reply do not confirm. |
| RDP UDP | Exact 16-byte v1 SYN/SYN-ACK on 3389, full 4-byte source-ack match, MTUs 256–1600 | Wrong final sequence byte (not a three-byte prefix match), flags, port, MTUs, length or direction. Extended v2/mid-flow heuristics excluded. One shared RDP label avoids transport double counting. |

Host names `proxy_boundaries`, `wireguard_boundaries`, `openvpn_boundaries`,
`rdp_boundaries` and `tunnel_lifecycle` exercise these owner-visible behaviors.
Every new fact covers identity errors, policy publication, attempt/byte stop and
same-slot reuse. `proxy_mail_union` preserves SOCKS5→FTP-control→TLS/FTPS facts
on one flow. The independent reference includes each ID and combined old/new
sets across all three plans, PRE/POST, cold/hot and changed availability/sets.

The production resolver order is RDP → OpenVPN → UDP WireGuard/QUIC/mDNS or TCP
SOCKS/mail → existing base guess (with the prior FTP-data fallback). New selected
shapes have disjoint framing; current corrections precede mapping and one union.
The fixed fork's first-packet-only SOCKS guess and seven-byte generic-X.224 RDP
heuristic are deliberately not adopted; their useful version/port distinctions
are retained with stronger bounded message pairs. No confidence model is added.

Actual ARM64 layout is 128 bytes for recognition and 360 for FlowEntry: +72 bytes
per entry versus R2. The protocol set remains one 8-byte bitset; the 128-entry
worker policy cache remains 23584 bytes. Existing `flow.runtime` reports 389448
allocated bytes for a 1024-entry owner, including the new state, and its actual
high-water mark. One packet still invokes LPI once and bounded current-payload
supplemental checks; stopped producers skip detector work. No new allocation,
second table, stored original packet or TCP reassembly buffer is introduced.

Primary reference links:
[nDPI OpenVPN](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/src/lib/protocols/openvpn.c),
[WireGuard](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/src/lib/protocols/wireguard.c),
[SOCKS](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/src/lib/protocols/socks45.c),
[RDP](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/src/lib/protocols/rdp.c).
Their source/license hashes are in local `reference-source.json`. LGPL code is
not copied or linked; existing libprotoident licensing/relink materials remain.
Wire framing additionally follows [WireGuard's protocol](https://www.wireguard.com/protocol/),
RFC1928 SOCKS5, and Microsoft's
[RDP negotiation request](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/902b090b-9cb3-4efc-92bf-ee13373371e3)
and [connection confirm](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/84909189-251f-4bd0-a410-35bb4c38eefa).
