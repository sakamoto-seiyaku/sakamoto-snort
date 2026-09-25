# R4 bounded realtime recognition

The R1 owner-local resolver remains the only publication path: libprotoident
current guess → selected supplemental correction → stable catalog mapping →
deduplicated historical union. The existing owner lifecycle, management API /
save / apply / query and actual packet-result boundaries are the agreed test seams.
No new production test interface is added.

Catalog IDs 1016 STUN, 1017 RTP, 1018 RTCP, 1019 SIP and 1020 DTLS distinguish
wire protocols. A DTLS label never adds TLS, SNI or confirmed-no-SNI and never
widens the whole-rule TLS/QUIC prerequisite. Earlier published facts persist.

Each payload is synchronously borrowed. The existing 20-attempt / 32-KiB window
bounds all checks, and Flow generation/incarnation bounds retained state. Policy
publication does not reset attempts. Flow release/reuse clears recognition.
There is no packet holding, extra TCP byte cache, heap allocation, media decoding,
call/session engine, transport ownership or second Flow table.

## Selected detection forms

| Fact | Envelope and acceptance | State / limits |
| --- | --- | --- |
| STUN | Modern RFC8489 cookie, top bits zero, Binding / Allocate / Refresh / Send / Data / CreatePermission / ChannelBind / Connect / ConnectionBind methods; exact message and padded-attribute lengths. UDP datagram or one complete TCP message, optionally RFC4571 length prefix; any port / observed direction. | Single message; no retained detector state. No classic-STUN, vendor framing, TURN-channel payload inference, authentication or connection success claim. |
| RTP | RFC3550 version2, selected PT 0–34 or 96–127, complete CSRC / extension lengths, nonempty body, valid clear padding. Three forward-progressing packets with the same per-direction SSRC; sequence delta 1–16 with modulo wrap. UDP or one exact RFC4571 TCP frame; any port. | SSRC, sequence and saturating count per direction. Duplicates / old reordered packets do not advance; changed SSRC / forward gap restarts that direction. No codec validation or SRTP encrypted-padding support. |
| RTCP | Selected RFC3550/RFC5506 reduced-size sender or receiver report, exact count-dependent and record lengths, version2, no padding. Four reports with the same per-direction sender SSRC. UDP or one exact RFC4571 TCP frame; any port. | SSRC and saturating count per direction. Reports need not change because empty periodic receiver reports may be identical. Compound SDES / feedback and arbitrary RTCP types are excluded. |
| SIP | Selected common methods with sip:/sips:/tel: URI and exact SIP/2.0 suffix, or SIP/2.0 response status100–699; complete printable CRLF start line within512 bytes and payload at least30 bytes. TCP or UDP, any port / direction. | Single-payload start-line heuristic, no transaction-header/body/authentication validation or TCP line reassembly. Excludes upstream five-byte hello and TURN-prefix shortcuts. |
| DTLS | RFC6347 classic version0xfeff/0xfefd UDP record headers, exact complete records, types20–23. Epoch0 checks CCS/alert shapes and handshake fragment bounds; epoch>0 admits opaque encrypted records. | Up to 8 records/datagram, no retained bytes or reassembly. No DTLS1.3 unified-header/CID, TCP DTLS, handshake/authentication/SNI promise. |

The main reference is nDPI commit
`4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b`, `stun.c`, `rtp.c`, `sip.c`,
and DTLS sections of `tls.c`. It supplies framing/sequence ideas, not imported
source or a linked engine. Upstream branches differ in evidence strength: SIP
hello and broad prefix matches, RTCP type ranges and DTLS encrypted envelopes
are heuristics; no blanket strong-validation claim is made. Implementation is
independently written against protocol framing. Existing LPI licensing stays in
place; fixed reference hashes and notices are retained locally.

Fork nonstandard-port and short-visible-message ideas are selected only within
these rows. Weak two-byte RTP, incomplete SIP version comparisons, invalid
boundary checks and port-only publication are not compatibility obligations.
This is scoped heuristic recognition, not a zero-false-positive guarantee.

## Executable matrix and resources

Tests in tests/host/product_flow_lpi_test.c use independent literal fixtures
through product_flow_entry_identify, never private detector calls:

| Tests | Coverage |
| --- | --- |
| realtime_stun / realtime_boundaries | Modern request/response/indication, padded attributes, UDP/TCP/RFC4571, IPv4/IPv6, both directions and standard/nonstandard/DNS-conflicting ports; truncations and cookie/type/length/attribute errors. |
| realtime_rtp / realtime_boundaries | Three forward sequences including wrap, both directions/families, TCP prefix, CSRC/extension/clear padding; duplicates, reordering, gaps, changed SSRC, mixed directions, short/lookalike headers and port conflicts. |
| realtime_rtcp / realtime_additional_shapes | Four reduced-size SR/RR reports, UDP/framed TCP, both directions/families; version/count/type/length/padding errors and DNS/mDNS/SIP port conflicts. |
| realtime_sip / realtime_additional_shapes | Common methods, selected URI schemes, requests/responses and TCP/UDP; altered URI/version/line/control bytes, invalid status and five-byte hello exclusions. |
| realtime_dtls / realtime_additional_shapes | Opaque epoch-one record, epoch-zero fragment bounds, CCS/alert, versions 1.0/1.2 and up to 8 records; truncation, version/type/epoch/fragment/CCS and record 9 exclusions. |
| realtime_lifecycle | Every fact: stale generation/incarnation/tuple, policy publication without reset, packet/byte stop before recognition, historical retention after stop, Flow end and same-slot reuse. |
| realtime_multiplex / realtime_winners | Interleaved historical union; literal full winners across three plans, PRE/POST, cold/hot/changed set and availability, enforce/observe and once-per-packet IP-byte totals. |
| product_static_reference_test.py | Every catalog fact and combined old/new sets, including losing/negated predicates, across all three plans and independent complete logical results. |

128 reproducible random short payloads supplement named negative examples.
RTP/RTCP observations may be interleaved with other protocols. STUN envelope
validation does not authenticate attributes or validate every method/class
transaction combination. A crafted valid-looking sequence can satisfy these
heuristics; no corpus-wide accuracy rate is claimed.

Actual ARM64/Host layout: recognition 160 bytes, FlowEntry 392 (+32 each versus
R3), protocol set 8 and worker cache 23584. RTP retains 14 field bytes, RTCP 10;
alignment accounts for the rest. STUN/SIP/DTLS retain no additional state.
A 1024-entry owner allocates 422216 bytes, reflected in existing resource queries.
No new per-packet allocation exists. See [R4 acceptance](../testing/2026-09-25_R4_REALTIME_RECOGNITION.md).

Framing references: [STUN RFC8489](https://www.rfc-editor.org/rfc/rfc8489),
[RTP/RTCP RFC3550](https://www.rfc-editor.org/rfc/rfc3550),
[TCP framing RFC4571](https://www.rfc-editor.org/rfc/rfc4571),
[reduced-size RTCP RFC5506](https://www.rfc-editor.org/rfc/rfc5506),
[SIP RFC3261](https://www.rfc-editor.org/rfc/rfc3261), and
[DTLS1.2 RFC6347](https://www.rfc-editor.org/rfc/rfc6347).
