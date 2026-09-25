# R1 recognition coverage and limits

This is an executable capability description for SAKAMOTO-283, not a promise of
nDPI equivalence. The public lifecycle is [R1](R1_SUPPLEMENTAL_RECOGNITION.md);
the underlying publication/window contract remains [T12](T12_PUBLISHED_PROTOCOL_FACTS.md).
All selected checks run inside its existing 20-payload-attempt/32-KiB window.
No new cross-packet state or dynamic allocation is added. Empty payloads do not
consume attempts; misses and stopped producers retain published facts.

## Fixed evidence sources

- Base **LPI**: official LibtraceTeam `97a8efecd257ec09f652374399f27b3a65db7d0a`,
  vendored `third_party/libprotoident/lib/{tcp,udp}` and `proto_common.cc`.
  LGPL-3.0-or-later notices and existing relink materials remain packaged.
- Primary supplemental reference **nDPI**: official ntop
  `4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b`, `src/lib/protocols/{dns,http,tls,quic}.c`.
  Its DNS port/header/count checks informed the mDNS selection; its DNS/TLS
  reconstruction, QUIC decryption and metadata machinery are not imported.
  This implementation uses independently written RFC wire framing. No nDPI
  source or runtime dependency is distributed by this change.
- Wire semantics: RFC1035 §4.1, RFC6762 §§5/6/18, RFC9000 §§16/17.2.2,
  RFC9369 §3.2. Direct-unicast queries/responses are included; multicast delivery
  and service discovery are not implicitly established by a unicast test.

## Delivered rows

| Fact | Input and trigger; ports/direction | Resolution and known limit | Executable positive / relevant negative |
| --- | --- | --- | --- |
| DNS 1001 `dns` | LPI TCP/UDP directional four-byte prefixes, lengths and ports; UDP either 53; TCP length-prefix heuristic; either first-observed direction | Base guess retained unless this attempt has modern QUIC or validated mDNS. nDPI's optional nonstandard DNS and TCP assembly are not added. DNS is not implied by mDNS. LPI prefix heuristics can accept incomplete DNS bodies. | `dns_budget`, `multi_result_and_reuse`, `mdns_boundaries`: ordinary DNS, non53 miss, short opaque input; actual standard DNS on Linux. |
| HTTP 1002 `http` | LPI TCP HTTP/HTTP_NonStandard prefix rules; standard and nonstandard ports; request or reply prefixes, with existing bidirectional LPI features | Exact HTTP aliases only. nDPI HTTP parser/state/URL metadata and broad fork payload fallback are excluded here. Recognition is not a complete HTTP exchange. | `tls_upgrade`, `mdns_boundaries`: GET/response,80/8088, GEX lookalike; live HTTP upgrade on Linux/Root/VPN. |
| TLS 1003 `tls` | LPI TCP TLS/SSL record-prefix heuristics, current prefixes from either/both directions;443/80 and other ports subject to competing provider guesses | HTTPS and SSL map to TLS, never implicitly HTTP. nDPI's record/ClientHello reconstruction and SNI are deferred. A one-sided record prefix with empty other direction can qualify; after HTTP both direction prefixes must change in the selected upgrade. Header recognition does not validate record body/handshake. | `tls_upgrade`, `mdns_boundaries`: HTTP→TLS union,443/8443, bad version; live TLS1.2 handshake. |
| QUIC 1004 `quic` | Existing LPI old QUIC plus current UDP Initial framing: v1 type00 / v2 type01, fixed bit,≥1200-byte datagram, CID≤20, bounded token/payload varints; any ports/direction | Highest current-attempt supplemental precedence, then one catalog mapping. Modern framing replaces a conflicting current base guess, never historical facts. Header-only, no decrypt, no authenticated-session/HTTP3/SNI implication. nDPI Initial crypto/CRYPTO assembly is outside R1. | `quic_header_failures`, `multi_result_and_reuse`, `mdns_boundaries`: v1/v2,5353 overlap, invalid fixed bit/CID/token/length/type/short datagram; live Linux full v1 handshake and phone authenticated Initial exchange. |
| SSH 1005 `ssh` | LPI TCP SSH- prefix on any port/either side; additional port22 short/binary heuristics retained | No new SSH detector or handshake claim; retained as baseline coverage, independent of TLS. | `mdns_boundaries`: SSH- on 22/2222, SSX lookalike and opaque negative. Host coverage, no new SSH device claim. |
| mDNS 1006 `mdns` | UDP, either 5353 endpoint, single current datagram; query, answer, probe/known-answer framing;≤4096 bytes, ≤64 total questions/RRs,≤16 compression jumps/name and 4096 name traversal steps | After modern QUIC, before base mapping. Standard opcode/zero RCODE, nonempty sections, complete question/RR extents, nonzero TYPE/CLASS, bounded label/expanded-name lengths. Compression targets must already be parsed name boundaries. RDATA contents stay opaque; names present only in earlier RDATA are outside this initial compression subset. No result from port alone. 512 call-local bitmap bytes, zero persistent growth. | `mdns_query`, `mdns_boundaries`: multicast-address query, direct query/reply, compressed A answer/cache-flush/goodbye, IPv4/IPv6, both ports/directions, every query truncation, bad opcode/rcode/type/class/label/RDLENGTH, self/forward/non-name pointer, non-5353/TCP/empty/excess-count/trailing bytes. Actual direct-unicast query/answer plus rules on Linux and Root/VPN recorded separately. |

Each row uses the same owner identity validation, configuration retention,
FlowEnd/reuse, deduplication and full-set availability/cache semantics. All six
IDs are included in the independent logical-reference three-plan/PRE/POST and
cold/hot/changed-fact matrix. Hand-calibrated literals, not detector outputs,
supply expected facts. These examples do not establish zero false positives.

## Assessed groups outside R1

| Group | Selection and reason |
| --- | --- |
| SMTP/SMTPS, POP/IMAP variants, FTP/FTPS/file transfer | R2/SAKAMOTO-284 owns selected corrections and useful labels; preserving raw unmapped provider names here enables it. No new label or PASS claimed. |
| SOCKS versions, HTTP proxies, VPN/WireGuard/OpenVPN and remote access | R3/SAKAMOTO-285 selects reproducible personal-endpoint features; no wholesale fork chain or nDPI taxonomy import. Existing SSH remains above. |
| STUN/TURN/RTP/RTCP and realtime/other endpoint services | R4/SAKAMOTO-286 selection; no new label/PASS in R1. |
| DHCP/v6, NTP, SSDP and wider discovery | Not selected for R1: mDNS is the initial complete new slice. A reference registry entry alone is not a coverage promise; later group selection owns tests before publication. |
| GB/T32960 | Explicitly excluded by the accepted personal-endpoint scope. |
| Brand/risk/fingerprint databases, full nDPI engine, full fork parity | Explicitly excluded; no confidence model or cross-packet fact withdrawal. |

Ordinary and nonstandard ports, IPv4/IPv6 Host facts, actual platform delivery
and handshake strength are distinct evidence dimensions. See the dated R1
acceptance report for measured platform scope; future groups have no R1 PASS.
