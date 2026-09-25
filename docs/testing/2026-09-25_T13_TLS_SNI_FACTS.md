# T13 TLS ClientHello SNI acceptance

SAKAMOTO-264 implements the [T13 contract](../interfaces/T13_TLS_SNI_FACTS.md)
under ADR-0009, using only the VPP-native C product mainline. The source closure
for the accepted platform runs is
`c3102122776bc11f496b07c304674fb89667f346f529e9f4ab924c4c2e765b06`.
Local evidence is under `build-output/t13-20260925/`; build/run identities are
bound by the independent verifier, not inferred from a screenshot or Git HEAD.

## Acceptance mapping

| Original requirement | Implemented behavior and evidence |
| --- | --- |
| Valid name, confirmed absence, unavailable | Shared zero-copy Hello reader over the TCP-owned cache; owner tests use literal expected names/absence and malformed/truncated vectors. Live TLS stacks independently accept named/no-name handshakes. |
| Whole-rule TLS/QUIC prerequisite | Opcode 16 + operand 1, dependency union and whole-rule applicability before Boolean evaluation. Independent reference covers AND/OR/NOT, unavailable inputs, DTLS and supplemental protocol sets. |
| One bounded TCP input cache | Two independent 4096-byte directional ranges in one preallocated Flow cache; record spans borrow it. SYN establishes the expected first sequence. Gap/overlap/retransmission stops unavailable; T14 owns reconstruction expansion. |
| Original packets complete promptly; same-packet facts | Producer runs before the protected post-flow lookup. Independent trace joins require SNI→LPI→Flow→winner→release and actual native completion. Every selected packet has a terminal timestamp before the five-second parser deadline. |
| Invalid, truncated, timeout and budget behavior | Host checks all split/truncation offsets, malformed vectors, duplicate extensions, invalid names, packet/byte limits and unsupported sequence states. Linux and Root/VPN expose unavailable malformed/truncated results despite published heuristic TLS. |
| Query errors/resources; release without losing CT/facts | Identity-fenced typed API returns name/result/stop/work/cache counters through C/VAPI/Rust and Android's actual runtime session. Wrong incarnations reject. Timeout uses the existing owner heap, clears bytes without new packets or Flow retirement. |
| Existing plan/cache integration | 52,821 independent complete-winner comparisons across direct/factorized/residual plans, PRE/POST, cold/hot and changed facts/availability. Result comparison includes winner, rank, declared/actual action, mode and attribution. |
| Supplemental recognition combinations | Existing DNS/HTTP/SSH, mail/FTPS, tunnel/proxy/RDP and realtime/DTLS owner transcripts now also test unavailable SNI consumers. TLS/QUIC heuristic labels never fabricate absence; DTLS cannot supply the whole-rule prerequisite. This broad combination matrix is Host coverage. |
| Actual platforms and reproducible evidence | Linux `linux-build-d`/`linux-sni-b`; Android `pixel-build-c`/`pixel-sni-b`. Actual app sockets, saved/applied source, full packet bytes, typed queries, native drops, endpoint handshakes and recovered delivery are joined independently. |

## Platform results and limits

| Platform/profile | Selected packets | Actual policy drops | Cache hits / misses | Maximum admit→terminal |
| --- | ---: | ---: | ---: | ---: |
| Linux Root NFQUEUE | 62 | 8 | 84 / 40 | 19.356 ms |
| Android Root | 162 | 14 | 280 / 44 | 6.043 ms |
| Android controlled VPN | 167 | 12 | 294 / 40 | 8.781 ms |

Each profile includes a real TLS 1.2 connection with `example.test`, a real
TLS 1.2 connection with no hostname, a complete malformed Hello and a truncated
Hello. Observe→enforce→observe publication preserves Flow identity and SNI;
actual application timeouts are followed by endpoint receive/echo recovery.
Linux endpoint TLS is Python/OpenSSL; Android is the ordinary platform
SSLSocket with an ephemeral pinned certificate. Raw invalid-prefix endpoints
acknowledge receipt, proving those original bytes reached the endpoint while
SNI remained unavailable. NF_ACCEPT alone is never treated as delivery proof.

Truncated ready/expired queries retain exactly the same Flow packet count and
incarnation: the timer stops parsing and frees logical byte ranges without a
later packet. Live validation is representative IPv4/TLS1.2 coverage, not every
TLS version, TLS1.3 handshake authentication, arbitrary STARTTLS, ECH inner-name
inspection, tunnel-inner parsing, QUIC assembly, DTLS SNI or T14 reassembly.
Domain-name lists/exact/descendant matching remain T18. No performance gate or
ordinary-user VPN release claim is added; controlled VPN remains
`protectionRunning=false`. Timing above includes diagnostics and concurrent
build load and is not a benchmark comparison.

## Resources and checks

The single fixed cache reserves 8192 byte capacity plus 16 metadata bytes per
Flow. SNI result/metadata is 288 bytes; FlowEntry is 8888 bytes. Each 1024-entry
owner reserves 9,122,120 bytes, so both owners reserve 18,244,240 bytes. Active
logical byte ranges drop to zero on completion/error/timeout. Reserved pool
capacity remains until runtime teardown; there is no separate parser quota or
packet-path heap allocation. The 128-entry worker decision cache remains
23,584 bytes. Actual x86-64 and Android ARM64 query rows agree, with zero
capacity misses in these runs. x86-64 -O2 parser stack frames: Hello reader 944,
observe 48, vector helper 16, byte reader 8 bytes; these are not ARM64 stack or
process-RSS claims.

Complete applicable Host suite: 47/47. Rust: 16/16. Focused owner parser tests
pass ASan/UBSan/LSan. Existing VAPI transport harness now exercises valid absence,
wrong generation/incarnation, null/missing replies, invalid name length,
pre-submit failure and stale Flow errors; ambiguous/invalid replies fence the
session and return no fabricated result. Thirty-one critical witness mutations are rejected independently for each platform
run. Mutation tests bind
API identity/name/counters, full cached winner, actual verdict, completion time,
endpoint handshake/name/absence and build provenance.

## Retained failures and cleanup

Initial compile failures were the new API handler macro placement and the
source manifest's old generated API CRC. Both target builds were rerun with
`product_core.api/1.0.0@aabf0772`. Host harness declarations needed the new API
messages; their complete rerun passes. Initial sandbox Rust socket tests failed
on denied Unix sockets; the normal-host rerun passes. A focused red test found
that a first payload after SYN could skip sequence bytes; the producer now
seeds sequence spaces from SYN and the regression passes.

Android `pixel-sni-a` is retained and is not acceptance: empty SSLParameters
server-name lists did not suppress the hostname supplied to createSocket on the
platform TLS provider. Product correctly returned that sent name. The corrected
probe creates the no-name TLS session using the endpoint IP; fresh fixtures,
APK and a full Root/VPN rerun prove actual absence. Earlier Linux evidence is
superseded by the source-bound SYN-fix run. A first negative-test edit targeted
the host command's connection-generation preamble rather than its SNI identity;
the corrected mutation targets the actual SNI field and is rejected.

Runtime, endpoint and probe processes were cleaned up. The final phone state is
stopped VPN, generation 1564, saved/active revision 349, empty errorCode,
`mayBeActive=false` and `protectionRunning=false`. Device operations use
only `./dev/adb` through the established Linux-client route. All 33 entering
user design/research files remain byte-identical and outside this ticket's
commit. Reviews and the complete evidence index accompany the final closure.

## Independent reviews

Standards: no documented-standard breaches; two nonblocking heuristics (shared
ABI enum constants and repeated test fixture setup). The existing explicit
wire-value validation remains deliberately independent of private producer
enums, and scenario-local fixtures keep the tested packet inputs visible;
`sample()` already shares the repeated split/name matrix. Spec: no concrete
missing requirement, scope creep or incorrect implementation in the agreed T13
scope. Both reports are retained separately in the local index. Neither review
claims to have independently rerun device traffic.
