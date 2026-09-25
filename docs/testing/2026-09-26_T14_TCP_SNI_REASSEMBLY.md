# T14 bounded TCP reconstruction for SNI

SAKAMOTO-265 extends the [T14 owner/cache contract](../interfaces/T14_TCP_SNI_REASSEMBLY.md)
under ADR-0009. The accepted Product source closure is
`bf11ee0b75210a2ba0867d3bccffa7789fd016d5050c8fc0b81ea08bfdf57457`.
Evidence and exact reproduction inputs are indexed under
`build-output/t14-20260925/`. No removed C++ or POC implementation was used.

## Original acceptance mapping

| Requirement | Implementation and verification |
| --- | --- |
| One cache, independent directional sequence spaces | The existing two 4096-byte Flow ranges gain fixed, sorted range metadata. SYN anchors ISN+1; unsigned window offsets handle wrap. Without SYN the first payload anchors the attempt. Owner transcripts cover both directions, wrap and independent offsets. |
| Cross-segment/record, reorder and retransmission | Adjacent/equal overlapping ranges merge; identical bytes are credited once and unchanged prefixes do not reparse. Conflicting overlap stops unavailable. Host covers 24 orderings with duplicates, partial overlaps, all previous record/split boundaries and reordered records. Actual Linux/Root send controlled gaps, duplicates and wrapped sequence ranges through the Product graph to kernel endpoints. |
| Bound bytes, span, metadata, work and lifetime | Each direction has 4096 bytes/span and 16 ranges. Twenty payload attempts, 131072 charged work units, bounded TLS record/extension loops and the existing five-second owner deadline limit effort. No separate parser quota or packet-path allocation. |
| Failure releases parsing storage, preserves facts/CT | Terminal outcomes clear both logical caches. API queries and owner tests retain Flow identity, packet activity, CT deadline and published facts. Timeout runs with no new packet. Completing valid TLS after LPI has stopped still publishes TLS independently. |
| No parsing path around pre-flow DROP; original packets progress | Host rejects the missing tail at the pre-flow owner boundary. Android ordinary ACK DROP rules produce 5 Root and 2 VPN pre-flow drops with no Flow/SNI producer entry. Trace joins check one immutable snapshot, complete winner and cache result, one native completion/free, and bounded admit-to-terminal time. There is no automatic allow window. |
| API facts, full winners, reclamation and peaks | The independent verifier uses a dictionary of wire byte positions and literal Hello expectations, plus the existing independent ordered-rule reference. It joins saved/applied source, API identity/counters/name, whole winner/rank/mode/action/attribution, cache guards, native outcomes and actual endpoint receipts. Wire retransmissions remain real packets; reconstruction adds no synthetic business hit or duplicate logical byte credit. |
| Real bounded experiment and initial budgets | Device observations include 4090 retained bytes, 16 sparse ranges, the 4096-byte successful boundary, span/metadata/packet/byte exhaustion, timeout and 48 simultaneous attempts. Fixed reservation and process high-water RSS are recorded below. These are engineering initial values and representative functional evidence, not universal optima or performance/release gates. |
| Coverage and honest limitations | Linux and Android Root exercise deliberate raw TCP sequence patterns against actual kernel endpoints; VPN uses ordinary app sockets and real kernel retransmission caused by an ordinary reverse-packet DROP. Both Android profiles also complete an actual TLS1.2 handshake and observe/enforce/recover delivery. Broader sequence/record/error combinations are Host evidence. |

## Actual platform results

| Platform/profile | Selected packets | Actual drops | Pre-flow drops | Max admit-to-terminal |
| --- | ---: | ---: | ---: | ---: |
| Linux Root NFQUEUE | 137 | 0 | 0 | 4.529 ms |
| Android Root | 807 | 12 | 5 | 36.166 ms |
| Android controlled VPN | 812 | 8 | 2 | 111.780 ms |

Linux uses `linux-build-a` / `linux-sni-b`. Android uses `pixel-build-a`;
Root is the independently verified, fully stopped Root lifetime within
`pixel-sni-a`, and VPN is `pixel-sni-b`. The first Android run's later VPN failure
is retained and explicitly excluded from the Root-only verification; that run
as a whole is not a PASS. Only the unfinished VPN profile was repeated.

The deliberate wire sender is an external test endpoint, not Product code. It
uses a real SYN/SYNACK/ACK exchange and actual IP/TCP packets; an independent
kernel socket receives each complete literal ClientHello and returns a receipt.
Those cases prove TCP delivery and syntactically valid Hello reconstruction,
not authenticated TLS sessions. Separate Android SSLSocket/OpenSSL exchanges
prove actual TLS1.2 handshakes, named SNI, policy blocking and recovered echo.
NF_ACCEPT, TUN completion or screenshots alone are never delivery proof.

Actual platform coverage is representative IPv4. Linux/Root cover reordered
segments, equal retransmission, a wrapped 4096-byte Hello, 16-range metadata
pressure and byte/span/packet exhaustion. Android ordinary socket cases cover
split named Hello, actual duplicate payloads, oversized Hello, timeout, 48
concurrent no-name Hellos and real TLS1.2 named traffic. Conflict-overlap,
both-direction range combinations and all record boundaries are Host coverage.
First-payload anchoring without an observed SYN does not infer missing earlier
stream bytes. General STARTTLS, tunnel-inner/ECH names, DTLS SNI, QUIC assembly
and domain lists remain outside this slice (QUIC T15; domain consumers T18).

## Resource experiment and selected values

The cache reserves 8340 bytes per Flow: the existing 8192 directional byte
capacity plus 148 metadata/alignment bytes. SNI small state remains 288 bytes.
FlowEntry is 9016 bytes; each 1024-entry owner reserves 9,253,192 bytes, or
18,506,384 bytes for two owners. The increase over T13 is 262,144 bytes across
both pools. The policy cache remains 23,584 bytes per owner. Reservation lasts
until runtime teardown; logical bytes/ranges clear immediately on terminal
parsing outcomes. This is not another concurrent-parser admission pool.

On both Android profiles, a single snapshot proves 48 simultaneous running
attempts retaining 20 bytes each (960 logical bytes), exceeding the withdrawn
32-parser quota. Linux and Android Root observe 4090 current bytes/span before
the final six bytes complete a valid 4096-byte Hello. Sixteen disjoint one-byte
ranges are visible before the seventeenth stops parsing; a byte at offset 4096
also stops the attempt. Duplicate packets retain one logical byte in the
packet-budget experiment and stop at attempt 20. A 4097-byte declared Hello
stops unavailable while the complete original stream still reaches its peer.

The 4096-byte capacity retains T13's initial allocation and accepts the tested
small and padded Hellos; the actual Android TLS1.2 ClientHello was 159 bytes
on both profiles. Sixteen ranges add a small fixed metadata cost while
admitting the tested reorder patterns. The existing 20 attempts and five-second
deadline allow the measured split/retransmission cases and terminate repeated
duplicates and stalled gaps. The work counter charges incoming comparisons/
copies and growing-prefix rescans; fixed record/extension limits additionally
bound their loops. Work units are not CPU cycles. These values intentionally
leave unsupported larger or excessively fragmented attempts unavailable.
The maximum queried work was 24,173 units on Linux/Root and 472 on VPN.
A separate Host transcript isolates work exhaustion: equal 4000-byte overlaps
advance the prefix one byte at a time and stop on attempt 17, at 128,120 charged
units and 4015 unique bytes, before any packet/byte/span/metadata/time limit.

Android process high-water RSS was 116,632 KiB (Root) and 119,100 KiB (VPN);
end-of-run RSS was 116,632 / 118,780 KiB. These include VPP, diagnostics and
transport state, not just TCP parsing; they are not an incremental-parser RSS
or power/thermal benchmark. Linux logical/pool peaks are proved, but no Linux
process high-water RSS measurement is claimed. Timings above include tracing
and test/control activity and establish packet progress, not a performance gate.

## Checks, retained failures and cleanup

The complete applicable Host suite passes 47/47; Rust passes 16 tests. The
independent reference passes 52,821 full-result comparisons across direct,
factorized and residual plans, PRE/POST, cold/hot cache and changed protocol/SNI
availability, including supplemental protocol combinations. Focused owner tests
pass ASan/UBSan/LeakSanitizer on the normal host. Independent evidence-negative
tests require the critical API, wire/cache/range, winner, timeout, completion,
endpoint and source/artifact witnesses: 42 mutations are rejected on Linux,
46 on scoped Android Root and 45 on VPN. Review outputs and exact test commands
are retained in the local acceptance index and run artifacts.

Retained red tests demonstrate the former gap/retransmission failure and the
late-TLS-after-LPI-stop publication bug. The first Linux sender cleanup tried
to send RST through its own RST-suppression hook; changing that test cleanup to
FIN produced the accepted run. The first VPN retransmission sample restored
ACK policy through slow UI capture after bytes had started, exceeding five
seconds; Product correctly returned timeout. Preparing the same management
operation before sending, then applying it promptly, proves real retransmission
within budget without changing Product limits or semantics.

The sandbox sanitizer run hit a ptrace/LeakSanitizer failure and repeated its
signal diagnostic; it was stopped and its full output compressed losslessly.
A bounded normal-host run passes. Evidence-reader corrections retain complete
JSON events from concurrent endpoint writes, treat malformed source decoding
as rejection, and target selected-packet witnesses in negative tests. None of
these collector/verifier corrections relabels a Product failure as success.

Runtime/endpoint/probe cleanup is recorded per run. The final device is stopped,
with `mayBeActive=false` and `protectionRunning=false`. No ordinary-user VPN
release or new performance qualification is claimed. All 33 entering user
design/research files remain outside this ticket's changes and commit.

## Independent review

Standards found no documented-standard violation. It identified three
nonblocking maintainability judgments: repeated policy fixture construction,
repeated cache diagnostic projections and a misleading collector parameter
name. The parameter now explicitly says `expected_protocol_id`; the two
localized repetitions remain visible at their platform/diagnostic call sites.
It also found a real verifier gap: the cleanup check searched for a tag that
was not on the RST suppression rules. The verifier now rejects the actual
per-session port/target rules, with a retained-hook mutation regression, and
the collector records removal errors. Product bytes are unchanged by this fix.

The separate Spec review found no concrete missing, partial or incorrect
requirement. Both reports identify their fixed review object and distinguish
inspection of retained device evidence from a new device run. Review reports
and the corrective follow-up are retained in the local index.
