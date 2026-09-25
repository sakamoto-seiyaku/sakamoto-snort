# R1 supplemental recognition and mDNS — representative acceptance

2026-09-25. SAKAMOTO-283. **PASS within the bounded scope below.**
Contracts: [resolution/lifecycle](../interfaces/R1_SUPPLEMENTAL_RECOGNITION.md)
and [auditable coverage matrix](../interfaces/R1_RECOGNITION_COVERAGE.md).
Evidence index: `build-output/r1-20260925/acceptance-index.json`.
Final Linux/APK source closure:
`13af1eb00784dffbedbdd7248c34f0c74d2ea92663f40666a13edae2ecde6576`.

## Original acceptance mapping

| Requirement | Result and evidence |
| --- | --- |
| Explicit coverage selection, fixed sources, runnable positives/negatives | Coverage matrix gives all five existing facts plus mDNS, fixed official LPI/nDPI revisions, transport/ports/direction/window, precedence and limitations. R2/R3/R4 and excluded groups are distinguished without claiming future PASS. |
| Keep upstream information until bounded correction, map once | Adapter retains noncatalog module names including FTP/SMTP. C resolver selects modern QUIC first, then structurally valid mDNS, then original guess; a single mapping precedes deduplicated union. Host 53→5353 overlap checks current DNS guess replacement. Earlier facts remain. |
| Existing QUIC integration and five-fact boundaries | v1/v2 supplement moved into the same resolver. Host exercises DNS/HTTP/TLS/QUIC/SSH positives and related negatives, including standard/nonstandard ports, HTTP→TLS and DNS→QUIC accumulation. nDPI parser/reassembly/crypto differences are documented, not imported. |
| Stable mDNS meaning, independent DNS relation | ID 1006/key `mdns` is generated through the existing Java/Rust/C/schema catalog. DNS 1001 is distinct. Host covers message framing/compression, both directions/families and malformed/short/port-only negatives. Actual mDNS queries and valid A responses publish through Product graph and affect rules on all three tested platform paths. |
| Same API/save/apply/query/errors and compatibility | Actual complete-config API publishes ID 1006 conditions, source files and saved/active revision queries are independently checked. Existing catalog IDs unchanged; reserved/absent IDs remain rejected in Host compiler tests. No second authoring store or new public control API. |
| Owner-local lifecycle, availability and finite work | Same generation/incarnation/current-packet checks and existing Flow state. mDNS-specific publication retention, 20-attempt stop, deduplication and slot reuse tests pass. Existing byte-budget, stale-identity and unavailable-stop cases remain. No packet holding, second table or byte cache. |
| Whole-set cache and full logical winner | Independent AST compares all six IDs under direct/factorized/residual plans, PRE/POST, cold/hot/changed-set/availability and negation/observe. 15,348 complete winner comparisons. Live verifier also checks full winner/mode/actions/attribution, native completion and exactly-once owner counters. |
| Linux and Android actual packets, NOT/enforce/observe/recovery | Current Linux runs standard DNS and mDNS separately, each with HTTP→TLS and QUIC. Root and controlled VPN both perform mDNS→QUIC, TLS, API rule blocking and recovery. Endpoint payloads/peer/session nonce/time window and app delivery are independently joined to Product wire/query evidence. |
| Resource/cost accounting and truthful limits | Zero persistent Flow/cache growth. Actual ARM64 lifecycle tests and three repeated 40,000-call samples per workload, call-local bitmap/stack accounting below. Failed probes are retained. No GB/T32960/full nDPI/complex withdrawal. |

## Verification results

- Final Host CTest **46/46**, Rust Product Core **16/16**, generated catalog shell
  contract and actual Linux/Android Java/NDK/VPP/Rust builds pass.
- Focused Flow/LPI and cache tests pass **ASan/UBSan/LSan** after the compression
  fix. The same owner-seam detector tests pass on actual Android ARM64.
- Independent full-winner comparison: **15,348** cases across all three plans.
- Linux mDNS: **176 packets, 5 actual drops, 4 published-set changes, 321 cache
  hits/31 misses**. Linux DNS: **176 packets, 5 drops, 4 changes, 317/35**.
- Phone Root: **154 packets, 8 drops, 4 changes, 280/28**. Controlled VPN:
  **156 packets, 7 drops, 4 changes, 285/27**.
- Altered witness rejection covers producer identity/facts/window, full cached
  result and counters, source binding, query labels, missing receive/response/
  recovery/client delivery, wrong endpoint peer and payload. Exact counts and
  categories are in the indexed negative reports; no fixed negative count is a gate.
- Independent Standards and Spec reviews found issues, now fixed and rechecked:
  compression pointers into non-name fields were accepted; endpoint evidence
  initially lacked session/payload binding; summary wording misnamed mDNS.
  Red→green regressions and final review reports remain indexed.

The endpoint oracle uses hand-encoded RFC query/answer bytes and independent
socket/TLS/aioquic outcomes. It never calls the production detector to derive
expected facts. NF_ACCEPT and UI screenshots alone cannot satisfy delivery.
The device debug probe drains duplicate preceding UDP replies before its gated
QUIC transition; this affects test sockets only, not packet-domain behavior.

## Cost and limitations

`product_lpi_state_t` remains **56 bytes**, FlowEntry **288 bytes**, existing
128-entry worker cache **23,584 bytes**. Each eligible attempt performs one LPI
registry query, at most one QUIC framing check, and only on UDP 5353 a bounded
mDNS framing check. Window remains 20 payload attempts/32KiB. A 512-byte
temporary boundary bitmap is discarded after the call. ARM64 `-O2` stack-usage
output reports 368 bytes for identify and 528 for resolver, 896 combined before
caller/library frames; this is separate from per-Flow storage.

Actual ARM64 owner-identify calls, three repetitions of 40,000 calls per shape:
median sample averages **1.81µs** for valid mDNS, **1.27µs** for same-size opaque
UDP 5353 and **1.28µs** for the same query on 5354. Allocation/Flow setup is outside
the timed call loop; clock and API overhead remain. These are representative
cost observations, not a baseline speedup, throughput/power/thermal gate or
universal latency guarantee. The selected parser adds no heap/RSS-owned state.

Live semantic scope is **IPv4 direct-unicast mDNS**, with real query/answer
delivery. IPv6 is Host coverage only. No multicast discovery/advertisement
delivery claim is made. Linux QUIC completes a v1 handshake; phone proves an
authenticated v1 Initial exchange, not a completed QUIC connection. SSH has
Host coverage. Neither protocol label proves valid SNI, authenticated TLS/QUIC,
HTTP3, every RR type or universal detector accuracy. Controlled VPN retains
its pre-existing `protectionRunning=false` release gate.

The initial mDNS framing subset deliberately rejects messages above 4096 bytes,
more than 64 records/questions, excess name work/jumps, and compression references
to names present only inside opaque earlier RDATA. These are bounded coverage
limits, including possible false negatives for valid but unsupported messages.
The retained LPI prefix heuristics can classify incomplete bodies; positive
header fixtures do not imply complete-session validity. No broad accuracy corpus
was measured. T12's earlier phone DNS53 delivery gap remains a historical gap;
successful current mDNS does not relabel that failed probe.

## Retained attempts and cleanup

`pixel-mdns-a` could not bind the existing local 5353 listener. `pixel-mdns-b`
delivered mDNS but its duplicate response was consumed by the QUIC probe; that
attempt is not PASS. The final probe drains the preceding exchange and
`pixel-mdns-c` completes both profiles. Linux build/run `*-a` preceded the
reviewed compression fix and is superseded by final `*-b`. Early ARM helper
build attempts exposed disabled assertions and an unavailable API26 clock
helper; corrected assertion-enabled monotonic-clock builds were used.

All owned runtime/test processes and helpers are stopped/removed by the
collectors. Final phone is **stopped VPN**, generation 1548, empty errorCode,
`mayBeActive=false`, `protectionRunning=false`. Device selector stays in local
evidence. The 33 pre-existing design/research modifications remain byte-identical
to the R1 entry baseline. Only this ticket's files are committed.
