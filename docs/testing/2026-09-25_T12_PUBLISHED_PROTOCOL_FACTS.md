# T12 published protocol facts — representative acceptance

Date: 2026-09-25. [SAKAMOTO-263 / T12](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/50824432-ad45-47ec-8624-c9811048a7ee).
Result: **PASS within the original representative T12 scope**, with the platform
and protocol limits below. This is not SNI, broad protocol accuracy, performance
qualification or ordinary-user VPN release acceptance.

Native contract: [T12 published facts](../interfaces/T12_PUBLISHED_PROTOCOL_FACTS.md).
Local evidence index: `build-output/t12-20260925/acceptance-index.json`.
Both actual Product builds bind source closure
`f70a29d423b9c5cbbfce02115d339f58a6565cecb342d6314b548466efe31d88`.
The initial 31 unrelated design files remain byte-identical to the T11 handoff.

## Original acceptance mapping

| Original requirement | Implementation and direct evidence |
| --- | --- |
| Existing owner-local Flow, real libprotoident, no parallel flow table/fork import | `product_flow_lpi.c` mutates embedded `product_lpi_state_t` only after generation/incarnation and current-packet identity validation. Official LibtraceTeam source is pinned at `97a8efecd257ec09f652374399f27b3a65db7d0a`; 551 unchanged upstream files and the two feature-only adapter edits are inventoried. Product packet-domain logic remains C. |
| Stable catalog and TLS/QUIC mappings; no private AppID/category facts | Generated C catalog comes from existing TSV IDs 1001–1005; reserved/absent IDs reject the predicate. Provider aliases map exact recognized facts. HTTPS contributes TLS because its recognizer checks TLS bytes; it does not imply an HTTP fact. A bounded RFC 9000/9369 Initial-header supplement supplies modern QUIC recognition. |
| Deduplicated immediate accumulation, no-result retention, full-set winner | Host Flow tests and live HTTP→HTTP+TLS use one incarnation. Linux also observes DNS→DNS+QUIC. The first packet publishing the new fact already uses it in post-flow matching. Miss/unmapped attempts and later budget stops preserve existing facts. |
| Availability distinct from results and stop | NOT does not match before any supported fact is available. Linux fresh opaque UDP reaches attempt exhaustion with availability false. Phone nonstandard-port DNS remains unmapped before QUIC; it does not become comparable Unknown. This catalog has no explicit Unknown ID. |
| Bounded producer/lifecycle | 20 payload attempts and 32 KiB payload credit, neither reset by policy publication; no payload borrow survives the synchronous call. No packet-side allocation, waiting, second flow table or per-flow library heap. FlowEnd stops the producer; pool reuse clears state and changes incarnation. |
| API, real packets, fact/winner queries, NOT and stop | Conditions are submitted through actual complete-config APIs, saved source is read independently, and `show product flows` returns set availability, stable catalog facts, attempts, stop reason and last winner. Host malformed/identity/budget cases plus Linux and phone packet completions prove behavior. |
| Immediate T11 cache integration | All application rules contribute LPI dependency; canonical guards include full published set and availability plus existing snapshot and Flow identity. Independent cold/hot/fact-change comparisons and live cache-hit/result/counter checks pass. |
| Immediate T09/T10 optimization integration | Independent logical AST compares direct, split, cold/hot and changed-fact queries under direct, factorized and residual plans: 12,072 complete winner comparisons. Public plan-resource queries confirm that LPI/range cases actually use all three plan forms. |
| Retained representative evidence and limits | Current-source Host, Linux NFQUEUE and phone Root/VPN builds/runs are bound below. Failed setup and extra probes remain in the local index; no Host result substitutes for device evidence. |

## Verification

- Final applicable Host CTest suite: **46/46**. Rust Product Core: **16/16**
  unit/integration tests. Java/NDK/VPP/Rust actual APK and Linux builds succeed.
- Focused new Flow/LPI and existing complete-cache tests pass
  **ASan/UBSan/LSan**. The sandbox forbids LeakSanitizer ptrace and one real UDS
  lifecycle test; retained attempts are distinguished from successful same-test
  runs outside that sandbox. No unrelated historical sanitizer campaign reran.
- Independent native Flow tests exercise HTTP/TLS and DNS/QUIC accumulation,
  tiny payloads, wrong identity/packet, rule-publication retention, budget stops,
  same-slot reuse, reserved IDs, QUIC v1/v2 recognition and malformed/truncated
  Initial headers.
- Independent packet/source verifier: Linux **176** captured packets,
  **5** actual policy drops, **4** published-set changes, **318** cache hits / **34**
  misses among the selected complete queries. Phone Root: **128** packets,
  **8** drops, **3** set changes, **228/28** hits/misses. Phone VPN: **130** packets,
  **7** drops, **3** set changes, **233/27** hits/misses.
- Each accepted run rejects **37** altered-witness cases: changed set,
  availability, budget, incarnation, source binding, query catalog labels,
  cache guard/result fields, counters and missing producer observations.
- Independent Standards review: no findings. Independent Spec review: no
  missing, incorrect or out-of-scope behavior identified; it separately reran
  the Linux and phone verifier and checked the original ticket scope.

The verifier derives this workload's protocol facts from recorded wire prefixes
and actual peer TLS/QUIC protocol events, then evaluates saved logical source in
an independent ordered AST. It checks immediate facts, whole-rule placement,
full cached result fields, owner counters, one snapshot, stable Flow identity,
readable query prefixes, exactly-once native completion and actual NFQUEUE/VPN
policy disposition. It loads no Product detector, compiler, index or tracker.
Its protocol oracle is deliberately workload-specific, not a second detector.

## Platform evidence and limits

Linux `linux-d` uses an isolated `--network none` tooling container with
NET_ADMIN/NET_RAW. Only current Product binaries execute. Application sockets
perform a real HTTP/TLS 1.2 upgrade, standard DNS exchange and complete aioquic
QUIC v1 handshake. Actual NFQUEUE verdicts, same-Flow enforcement/recovery,
producer stop and cleanup are captured. The older `linux-c` run correctly kept
nonstandard-port DNS unavailable and is retained separately.

Phone `pixel-b` installs the exact new APK/native combination and runs Root then
VPN serially through `./dev/adb`. Ordinary application Socket/SSLSocket performs
HTTP→TLS 1.2 on one connection. DatagramSocket sends an independently generated,
cryptographically valid QUIC v1 Initial; the peer accepts its ClientHello and
returns a QUIC flight. **This is Initial exchange evidence, not a complete phone
QUIC connection.** Nonstandard-port DNS request/reply remains an unmapped result
and provides an availability counterexample. There is no phone DNS53 PASS,
QUIC v2 device claim, SNI extraction, broad traffic corpus or IPv6 semantic claim.
Controlled VPN still reports `protectionRunning=false` under its existing gate.

An extra phone standard-DNS attempt, `pixel-d`, captured an outgoing DNS packet
through Product NFQUEUE with ALLOW, but it did not reach the test endpoint and
the app timed out. The network-side cause is not established; no Product success
or failure beyond that observed disposition is inferred. Its runtime was stopped
and its uniquely identified endpoint container removed. This extra experiment
is excluded from the accepted original representative phone matrix.
Earlier `linux-a/b`, `pixel-a/c` attempts failed before their intended acceptance
traffic due to test dependency, sandbox or endpoint-bind setup; they are retained.

## Resource accounting and reproducibility

`product_lpi_state_t` adds **56 bytes per Flow**. The tested entry grows from
232 to **288 bytes**. At 1,024 slots per worker, the existing complete Flow pool
allocation grows from 258,376 to **315,720 bytes**; both workers add 114,688 bytes.
No additional per-flow allocation or independent capacity exists.

The complete-result cache remains 128 entries per worker. Set/availability add
16 bytes per cache entry: **23,584 bytes per worker**, 4,096 extra bytes across
both workers. This storage remains included by the existing management resource
accounting. Producer state, immutable library registry and process/library RSS
are separate costs, not hidden inside the rule compiler limit.

The official library's fixed registry initializes before owner admission and is
released at process exit. Each eligible payload causes at most one registry
query, with at most 20 queries per Flow. Its detector/registry sources remain
unchanged; C supplies current directional prefixes and lengths. No sustained
throughput, power, thermal or universal cache speedup conclusion is drawn; the
prior T09–T11 performance qualifications remain unchanged.

Linux adds its system `libstdc++.so.6`/`libgcc_s.so.1` dependency; Android links
libc++ statically into the plugin and packages libprotoident notices. The Linux
plugin section-size comparison and dependency list, full upstream inventory,
build source/binary hashes and exact external endpoint packages are indexed
locally. Fork/POC artifacts do not enter the Product closure.

Reproduce from the indexed commands/build witnesses with
`tests/evidence/verify_t12_lpi.py` and `test_t12_lpi_negatives.py`. Linux collection
uses `tests/device/t12-linux-lpi.py`; phone collection uses
`tests/device/t12-pixel-lpi.py`. `tests/device/helpers/t12_protocol_peer.py` is
only a synthetic endpoint and protocol oracle, with ephemeral test certificates.
Client phase gates pause the application test socket, not Product-owned packets.
