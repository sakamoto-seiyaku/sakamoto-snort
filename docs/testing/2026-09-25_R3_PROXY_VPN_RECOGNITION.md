# R3 proxy, VPN and remote-access recognition — representative acceptance

2026-09-25. SAKAMOTO-285. **PASS within the selected forms below.**
Coverage contract: [R3 recognition](../interfaces/R3_PROXY_VPN_RECOGNITION.md).
Local evidence index: `build-output/r3-20260925/acceptance-index.json`.
Final Linux/APK Product source closure:
`da316996aed9bd69588b5092bd2d8d9c331a1ebfbfd074cfdc82b36f80325154`.
Accepted live runs are **Linux source-c / Android source-c run-e**; earlier
artifacts and interrupted runs are retained separately.

## Original acceptance mapping

| Requirement | Result and evidence |
| --- | --- |
| Explicit messages, directions, transports, ports, state and stops | The executable coverage matrix selects OpenVPN no-HMAC reset/control envelopes, WireGuard handshake/cookie/transport index sequences, SOCKS4/4a and SOCKS5 negotiation, and RDP TCP negotiation / UDP v1 SYN pairs. Stable IDs 1011–1015 are openvpn, wireguard, socks4, socks5 and rdp. RDP transports share one label; no duplicate generic SOCKS label. |
| nDPI primary reference and bounded state | Fixed nDPI `4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b` OpenVPN/WireGuard/SOCKS/RDP source and LGPL notices were examined and hashed. Selected framing/state ideas are independently implemented in VPP-native C; no source import, whole nDPI module, second Flow table or transport ownership. |
| Scoped fork features and pre-publication correction | Version distinction and nonstandard TCP ports are retained with paired messages. Weak one-packet SOCKS, generic seven-byte X.224 and broad UDP/port-only guesses are excluded. All results use R1's resolver before catalog mapping and historical union. An unmatched attempt never publishes final Unknown or withdraws an old fact. |
| Actual API/save/compile/apply/query/decision closure | Linux uses the actual Product management client and Android its existing complete-rule diagnostic entry. Positive/NOT conditions, source rules, groups/bindings, saved/active revisions and complete winner/mode/action/attribution are independently joined to actual packets and named Flow facts. Observe→enforce→recover changes preserve each Flow; new facts invalidate old cache guards. |
| Identity, directions, malformed input, budgets and reuse | Each protocol covers relevant negative and short/lookalike cases, incorrect generation/incarnation/tuple, same-direction input, rule publication, 20-attempt/32-KiB stops and same-slot reuse. The SOCKS5 method bitmap covers all offered values 0–254 and the 32-offer limit. RDP flag 8 without its required correlation-info cannot confirm. No packet or TCP bytes are retained. |
| Independent reference and resource accounting | **35,004** logical-reference cases exercise the three plans, PRE/POST, cold/hot and changed protocol set/availability, complete winners and once-per-packet accounting. Combined SOCKS5→FTP-control→TLS/FTPS preserves R2 facts. State is 128 bytes, FlowEntry 360, protocol set 8; existing resource queries include the new layout. |
| Actual Product graph and endpoint coverage | Linux proves all five new labels through seven socket workloads: OpenVPN TCP/UDP, WireGuard, SOCKS4, SOCKS5, RDP TCP/UDP. Android Root and controlled VPN each prove SOCKS5 CONNECT relay and WireGuard handshake/data with real app sockets, API rules, blocked timeout, successful recovery, queries and normal stop. Endpoint delivery is required separately from native verdicts. |
| Matrix, ARM64 costs, full checks and review | Host **46/46**, Product Core Rust **16/16**, catalog/build contracts, Linux/APK builds, assertion-enabled actual ARM64 owner tests and focused ASan/UBSan/LSan pass. Both independent review axes were rechecked after fixes. Scope and costs are below; ordinary-user VPN release gates are unchanged. |

## Actual traffic and evidence strength

| Run | Packets | Actual drops | Published-set changes | Cache hits / misses |
| --- | ---: | ---: | ---: | ---: |
| Linux Root, seven workloads | 429 | 19 | 7 | 771 / 87 |
| Android Root, SOCKS5 + WireGuard | 128 | 7 | 2 | 231 / 25 |
| Android controlled VPN, same pair | 129 | 7 | 2 | 234 / 24 |

SOCKS4/5 perform actual CONNECT and relay nonce-bearing messages through a
separate TCP connection to an echo listener. SOCKS5 deliberately offers both
no-auth and a private method before accepting no-auth, exercising the review fix.
The verifier requires the target listener's receive/send witnesses as well as
proxy and client evidence.

The WireGuard test endpoints perform Noise IKpsk2, validate authentication,
and exchange encrypted inner IPv4 ICMP echo packets using cryptography/OpenSSL
primitives. On Android, the app sends fresh precomputed session frames through
ordinary UDP sockets and checks exact authenticated peer responses; the peer
also decrypts and checks inner ICMP. This establishes that selected controlled
exchange, not official WireGuard implementation interoperability, kernel tunnel
routing, roaming/rekey timers or a general VPN implementation. Product itself
recognizes visible framing/indices and does **not** authenticate or decrypt it.

OpenVPN live evidence is a standards-framed no-HMAC reset/acknowledgment exchange;
RDP live evidence is TCP negotiation and UDP v1 initial SYN/SYN-ACK exchange.
Those bounded test responders repeat initial messages to exercise policy windows.
They are **handshake-fragment evidence**, not completed OpenVPN TLS authentication
or a desktop session. RDP TCP's confirm uses the documented source reference;
full X.224/RDP parsing and extended negotiation remain outside the detector.

The independent wire oracle uses exact known workload transcripts and fixed
expected labels, never Product recognition to generate expected facts. It joins
source/artifact, installed native/APK hashes, configuration, runtime generation,
Flow identity, full winners, native verdict/completion, cache and packet counters,
Flow queries and endpoint results. Altered or missing identities, protocol facts,
winners/actions/counts, resource sizes, distinct workloads, crypto/relay delivery
or fresh probe identities are rejected. No fixed negative-test count is a gate.

Live coverage is IPv4; IPv6 is Host coverage. Android exercises two representative
protocols and one active packet owner in these runs, not every detector/owner
combination. Linux covers both owners. Recognition does not imply SNI, full Hello
validation, tunnel-inner application labels or universal accuracy. Historical
facts remain cumulative. Controlled VPN retains `protectionRunning=false`.

## Resource and ARM64 measurements

Recognition state is **128 bytes**, FlowEntry **360 bytes**, each **+72 bytes**
versus R2. The protocol set stays 8 bytes and the 128-entry worker cache stays 23584
bytes. Actual Linux and Android `flow.runtime` report **389448 allocated bytes
per 1024-entry owner** and zero capacity misses. Linux high-water marks are 4/3;
Android's representative pair uses owner 1 (peak 2), with owner 0 idle. No new
packet allocation, second table or byte cache is introduced.

Three actual ARM64 samples of 40000 timed identify calls per shape give these
median sample averages (µs/call):

| Shape | µs/call |
| --- | ---: |
| OpenVPN reset pair | 1.180 |
| WireGuard initiation/response | 1.224 |
| SOCKS4 request/reply | 1.731 |
| SOCKS5 request/reply | 0.472 |
| RDP negotiation pair | 0.658 |
| WireGuard-like reserved-byte negative | 1.291 |
| Already-stopped producer | 0.047 |

These are assertion-enabled `-O2` owner-seam calls; Flow allocation/observation
is outside the timed operation, while per-call clock overhead remains. They are
not plugin-wide latency, p99, throughput, power/thermal results, a direct R2
speed comparison or a new performance acceptance threshold.

ARM64 stack-usage output reports identify 368, resolver 32 and the largest nested
mDNS frame 528 bytes: 928 bytes along that path before external library/caller
frames. Selected mail nesting is separately recorded. Final plugin section
deltas versus R2 are Linux text +4256 / rodata +208 bytes and ARM64 text +2160 /
rodata +456; data/BSS unchanged. These section counts are not RSS measurements.

## Reviews, retained failures and cleanup

Both reviews found SOCKS5's initial common-method-only bitmap contradicted the
offered-method contract. A mixed private/common offer was first reproduced as
red, then fixed with bounded full membership and all-method/boundary tests.
Standards' parallel-fixture-array judgement was resolved with explicit fixture
objects. A final protocol audit found RDP flag 8 accepted missing correlation
bytes; its red→green regression and independent Microsoft-spec recheck are kept.

`retained-attempts.json` preserves the initial wrong CMake target, malformed test
cookie, overclaimed HTTP fixture expectation and missing lifecycle callback;
these were test/setup corrections. The first full Host suite lacked permission
for real Unix sockets; the normal-host final suite passes. An initial ARM script
incorrectly estimated alignment at 136/368; it rejected actual 128/360 results,
then corrected checks and final source-c samples passed.

Android source-a completed raw collection before the method fix but is not final
acceptance. Runs-b/d hit WSL Windows-command launch failures; run-c reused a
WireGuard fixture nonce and old release files, skipping gates. Those runs are
not relabelled PASS. The collector now rejects used report/release identities;
the guard was exercised against old and fresh device state, and final run-e uses
fresh fixtures. Bounded retries apply only to idempotent WSL reads/captures.
Ambiguous runtime-start attempts still enter cleanup. The final run uses the
unchanged canonical `./dev/adb` with a temporary official Linux client connected
to the existing localhost ADB server; no server restart or global wrapper change.

Owned runtime/endpoint processes and the device cost helper are gone. Final
phone readback is **stopped VPN**, generation 1558, saved/active revision 327,
empty errorCode, `mayBeActive=false`, `protectionRunning=false`. The temporary
host ADB client is retained as tooling for later work. All 33 entering design/
research files remain byte-identical; this ticket commits only its scoped files.
