# R4 realtime recognition — representative acceptance

2026-09-25. SAKAMOTO-286. **PASS within the selected forms below.**
Coverage/state contract: [R4 recognition](../interfaces/R4_REALTIME_RECOGNITION.md).
Local index: build-output/r4-20260925/acceptance-index.json.
Linux and Android Product source closure:
fca5efbf1c9e076ef73f7e3dc5041e290eca6d3db709499271f1b54668f060f4.
Accepted live runs: **Linux run-b / Android run-a**, both source-a artifacts.

## Original acceptance mapping

| Requirement | Result and evidence |
| --- | --- |
| Type/length/direction/port, multi-packet and stop matrix | The executable contract selects modern STUN envelopes, three forward RTP sequences per SSRC/direction, four reduced-size RTCP reports, SIP start lines and classic DTLS record/fragment envelopes. IDs 1016–1020 distinguish STUN/RTP/RTCP/SIP/DTLS. nDPI is the main framing/state reference; hello/port-only and invalid-boundary shortcuts are excluded. |
| Positive/negative and overlapping features | Host cases cover truncation, version/type/length/attribute/extension/padding errors, sequence duplication/reordering/gaps/wrap, SSRC/direction changes, standard/nonstandard/conflicting ports, random short payloads and interleaved facts. No universal false-positive claim. |
| R1 resolution and DTLS separation | Existing provider→resolver→catalog→deduplicated historical union remains. Current supplementary selection precedes mapping. DTLS adds only its own fact, never TLS/SNI/confirmed absence. R1–R3 owner tests remain passing. |
| API, saved/applied configuration, queries and actions | Product management API / Android complete-rule diagnostics join rules, bindings, revisions, named facts and complete winner/mode/actions to real packets. STUN→RTP and STUN→RTCP make a known NOT predicate become positive; each Flow survives observe→enforce→recover publication. |
| Bounded owner state and lifecycle | Existing 20-attempt/32-KiB limits, synchronous borrowing and generation/incarnation remain. Each fact has identity, publication, budget and reuse checks. No media decoder, extra byte cache, payload ownership or second Flow table. State 160 / FlowEntry 392, +32 bytes each versus R3. |
| Three plans, PRE/POST, cache and arithmetic | **52,164** independent complete-winner comparisons cover every fact and mixed sets across direct/factorized/residual plans, PRE/POST and cold/hot/changed inputs. An actual owner STUN→RTP sequence checks literal complete winners and unchanged packet/IP-byte totals despite repeated cache queries. Live verification checks each selected packet's single Flow contribution and native outcome. |
| Linux and Android traffic | Nine Linux workloads prove all five labels: STUN/RTP/RTCP/SIP over UDP and declared complete-message TCP forms, plus DTLS UDP. Android Root and controlled VPN each prove STUN binding→bidirectional RTP, DROP timeout and endpoint recovery. NF_ACCEPT alone is never delivery evidence. |
| Costs, cross-regressions, review and cleanup | Host 46/46, Rust 16/16, final actual ARM64 assertion-enabled semantics/costs, catalog/build contracts and ASan/UBSan/LSan pass. Both independent review axes completed; Standards cleanup/evidence findings were fixed and rechecked. Existing Flow/query/decision regressions are included. TLS/QUIC SNI and normal-observation consumers are not yet implemented; this ticket does not claim them. |

## Actual traffic and limits

| Run | Selected packets | Actual drops | Set changes | Cache hits / misses |
| --- | ---: | ---: | ---: | ---: |
| Linux Root, nine workloads |557|21|13|1004 /110|
| Android Root, STUN→RTP |59|1|2|58 /60|
| Android controlled VPN, STUN→RTP |59|1|2|106 /12|

Nonce-bound peers exchange STUN requests/responses with padded attributes;
the diagnostic XOR-MAPPED-ADDRESS is explicitly a controlled value, while the
actual transport peer is separately recorded. RTP carries 160-byte PCMU sample
blocks with endpoint-specific SSRC, sequence and timestamp. RTCP uses reduced-size
sender/receiver reports. SIP OPTIONS receives a matching 200 response. DTLS uses
ClientHello/HelloVerifyRequest cookie exchanges: **initial handshake fragments**,
not completed authentication, encrypted delivery or SNI. No audio playout, media
decoder or mainstream-endpoint interoperability is claimed.

TCP evidence covers complete STUN/SIP messages and exact RFC4571 RTP/RTCP frames;
arbitrary segmentation/coalescing is outside these new detector rows. Other
explicit false-negative boundaries include classic STUN/vendor formats, compound
RTCP/feedback, RTP gaps above the selected bound, encrypted SRTP padding and
DTLS1.3 unified headers. No new stream cache or general DPI accuracy claim.

The independent verifier builds exact known transcripts without calling Product
detection or importing the peer. It binds source, artifact/APK/installed-native
identity, runtime/profile, source configuration, Flow identity, complete logical
results, cache guards, protocol queries, payloads, endpoint requests/responses and
recovery delivery. Negative verification rejects missing public-label workloads,
reused nonces, altered/missing identities, facts, winners/actions/counts, resource
values and endpoint/client witnesses. No fixed negative-test count is a gate.

Live coverage is IPv4; IPv6 and the wider negative matrix are Host coverage.
Android is a representative UDP/multi-packet chain, not every detector on-device.
Linux uses both workers; Android VPN media uses owner 1. Root resource high-water
marks include unrelated device flows. Controlled VPN retains protectionRunning=false;
ordinary-user VPN release and existing performance gates remain unchanged.

## Resources and actual ARM64 costs

Recognition 160 bytes, FlowEntry 392, protocol set 8, and 128-entry worker cache 23584.
Each 1024-entry owner reports 422216 allocated bytes and zero capacity misses.
High-water marks: Linux 4/5, Android Root 5/5 and VPN 0/1. No added heap allocation
or retained packet buffer.

Final arm-cost-c performs a clean rebuild, verifies Product source before/after,
snapshots test/CMake inputs, records the actual compiler and translation-unit
command, verifies assertions remain enabled and matches deployed/executed binary
SHA. Final owner tests run on-device before three samples of 40000 timed identify
calls per shape. Median sample averages, microseconds/call:

| Shape |µs/call|
| --- | ---: |
| STUN |0.796|
| RTP sequence |1.751|
| RTCP reports |0.308|
| SIP start line |0.208|
| DTLS envelope |1.340|
| RTP-like wrong-version negative |1.287|
| Already-stopped producer |0.046|

These assertion-enabled -O2 owner calls include existing LPI and clock overhead;
allocation/observation is outside the timed call. They are not end-to-end latency,
p99, throughput, power/thermal comparisons or a new gate. Stopped calls perform
no detector work. A running attempt invokes the base provider once and bounded
resolver checks. STUN/SIP/DTLS retain no added state, RTP 14 field bytes and RTCP 10.

ARM64 stack usage: identify 368, resolver 112 and largest nested mDNS frame 528,
1008 bytes on that path before external library/caller frames. Plugin section
deltas versus R3: Linux text +3904 / rodata +336; ARM64 text +2304 / rodata +384;
data/BSS unchanged. Section sizes are not RSS measurements.

## Reviews, retained failures and cleanup

Spec found no confirmed missing behavior or scope creep. Standards identified
an endpoint leak on Linux collector startup failure. An occupied-port red test
reproduced one leaked process, explicitly removed afterward. Endpoint creation
and readiness now have cleanup protection with independent cleanup attempts.
The final green failure test leaves no process; the positive Linux path was
rerun with fresh nonces (run-b).

Standards also required the ARM executable/source/assertion chain above. Cost-a
is preliminary evidence; final cost-c includes the clean-build binding and final
matrix. The fix was independently rechecked; intermediate cost-b is retained.

Other retained failures were an incorrect fixture fragment offset, a test
compile-budget type name, cost-helper editing error and escaped collector newline.
They are test/harness errors, not Product PASS records. Initial Rust execution
was denied real Unix sockets by the sandbox; normal-host rerun passes 16/16.
LeakSanitizer required a normal-host environment because sandbox tracing prevented
it from running; final checks pass. Valid Linux run-a is superseded by run-b after
the cleanup fix. No failed attempt is relabelled PASS.

Owned runtime, endpoint and device helper processes are gone. Final phone state:
**stopped VPN**, generation 1560, saved/active revision 332, empty errorCode,
mayBeActive=false and protectionRunning=false. All device operations used ./dev/adb
with the established per-process Linux-client route to the existing ADB server;
no server restart, direct Windows adb or KernelSU bypass. All 33 entering design/
research files remain byte-identical and outside this commit. No next ticket was
started by this implementer.
