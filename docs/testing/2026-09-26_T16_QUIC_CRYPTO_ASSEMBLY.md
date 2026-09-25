# T16 QUIC CRYPTO assembly acceptance

[SAKAMOTO-267](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/ee27428a-3d06-41ec-80c4-29867fec1dd5)
extends the shared QUIC v1 client Initial SNI producer. The
[contract](../interfaces/T16_QUIC_CRYPTO_ASSEMBLY.md) defines ownership,
identity, bounds and downstream responsibility. The local
[acceptance index](../../build-output/t16-20260926/acceptance-index.json)
binds exact builds, source snapshots, traffic, readers and review evidence.

## Behavior and limits

Independent CRYPTO offsets retain copied authenticated payload ranges in the
same owner-local Flow. The first authenticated client Initial anchors direction
and DCID. Reordered/repeated equal bytes merge; conflicting overlap terminates
unavailable. Complete contiguous content enters the existing borrowed-span
ClientHello parser. A whole SNI rule retains its TLS/QUIC prerequisite, complete
winner/cache dependencies and same-packet cutoff. QUIC results publish QUIC,
not TCP TLS. Policy changes do not clear partial assembly or published facts.

The TCP and QUIC structures are distinct members of protocol-tagged preallocated
storage. This is neither TCP sequence reuse nor a second parser pool. Terminal
success/failure, unchanged owner deadline and FlowEnd retirement clear retained
bytes and metadata; fixed Flow reservation persists until pool teardown.
The identity-fenced 320-byte query projects the selected transport's retained
bytes. `bytes` is now unique admitted CRYPTO bytes; duplicate work and datagram
bytes still consume the cumulative work budget. Stop11 remains valid ABI history;
incomplete assembly now stays unavailable/running rather than terminal11.

The admitted initial values are 4096 CRYPTO offset bytes, 32 disjoint ranges,
32 CRYPTO frames/64 nonpadding frames per Initial, eight coalesced Initial
packets per datagram, 20 nonempty payload attempts, 131072 diagnostic work units
and five seconds from the original attempt. Reverse traffic consumes budget but
cannot mix server CRYPTO. DCID changes cannot reset state. PN reconstruction
advances only after authenticated input, starting in the first observed window.
[QUIC CRYPTO and packet-number rules](https://www.rfc-editor.org/rfc/rfc9000.html)
provide protocol framing; the local capacity values are engineering limits.

Supported scope is v1 client Initials in the admitted first packet-number window
and its tracked continuation, including split/reordered/coalesced ranges.
Retry, connection migration, server Initial decryption, arbitrary versions,
handshake completion, authenticated peer identity, HTTP/3 and general tunnel
contents are not claimed. Actual packet-path samples are IPv4; IPv6 qualification
is not inferred. T18 owns later exact/descendant domain-list integration with
these assembled names. Controlled VPN is not an ordinary-user release gate.

## Verification seams and results

Existing authorized seams: public owner observe/identify/close/release/deadline,
real management/save/apply/query and packets, independent complete winner/cache
comparison. Wire expectations come from RFC9001 and Python cryptography/aioquic,
not the Product decoder. Reused input scratch is overwritten immediately after
public identify calls, proving assembly does not depend on a borrowed packet.

- Final full Host suite: 49/49; existing independent three-plan ordered/split,
  cold/hot/fact-change reference: 52,821 complete-winner comparisons.
- Rust: 16 unit/integration tests. Focused ASan/UBSan/LSan: 5/5 suites.
- Host and physical ARM64: RFC9001 plus 147 protected single-Initial cases and
  244 multi-Initial sequences. These cover every Hello split boundary in both
  orders, equal overlap, duplicate, conflict, reverse isolation, DCID/version/
  authentication failure, PN window transitions, range/span/attempt/work/time
  limits, max-eight coalescing and ninth-packet rejection.
- Partial state survives policy revisions, but generation/incarnation and ended
  identities reject mutation. Timeout without a new packet retains CT while
  clearing assembly. Actual END callbacks see cleared bytes/metadata before
  release; full pool admission fails without a separate parser quota, then
  releases/reuses all slots.

All three final Product packet paths exercise two real STUN exchanges before
QUIC, named and absent Hello sequences, contradictory overlap, range and offset
exhaustion, duplicate packet exhaustion, timeout without new data, policy
observe/enforce/recovery, stale typed-query rejection and same-packet final-range
DROP. Named traffic includes two coalesced Initials in its middle datagram.
The independent reader joins exact encrypted wire, independent decryption/TLS,
configuration, complete winner/rank/action/mode/reason, cache guards, endpoint
outcome and native packet completion. Partial packets already complete normally;
only the packet making SNI available can acquire that new rule result.

| Final path | Packets | Actual DROP | Cache hits / misses | Max admit→terminal |
| --- | ---: | ---: | ---: | ---: |
| Linux NFQUEUE | 540 | 4 | 947 / 133 | 324.614 µs |
| Pixel Root | 540 | 4 | 947 / 133 | 69,199.748 µs |
| Pixel controlled VPN | 540 | 4 | 998 / 82 | 4,262.288 µs |

These are functional samples, not latency SLOs. The larger Root sample remains
in the record. Each path observes up to 450 retained Hello bytes, 32 disjoint
ranges and 19,440 cumulative work units in its actual workload. The physical
public-Flow campaign below separately exercises the larger byte/work envelope.
The Android timeout probe waits at least 5.1 seconds without new packets; the
typed query and same Flow identity show stop7/unavailable and all-zero assembly
metadata. Both profiles end stopped with no owned VPP process.

Only `linux-build-c/linux-sni-c` and `pixel-build-c/pixel-sni-c` are final accepted
Product artifacts, source closure
`e556cbedfae2802a6e6d4b05a0e75104509a1af2e9f5b038df33397f4c4621ec`.
Missing/altered witness rejection passes: 54 Linux, 55 Pixel Root and
55 Pixel VPN mutations. Changes to assembly bytes/ranges/contiguous span/PN,
SNI/query identity, complete cached winner, exact wire, actual verdict, endpoint
flight, build binding and resource reservation are rejected.

## Resource experiment and choice

FlowEntry is 9024 bytes (+8 from T15), including an independently typed 4264-byte
QUIC representation in the existing TCP-sized union. A 1024-entry owner reserves
9,261,384 bytes; two owners reserve 18,522,768 bytes. The policy cache stays
23,584 bytes/owner. There is no packet-path heap or second concurrency limit.

The physical ARM64 campaign runs current public Flow observe/identify and actual
close/END release, not isolated crypto primitives: ten workloads × capacities
1/64/1024 × three samples × ten complete allocation/processing/retirement cycles.
Workloads vary 1/8/16/32 ranges, 512/2048/4000 retained bytes, full eighteen-step
cumulative work exhaustion, repeated overlaps and coalesced complete Hello.
Per-packet timings include observe, identify and in-region assertions, excluding
setup/retirement;
cycle timings include lifecycle. They are wall-clock measurements without
subtracting scheduler or clock overhead, not latency SLOs.

At capacity1024, the eighteen-step work case reaches 4,096,000 simultaneous
logical bytes and 129,536 work units per flow, then stops unavailable and clears
state. It measures median-of-three mean packet time 10.292 µs, maximum observed
packet time 1.213 ms. The 4000-byte case has mean 15.538 µs and max1.376 ms;
32 ranges mean13.207 µs and max0.716 ms. Across all 1024-flow arms, the largest
observed sample is 4.268 ms in the 512-byte arm; it is retained, not hidden as an
outlier. Actual results and all capacities are in `arm64-cost-c/result.json`.

4096 bytes retain the existing bounded Hello envelope without growing a second
full cache. Thirty-two ranges cover the tested sparse/reordered envelope with
128 bytes of range metadata; the thirty-third is rejected explicitly. The
inherited twenty-attempt/five-second limits retain a fixed lifetime even under
repetition, and 131072 work units stop the heavy repeated-decryption sequence.
Eight coalesced packets bound crypto invocations independently of tiny frames.
A further nine physical samples measure the full eight-coalesced-packet cap
at capacities1/64/1024. At1024, median mean packet time is
51.682 µs and the maximum is
732.503 µs; inputs and binary hashes are
bound in `arm64-coalesced-peak.json`. These supplement the90 main samples.
The measured modest fixed reservation and successful high-work cleanup support
these initial local bounds; they do not prove arbitrary internet coverage,
energy efficiency, thermal/soak behavior or a release performance budget.

## Retained failures and review

The first split red test stopped11 instead of remaining running. Independent
Spec review found that only the first packet in a coalesced datagram was read;
its two-600-byte Initial reproduction and the red/green fix are retained.
The review also required high-byte/cumulative-work and peak-time measurements;
the full-sequence ARM64 campaign above addresses that gap. A debug-probe Java
JSONArray type reference compile error was corrected before the final build.
Earlier a/b artifacts and runs remain evidence history, not final acceptance.

## Standards

Independent initial and corrected/final reviews found no hard documented-standard
violation or outstanding correctness blocker. Small interval-merge duplication
and historical probe payload names remain nonblocking judgments. Final review
confirmed the source-bound Linux/Pixel results, resource figures and explicit
scope. Its final packaging observation (index and future-tense disposition) is
resolved by the completed local index and this report.

## Spec

The P2 coalesced-Initial issue and the partial resource evidence were fixed and
independently rechecked. The reviewer reran the original red reproduction and
final Pixel reader; Root/VPN both passed. No remaining correctness, scope or
acceptance blocker. Final negative results and the previously missing index
are now present.

Standards: no outstanding hard finding. Spec: one P2 and one evidence gap
resolved; no outstanding finding. Full reports are indexed separately.

## Reproduction

Current sources: `tests/host/quic_crypto_sequences.py`,
`tests/host/product_flow_quic_test.c`, `tests/device/t16-{linux,pixel}-sni.py`,
`tests/device/helpers/t16_quic_peer.py`, `tests/evidence/verify_t16_sni.py`,
`tests/evidence/test_t16_sni_negatives.py` and `tests/evidence/run_t16_arm64.py`.
Exact compiler inputs, source/build hashes, copied reader sources and raw run
files remain in the local index. Linux uses a network-none tooling container
with current Product binaries. Android uses only `dev/adb`, the explicit VPP
stage and fresh fixture nonce. No POC source or removed C++ Product is used.
