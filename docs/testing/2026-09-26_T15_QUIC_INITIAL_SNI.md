# T15 QUIC v1 Initial SNI acceptance

[SAKAMOTO-266](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/f8303934-d4b1-48d1-86c0-f8334f5d75c9)
implements the single-complete-Initial slice of the unified rule specification.
The [interface contract](../interfaces/T15_QUIC_INITIAL_SNI.md) defines its
supported version, shared Hello semantics, limits and failure reasons.

Final Product source closure:
`94c6af4e95458c6a7da9b0a4c8df435953de8f4f947bee59155a8241ba60df33`.
The local [acceptance index](../../build-output/t15-20260926/acceptance-index.json)
binds source snapshots, builds, raw runs, independent readers, negative witnesses,
reviews and the final commit. Only `linux-build-c` / `linux-sni-c` and
`pixel-build-c` / `pixel-sni-c` are accepted final platform artifacts.

## Implemented behavior

The existing owner-local UDP producer removes QUIC v1 client Initial header
protection, authenticates/decrypts AES-128-GCM and reads complete CRYPTO spans
through the shared ClientHello parser. A name or confirmed absence publishes
QUIC, without falsely adding the TCP TLS label. The producer retains no UDP
packet or decrypted bytes between calls and does not use TCP sequence storage.
Cross-Initial assembly remains explicitly unavailable in this slice.

The unchanged 320-byte identity-fenced SNI query distinguishes name, valid
absence, malformed input, unsupported version, authentication failure and
incomplete assembly. Added stop values are documented in the interface; VAPI
accepts their valid range and still rejects malformed/omitted/stale responses.
The API identity remains `product_core.api/1.0.0@aabf0772`.

Mbed TLS 3.6.7 supplies the pinned, unmodified C AES/GCM/SHA-256 primitive
subset. Its [provenance and hashes](../../third_party/mbedtls/README.md) and
license are retained. Both platforms statically link private symbols; neither
loads a platform-private libcrypto ABI. Existing serialized graph startup
primes CPU capability detection before packet workers run. Android packaging
records `quicCrypto` and `quicVersion`, requires exactly one correct value for
each, and includes dependency notices. Six real `--apk-only` admission tests
reject missing, wrong and duplicate values.

## Acceptance mapping

| Requirement | Evidence |
| --- | --- |
| Supported protected Initial and shared name/absence | RFC9001 Appendix A.2 through the public Flow operation; 147 independently protected cases; aioquic-generated valid name/absence Initials accepted by an actual aioquic endpoint on all three packet paths |
| Whole-rule TLS/QUIC prerequisite, cutoff and no holding | Independent full-winner reader joins saved source, snapshot, SNI/LPI, PRE/POST cache, actual verdict/completion and free events; two fresh Initials are dropped by their own newly available SNI result |
| Incomplete/unsupported input cannot confirm absence | Host incomplete prefixes, gaps/overlap, unknown frames, bounds and invalid vectors; live malformed-name, version, authentication and incomplete-offset cases preserve result 0 with stops 2/9/10/11 |
| Typed query and bounded lifetime | Real API identity/query joins and stale-incarnation rejection; Host revision retention, same-slot reuse, packet budget and owner-deadline cleanup without a new packet or CT expiry |
| Existing cache and recognition integration | Real STUN warms the same Flow/application fallback before QUIC; Initial invalidates that cache result; subsequent hot queries and policy revisions retain complete attribution and existing facts |
| Index/factorized/residual integration | Hand-decided producer-to-cache winners for every wire case in three plans; existing independent ordered reference extended with QUIC SNI transitions and mixed protocol sets |
| Supplemental protocols | Real STUN→STUN+QUIC coexistence; full Host R1–R4 framing/lifecycle regressions and complete-winner matrix; no DTLS→TLS shortcut or tunnel-inner parsing |
| Android dependency/ABI closure | Fresh APK and installed native hashes, source-bound build, explicit Android stage, private static crypto linkage, management API, app socket traffic and stopped runtime identities |

## Results

Host full suite: **48/48**. Rust: **16** unit/integration tests. The independent
ordered reference reports **52,821 complete-winner comparisons**, with three
plans, split execution, cold/hot cache and fact changes. These include existing
coverage; they are not 52,821 new QUIC wire examples. RFC plus the **147** new
protected wire cases also pass as a standalone public-Flow C executable on the
physical ARM64 phone. Focused QUIC/TLS/LPI/cache ASan, UBSan and LSan runs pass.

Each platform sends two real STUN request/reply pairs before its Initial, then
tests name, valid absence, four unavailable outcomes, and two first-Initial
cutoff drops. Valid nonblocked Initials produce an independently parsed name or
absence, a real server `ProtocolNegotiated` event and a QUIC reply flight.
Later ordinary UDP probes exercise observe/enforce/recovery and stopped LPI
budgets without clearing the published SNI or protocol set.

| Final platform | Selected packets | Actual drops | Cache hits / misses | Maximum admit→terminal |
| --- | ---: | ---: | ---: | ---: |
| Linux NFQUEUE | 448 | 4 | 775 / 121 | 284.500 µs |
| Pixel Root | 448 | 4 | 832 / 64 | 5,162.150 µs |
| Pixel controlled VPN | 448 | 4 | 824 / 72 | 3,808.594 µs |

These are bounded functional samples, not latency SLOs or a performance pass.
The independent readers verify complete winner, mode, declared/actual action,
rank/reason/order, current facts, cache guards, source identity, exact wire,
API state, endpoint outcomes and native completion. Screenshots/XML record
operations only. Missing or altered witnesses are rejected in **47** Linux,
**48** Pixel Root and **48** Pixel VPN mutation checks. The VPN delay mutation
explicitly selects a tested admission token rather than unrelated background
traffic.

## Resources and costs

Selected limits are 4096-byte datagrams/decrypt scratch, 32 nonoverlapping
CRYPTO spans, 64 nonpadding frames, 32 ACK ranges, 20 payload attempts and the
shared five-second deadline. Hello/extension/work limits remain bounded.
There is no new Flow reservation or parser admission quota: FlowEntry remains
**9016 bytes**, including the existing **8340-byte TCP cache** and **288-byte
SNI state**. A 1024-entry owner reserves **9,253,192 bytes**; two owners reserve
**18,506,384 bytes**. The policy cache remains **23,584 bytes per owner**.

Five physical ARM64 samples of 10,000 public Flow flush/observe/identify cycles
using the RFC Initial measured **9.882–13.124 µs/cycle**, median **12.131 µs**.
This includes Flow lifecycle and LPI work in a standalone C test, not the VPP
Adapter or an isolated cryptographic primitive. The compiled inputs are checked
against the final Product sources in `arm64-final-witness.json`. Compiler stack
usage records a **5280-byte** QUIC observer frame; called helpers add their own
bounded frames, so this is not a claim of total stack peak. The Android plugin
file grows by **27,904 bytes** against the T14 artifact; file size is not RSS.
Idle power, thermal behavior, broad concurrency costs and release performance
are not measured here.

## Retained failures and limits

`retained-attempts.json` links the original red test, transient compile/test
errors, the pre-existing Clang/GNU-extension full-build incompatibility, and
the sandbox UDS failure followed by successful normal-host tests. Initial
artifact sets `a` and `b` and their runs remain preserved and excluded from
final acceptance: `a` predates CPU-probe priming; `b` predates the packaging
manifest guard repair. The manifest review finding has retained real-entrypoint
red **0/6** and green **6/6** rejection evidence. The first VPN mutation's
background-token targeting error is retained separately from Product results.

This proves **QUIC v1 Initial exchange**, not a completed or peer-authenticated
QUIC/TLS handshake, HTTP/3, general QUIC decoding or tunnel contents. Initial
keys are public protocol-derived keys. Platform traffic here is representative
IPv4; IPv6, Retry processing, server Initial decryption, later packet-number
windows and arbitrary frame families are not claimed. Cross-Initial CRYPTO
assembly belongs to [T16](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/ee27428a-3d06-41ec-80c4-29867fec1dd5);
exact/descendant domain-list consumers belong to T18. Controlled VPN continues
to report `protectionRunning=false`; this is not an ordinary-user release gate.

## Standards

Independent review found no documented architecture violation. One P2 in APK
manifest admission was fixed and rechecked with six negative entrypoint tests;
the stale Linux runner description was corrected. The remaining localized
duplication judgment concerns Hello header checks: TCP must bound advertised
length before the complete body arrives, while the shared entry also validates
QUIC input. Retaining those checks is nonblocking. Full report and follow-up:
`build-output/t15-20260926/standards-review.md`.

## Spec

Independent review found no substantiated missing requirement, scope expansion
or wrong implementation. Final source-bound Root/VPN and negative evidence is
linked in `build-output/t15-20260926/spec-review.md`. The supported slice and
unmeasured boundaries above remain explicit.

Standards: one P2 fixed, no outstanding blocker, one nonblocking judgment.
Spec: zero substantiated findings.

## Reproduction sources

Collectors: `tests/device/t15-{linux,pixel}-sni.py`; endpoint:
`tests/device/helpers/t15_quic_peer.py`; readers:
`tests/evidence/verify_t15_sni.py`, `test_t15_sni_negatives.py`, and
`test_t15_crypto_stage.py`. Exact build/source snapshots, inputs and identities
are indexed locally. Linux uses the existing network-none tooling container
and current Product binaries; Android uses only `dev/adb` and the explicit
`build-output/s220-20260913/android-stage-b` VPP stage.

Protocol references: [RFC9000](https://www.rfc-editor.org/rfc/rfc9000.html),
[RFC9001 packet protection and vectors](https://www.rfc-editor.org/rfc/rfc9001.html),
and [Mbed TLS 3.6.7](https://github.com/Mbed-TLS/mbedtls/tree/mbedtls-3.6.7).
