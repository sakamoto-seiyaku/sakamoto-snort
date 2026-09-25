# R2 SMTP / FTP / FTPS — representative acceptance

2026-09-25. SAKAMOTO-284. **PASS within the selected forms below.**
Contract and coverage: [R2 mail/file recognition](../interfaces/R2_MAIL_FILE_RECOGNITION.md).
Local evidence index: `build-output/r2-20260925/acceptance-index.json`.
Final Linux/APK Product source closure:
`b977f4fce466266edb990e7620b57794c05c9c926d21d8d885b0cce2a9f3fa54`.

## Original acceptance mapping

| Requirement | Result and evidence |
| --- | --- |
| Explicit supported SMTP, FTP control/data, explicit/implicit FTPS shapes | Coverage matrix records transport, ordinary/nonstandard ports, direction, first/subsequent messages, printable-ASCII line bound and record conditions. Stable IDs 1007–1010 represent implemented detectors, not a library-name inventory. |
| Preserve base guess and correct before publication through R1 | The existing one LPI query feeds the same C resolver. Complete banner tokens can replace the current SMTP/FTP ambiguity before catalog mapping. Relevant substring, conflicting-token, short-line, direction and budget negatives are covered. Earlier facts remain a union. |
| Fixed nDPI/license and justified FTPS/TLS relation | Primary reference is nDPI `4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b` SMTP/FTP-control/FTP-data, LGPL-3.0-or-later. No source or engine imported. Explicit AUTH TLS→opposite final 234→request-side handshake record, or 990 plus handshake record, resolves FTPS and TLS together. Port alone never produces the pair; implicit encrypted FTP does not imply a control fact. |
| Same complete configuration API/save/apply/query and real rules | Linux uses the Product management client; Android uses the existing complete-rule API through its diagnostic entry. Saved source, active revision, expressions, bindings, full query result and catalog keys are joined independently. Ordinary positive/NOT rules, observe/enforce and same-flow recovery are verified. |
| Bounded state, availability, stop/update/reuse | Four byte-sized direction/stage fields occupy prior alignment padding. LPI 56 / FlowEntry 288 bytes unchanged. No TCP cache, retained payload, heap allocation or second flow table. Twenty-payload-attempt/32 KiB budget remains. Host verifies pending AUTH cannot cross a reused slot, stale identity cannot write, rule updates retain facts/stage and exhausted attempts do not restart. |
| Each detector positive/negative and independent optimized matching | Host covers banner variants, each selected command family, port/family/direction boundaries, malformed/short records, rejected/multiline AUTH, nonstandard established FTP and mail-port correction. Independent ordered AST exercises all ten IDs through three plans, PRE/POST, cold/hot/changed set and availability with complete winner/mode/action/attribution. Actual packet accounting is checked once per packet. |
| Actual Linux labels and representative Android Root/VPN | Linux runs real SMTP EHLO/NOOP, FTP login/control, paced PASV/RETR using server TCP 20, explicit AUTH TLS 1.2 and implicit 990 TLS 1.2 sessions. Each new label has Product graph/query evidence and actual block/recovery. Root and controlled VPN each run FTP→TLS/FTPS, certificate-pinned app TLS, API configuration/query, timeout under enforcement and successful responses after recovery. |
| Coverage/cost/cross-regression and dual review | Matrix, actual ARM64 owner tests/costs and section/stack measurements are indexed. Current Host retains DNS, HTTP→TLS, QUICv1/v2, SSH and mDNS positive/negative tests; rule counters and protocol queries are checked on actual graphs. No SNI or normal-observation-store implementation exists to newly claim. Standards and Spec findings are fixed and independently rechecked. |

## Verification

- Final Host CTest **46/46**, Product Core Rust **16/16**, generated catalog
  contract, actual Linux and Android VPP/NDK/Rust/Java builds pass.
- The independent logical-reference suite runs **21,744** cases, each including
  ordered/split and cached comparisons under direct/factorized/residual plans.
- Final assertion-enabled owner tests pass on actual Android ARM64.
  Focused Flow/LPI and cache tests pass ASan/UBSan/LSan; retained sanitizer
  environment/startup failures are distinguished below.
- Final Linux selected workload: **361 packets, 20 actual policy drops,
  6 published-set changes, 648 cache hits / 74 misses**.
- Final phone Root: **77 packets, 7 drops, 2 changes, 138 hits / 16 misses**.
  Controlled VPN: **79 packets, 6 drops, 2 changes, 133 hits / 25 misses**.
- The independent verifier binds source/artifact, installed APK/native hashes,
  saved configuration, profile/generation/Flow identity, wire facts, complete
  winner, native verdict/completion, owner counters and readable queries.
  Exact nonce-bearing endpoint commands/replies and client delivery are required;
  NF_ACCEPT or a screenshot alone cannot establish delivery.
- Negative evidence includes missing/altered endpoint/session/handshake/file
  chunks, wrong source/identity/protocol/winner/action/count and missing workload
  coverage. Required **distinct** applications and coherent unique sessions are
  checked; duplicated FTP witnesses cannot replace missing SMTP. No fixed
  number of negative tests is an acceptance threshold.

The endpoint oracle is ordinary Python/OpenSSL SMTP/FTP sockets and Conscrypt
app sockets. The wire oracle uses hand-calibrated exact workload messages and
record framing, never production detector outputs. Root captures real NFQUEUE
packets; controlled VPN captures app TUN packets and actual return packets.

## Cost and limits

`product_lpi_state_t` remains **56 bytes**, FlowEntry **288 bytes**, worker cache
**23,584 bytes** at 128 entries. New stage fields consume four previous padding
bytes, so persistent per-Flow/worker storage does not grow. Each eligible attempt
still calls LPI once, then bounded supplemental checks and catalog mapping.
Stopped calls retain identity validation and skip detector work. No budget increase.

Three actual ARM64 samples of 40,000 timed owner-identify calls per shape have
median sample averages: **0.716µs** valid SMTP banner, **0.556µs** SMTP-like negative,
**1.312µs** implicit FTPS record, **0.014µs** already-stopped producer. Flow allocation
is outside the timed loop; API/clock overhead remains. These workload costs do
not establish a speedup, p99, throughput, battery/thermal budget or universal
accuracy/performance guarantee.

ARM64 `-O2` stack-usage output reports identify 368, resolver 592 and nested
line-command 48 bytes (1008 combined before library/caller frames); R1's
corresponding identify/resolver sum was 896. Existing mDNS uses a temporary 512-byte
bitmap. Final plugin section deltas versus R1: ARM64 text +3600 / rodata +192 bytes,
Linux text +2960 / rodata +288; data/BSS unchanged. Section deltas are not RSS claims.

Live coverage is IPv4; IPv6 is Host coverage. Linux FTP data is a deliberately
paced **PASV/RETR transfer with server TCP 20**, not evidence of automatic passive
arbitrary-port association, active-mode negotiation, FTPS data 989 or encrypted
inner-channel parsing. Header-only TLS/FTPS facts do not prove complete Hello
validation, authentication or SNI. Actual live TLS 1.2 handshakes are separately
proved by both peers; that stronger evidence does not broaden the detector's
contract. SMTP 465/SMTPS, all STARTTLS variants, split lines/records, AUTH SSL and
full FTP channel correlation are outside this selected subset. FTP-data remains
an explicit port heuristic with possible false positives. There is no historical
fact withdrawal or confidence model. Controlled VPN retains
`protectionRunning=false` and is not an ordinary-user release claim.

## Review, retained attempts and cleanup

Standards review's naming judgment was resolved with private stage enums while
retaining byte storage. Spec review found two defects: established FTP on 25/110/587
could not upgrade because of a mail-port exclusion, and the verifier accepted
missing SMTP when FTP witnesses were duplicated. Both have retained red→green
regressions. Final source-b artifacts and live runs supersede source-a; independent
Spec recheck reproduced rejection specifically by the coverage guard, after the
source guard passed.

`retained-attempts.json` indexes earlier evidence and failures. Initial full Host
run lacked Unix-socket permission; normal-host rerun passes. One lifecycle test
fixture omitted transport length and was corrected. Initial LeakSanitizer lacked
process-inspection permission. A subsequent cache sanitizer invocation emitted
startup DEADLYSIGNAL without a Product stack; the same final binary's verbose
rerun initialized the runtime and passed leak checks. This is retained without
claiming a diagnosed Product fault. Early phone-verifier failures came from
unrelated IPv6 traffic being parsed before workload selection and an idle cache
worker lacking the valid zero prefix. They did not indicate failed packet delivery.

All owned endpoint/client/runtime processes and device cost helpers are removed.
Final phone is **stopped VPN**, generation 1552, saved/active revision 299,
empty errorCode, `mayBeActive=false`, `protectionRunning=false`. Device selector
and raw evidence remain local. The 33 pre-existing design/research files are
byte-identical to entry; only R2-scoped files are committed.
