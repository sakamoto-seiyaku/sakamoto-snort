# T06: bounded static Boolean rules

Date: 2026-09-25. Scope: [SAKAMOTO-257](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/0d476ae4-0b9e-4e68-81eb-3f05ada336d9).
Result: **PASS for T06 representative acceptance**. The
[interface contract](../interfaces/T06_STATIC_EXPRESSIONS.md) records the source
encoding, availability, validation and publication limits.

## Source and evidence

Evidence root: `build-output/t06-20260925/`. The final Linux and Pixel `build-c`
manifests bind Product source closure
`896d6543a924443afce61da84ccd611229d52f369cf4e0dc453f0afae7e074b1`
and API identity `product_core.api/1.0.0@fdc80277`. Source snapshots, dirty diff,
artifact/APK hashes, installed native hashes, runtime identities, complete saved
configuration, raw packet bytes, query readbacks and endpoint payloads are retained.
`acceptance-index.json` and `raw-manifest.json` index the completed evidence.

## Original acceptance mapping

| T06 criterion | Implementation and evidence |
| --- | --- |
| Same VPP source/compiler/API chain; bounded AND/OR/NOT and static fields | Existing complete rule operation carries an optional expression through Java/JNI/Rust/VAPI into VPP-owned source. IPv4/IPv6 family, IP protocol, device direction, network/interface equality, source/destination CIDR and inclusive port ranges use the existing packet facts. `SKRULE04` persists expressions and reads earlier source formats. |
| Missing facts cannot become false then match NOT; known true OR still works | Three-valued evaluation preserves unavailable facts. Hand-calibrated full truth tables cover AND, OR, NOT and nested negation. Actual Linux and Root loopback packets have unavailable network context; NOT remains unavailable while a true source-port OR branch wins. |
| Current packet endpoints, device direction, address/port boundaries and platform availability | Host calibrates every leaf, both address families, CIDR edges, source/destination reversal, ports 0/65535 and unavailable direction/network/interface/ports. Linux uses source ports 65534/65535 and destination 65535. Pixel Root and VPN use controlled outbound sequences; VPN return evidence proves reversed packet endpoints and device input direction. |
| Full winner, Rank, declared/effective/actual action and source | Independent checks compare complete logical results, same-action competitors and ordering ties. Device verifiers join source identity/group binding, snapshot hash, winner/version, Rank, mode and action to real terminal completion and delivery. Observe DROP retains its winner while allowing actual traffic. |
| Test-only ordered reference calibrated with hand cases | `product_static_reference_test.py` evaluates logical ASTs recursively and rules in explicit order; 1301 comparisons include literal predicate and three-valued calibration followed by deterministic generated AST cases. It never enters Product runtime. |
| Bound expression depth/size/work before publication; preserve save/apply behavior | Source bytes are bounded at 64 per rule; depth at eight, effective rules at 128. There is no DNF expansion or worker allocation. Malformed/overlong source rejects before save. Valid depth-nine source saves, rejects compilation with source index/capacity error, and retains the old active winner; reload and repair are tested. Exactly 64 bytes and depth eight succeed. |
| Independent expectations, no compiler/index/cache reuse | Reference expectations read logical rules and input availability only. A separate source encoder supplies the real compiler. Evidence decoding reconstructs saved logical conditions, never reads compiled tables, and compares the actual packet decision. Every new static predicate has hand-decided matching/nonmatching/availability cases. |
| Representative Host/Linux/Android evidence, honest limits | Final Host suite and focused Rust/Java/C checks are retained separately. Linux independently verifies eight real NFQUEUE cases. Pixel independently verifies 16 cases, eight Root and eight controlled VPN, with rule updates and cleanup. Eleven falsified witness categories are rejected independently for each platform. |

## Verification and limits

Linux `linux-a/` contains four successive configurations: AND, OR, NOT and the
same NOT source through an observe group. Each gets a matching and nonmatching
port sequence. Pixel `pixel-a/` repeats those four configurations through the
baseline API text entry in both profiles. Screenshots/XML demonstrate operations;
packet captures, native completion, endpoint nonces and query deltas demonstrate
policy behavior. Returned VPN packets retain current source/destination and input
direction; they are permitted by complete NoMatch for these outbound-only rules.

The final applicable Host suite is **42/42** (`host-accepted.log/.xml`),
including the independent reference, Java boundary and complete Rust profile
contracts. A stale plugin-init test stub initially omitted the newly required
validator; it now links the real L4 module. The first sandbox run also denied
Unix-domain sockets; the accepted full run uses the normal Host environment.

`linux-a-verified.json` and `pixel-a-verified.json` record independent verification;
the corresponding `*-negative-witnesses.json` records rejection of changed winner,
Rank, mode, actual action, logical hit count, expression, availability, runtime
identity, endpoint, artifact binding and cleanup evidence. `review-results.md`
records the independent Standards and Spec review results. Standards found no
hard violation; its dead collector branch was removed and an optional numeric
truth-value readability suggestion remains. Spec found no missing or incorrect
T06 requirement. The archived Pixel collector contains the removed unreachable
branch; cleanup does not change its exercised operations or Product source.

This closes the required representative static-expression slice. Device cases
are IPv4 UDP and controlled contexts; full dual-stack/CIDR/protocol Boolean
coverage is Host evidence, not a new IPv6/TCP/device or physical handover claim.
Broad combined qualification remains T29. CT/LPI/SNI, optimized indexing,
post-flow placement, caching, performance/power and release readiness are outside
T06. Controlled VPN continues to report `protectionRunning=false`.

The preceding T05 sanitizer anomaly remains unexplained and unchanged. T06 does
not claim to diagnose or close it. T06's own GCC PIE sanitizer run intermittently
failed with repeated `DEADLYSIGNAL`; a minimal program reproduced the same symptom.
The retained T06 debugger backtrace locates a failure before `main`, in dynamic
symbol lookup for `pthread_getspecific` during `AsanInitInternal`. This identifies
the observed startup failure location, not the underlying platform defect or
every historical failure. The same C test sources built with `-no-pie` passed five
bounded default ASan/UBSan/LSan runs. `sanitizer-no-pie-summary.json` records flags,
binary hash and logs; `sanitizer-probe-results.json`, `gdb-summary.json` and the
compressed failed log retain the counter-evidence. No Product source change was
made to conceal the sanitizer startup issue. Initial T06 build attempts retained a stale
Android default-stage path, the old API CRC and an unupdated JNI word count;
`build-c` fixes those build integration errors and supplies both accepted runs.
A stale generic Host build directory also referred to a historical checkout;
all T06 Host results use the fresh ticket-specific C-only build directory.

```sh
rtk proxy python3 tests/host/product_static_reference_test.py
rtk proxy python3 tests/evidence/verify_t06_expressions.py build-output/t06-20260925/linux-a
rtk proxy python3 tests/evidence/verify_t06_expressions.py build-output/t06-20260925/pixel-a
```
