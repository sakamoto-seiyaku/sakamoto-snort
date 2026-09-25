# T11: worker-private complete-result cache

Date: 2026-09-25. Scope: [SAKAMOTO-262](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/9bf0b486-258d-4400-ad38-b0d6e230db72).
Result: **PASS for representative T11 acceptance**, with measured performance
regressions retained. [Native contract](../interfaces/T11_COMPLETE_RESULT_CACHE.md).
Local evidence: `build-output/t11-20260925/acceptance-index.json`.

## Original acceptance and implementation

| Original criterion | Implementation and evidence |
| --- | --- |
| Cache complete Match/NoMatch; hits retain unified attribution/accounting | Cache entries retain evaluation, logical rule, full Rank, reason, effective mode, declared/actual action and NoMatch reason. Both paths return through the same graph recording/completion path. The Host matrix compares complete results, and actual packet traces join cache queries to final winners, endpoint delivery and query counters. |
| Conservative entire applicable program dependency summary; values, availability, application and full snapshot identity | Every compiled UID bucket unions static/CT dependencies across all its rules. Guards conservatively contain every current static value and availability, plus CT state and flow direction when applicable, UID, query position and generation/revision/hash. The higher-ranked previously nonwinning CT rule invalidates an old ALLOW. No winner-only dependency inference or weakened guard is used. |
| Correct Flow instance, direction, subject, lifecycle and slot reuse | POST guards use the observed Flow incarnation, not a slot or detached fact version. PRE performs no Flow lookup. Host tests cover subject/availability/direction changes, same revision/different hash, generation/revision changes, separate worker caches and actual one-slot FlowEnd release/reuse. Linux closes a real UDP Flow, drains FlowEnd, reuses the same owner/slot with a new incarnation and proves a cold POST query followed by independent warming. |
| Lazy publication invalidation; preserve counters/CT facts and old readers | Publishing a snapshot never scans or clears owner caches/flows. One protected packet snapshot spans PRE/POST and owner observation. Linux publishes during a held old reader: that packet completes under the old identity and the next packet uses the new one. Sustained Linux and Pixel sessions retain incarnation and cumulative accounting across enforce/observe changes. |
| Fixed private capacity; collisions/guard failure fall back to normal matching | Each worker embeds fixed 128-entry storage. Direct-mapped collisions execute full normal matching and replace one entry; no mutable cache is shared across workers, no hot allocation or partial-best result is introduced. Capacity-one Host tests force replacements; the cost scan measures 16/64/128 active entries and pressure from 256 flows. |
| Compare complete winners/actions/counts; future facts share the contract | The independent AST evaluator compares all three T10 plan choices through direct, split, cold/hot and fact-change paths for 11,604 rule/input configurations. All currently implemented static/platform/CT fields are covered. Real Match/NoMatch hits join the same final business counts. The interface explicitly requires later protocol/SNI producers to extend dependency projection and transition tests. |
| Representative cold/hot, change-frequency, guard-cost and occupancy measurements; choose an adjustable initial capacity | Host and ARM64 each run 84 configurations × four repetitions, 40,000 queries per arm, with alternating configuration order and direct/cache arm order. Scans cover 1/32/128 rules, 1/64/256 flows, 16/64/128 capacity, simple exact rules, CT/residual-heavy rules and expanded-range NoMatch, plus CT changes every 1/2/16 rounds. Complete-result signatures agree; raw timings, hit/miss/replacement/occupancy, stack usage and memory witnesses are retained. |
| Local choices remain within agreed semantics/ownership | Initial low-bit hash clustering was measured and corrected with a final avalanche mix. Default 128 uses the already allocated 128 slots (21,536 bytes per worker) and improves collision behavior without enlarging fixed storage, altering actions or adding a user setting. Cheap-rule regressions are retained; no automatic bypass, relaxed guard or universal speedup claim is introduced. |
| Cross-capability combinations with T12/T13/T15/T18 belong to the later implementation | T11 covers every currently implemented fact class. Published LPI/SNI/domain predicates do not exist yet; their dedicated later tickets must extend the same summary/guard and the cold/hot comparison matrix. This is an integration obligation, not a new blocker or a claim that those facts were tested. |
| Complete representative verification and retain explicit scope limits | Platform results below are separate. Actual Linux traffic is IPv4 TCP/UDP; actual Pixel traffic is IPv4 TCP in Root and controlled VPN. Host provides broader predicate/availability/IPv6/maximum-rule combinations. Bootstrap IPv6 queries contribute diagnostic totals but are explicitly outside the device semantic claim. |

## Source and runtime binding

The final Linux `linux-build-b` / `linux-b` and Pixel `pixel-build-b` / `pixel-b`
share Product source closure
`ee377e2cb0a5743d90b15c31553e99cbbacf68b06d511d7b4efbbb98f065dc24`.
Build witnesses retain the source closure, dirty diff, stage/toolchain logs and
artifact hashes. Runtime records bind installed APK/native or Linux artifact
hashes, actual process/profile/generation, saved source bytes and snapshot
identity, request operations, captured packet bytes, external endpoint payloads
and completion. UI screenshots/XML are operation evidence only.

Linux uses the established network-none tooling container with NET_ADMIN and
NET_RAW; only current Product artifacts execute. No POC source was imported.
Android operations use `./dev/adb` serially. Native cost runs occurred after the
runtime collectors stopped and removed their temporary executables afterward.

## Verification results

- Host: **44/44** complete applicable tests. The focused cache and real Flow
  lifecycle suite passes **ASan/UBSan/LSan**. The independent reference covers
  **11,604** three-plan configurations, including six cold/hot/changed-fact
  evaluations and repeated split queries per configuration.
- Linux: base sustained-flow sequence **67 packets / 64 logical hits / 14
  actual drops**, plus **10 real UDP packets / 10 logical hits / zero drops**
  around same-slot reuse. Cache queries: **69 hits / 75 misses**, including
  **35 Match hits / 34 NoMatch hits**. FlowEnd and completion debt drain.
- Pixel Root: **71 packets / 71 logical hits / 20 actual drops**;
  **102 cache hits / 28 misses**, including **56 Match / 46 NoMatch hits**.
- Pixel controlled VPN: **65 packets / 65 logical hits / 14 actual drops**;
  **88 cache hits / 46 misses** overall. The IPv4 semantic scope includes
  **47 Match / 37 NoMatch hits**; **18 IPv6 bootstrap queries** are counted in
  diagnostics but excluded from the representative semantic claim.
- Independent altered-witness checks reject **29 Linux / 28 Pixel** categories:
  stale/mixed identities, wrong incarnation, query position, incomplete or wrong
  winner/mode/action/Rank/reason, missing/duplicate queries, false hit/miss totals,
  wrong capacity/occupancy/storage, wrong build binding and reused-instance drift.
- Pixel finishes stopped in VPN profile, generation **1542**, saved/active
  revision **258**, empty error code and `protectionRunning=false`. Root/VPN
  completion/resource debts close. No test endpoint, runtime or cost executable
  remains. The two controlled TCP rules and their enforce binding remain saved.

These are representative backend checks, not Android public-release acceptance.
No new physical-network, broad-device, power/thermal, live maximum-rule,
long-expiry, LPI/SNI or domain acceptance is claimed.

## Cost and engineering initial value

Final cost evidence is `cost-host-d` / `cost-arm64-c`; earlier cost runs remain
as diagnostic iterations. All signatures compare semantic result fields rather
than ALLOW/DROP alone. Timings below are median nanoseconds per query for 128
rules and 128 active slots; they include the identical harness result signature.

| Workload | x86-64 direct → cached | ARM64 direct → cached | Hit rate |
| --- | ---: | ---: | ---: |
| Exact rules, one hot flow | 122.2 → 126.6 | 223.4 → 534.3 | 99.9975% |
| Exact rules, 256 flows | 117.9 → 212.3 | 212.5 → 659.6 | 11.65% |
| CT/residual-heavy rules, one hot flow | 2,025.0 → 124.7 | 2,258.3 → 370.3 | 99.9975% |
| CT/residual-heavy rules, 64 flows | 2,070.8 → 962.1 | 2,142.4 → 1,320.0 | 59.28% |
| Expanded-range NoMatch, one hot flow | 508.2 → 125.6 | 923.6 → 451.6 | 99.9975% |
| Expanded-range NoMatch, 256 flows | 535.8 → 601.5 | 879.4 → 1,213.3 | 11.65% |

The hot path measures guard construction, dependency lookup, hashing, comparison,
result copy and harness signature without normal leaf/index work. It is not a
pure instruction-level guard benchmark. Cheap exact matching can be faster:
the 256-flow ARM64 example regresses **3.10×**. Expensive repeated queries benefit;
no universal performance PASS is claimed. CT changes every 1/2/16 rounds across
eight flows at 64 slots retain **68.72%** hits and complete equivalence; cached
median costs are **738.8/745.0/748.9 ns** on x86-64 and
**711.5/770.1/791.6 ns** on ARM64. Returning to an already guarded exact fact
value may safely reuse its result; these are not mandatory version-flush counts.

The initial hash had only 12 occupied slots and zero hits for a measured 64-flow
round-robin workload. Final avalanche mixing spreads the same workload over
50–52 slots at capacity 128, with 59.28–65.52% hits. Using all 128 already-backed
slots improves collision behavior compared with 16/64 without extra allocated
memory. This is an adjustable native initial value, not a promise that 128 is
optimal for all workloads. Misses and capacity pressure always retain complete
matching and full guards.

Each fixed cache occupies **21,536 bytes**, with **104-byte guards** and
**168-byte entries**. Both workers add **43,072 bytes** to management policy
representation peak: **911,756 bytes**, below the existing 1 MiB bound. The
existing bounded query scratch reserve still covers the measured cache and
matcher call chain. Compiler `-fstack-usage` outputs are retained. Process
high-water measurements are separate from representation storage; the helpers
also report `/proc/self/status` VmHWM. Neither that observation nor these short
runs establish thermal, power, sustained throughput or application-wide latency
budgets. CPU frequency, migration and background load remain uncontrolled.

## Review and retained attempts

The initial Standards review found no hard violation and one diagnostic issue:
cache dependency lookup work was missing from `subject_probes`. The implementation
now includes it on both hit and miss paths. The initial Spec review found no
semantic issue. Final independent reviews and follow-up are retained under the
local evidence index.

A first Linux collector used the older singular `show product flow` spelling;
its captured packets remain, but its reuse collection failed. The corrected
collector uses `show product flows`. The superseded first Pixel collection was
interrupted with its cleanup path before final-source rerun. The CT verifier was
updated to account for T08's whole-rule PRE placement and POST facts for unknown
subjects; the T11 verifier additionally binds inherited VPN startup policy and
separates bootstrap IPv6 diagnostics from the IPv4 claim. These changes do not
weaken packet decisions, winner or counter comparisons.

The first restricted Host suite passed 43 tests and could not bind the existing
real Unix-domain socket lifecycle fixture. The unchanged complete suite passes
outside that sandbox. The final cost repetitions alternate arm order to reduce
ordering bias. Raw earlier hash/cost measurements and collection attempts are
retained; they are not the final acceptance runs.

```sh
rtk proxy ctest --test-dir build-output/t11-20260925/host --output-on-failure
rtk proxy python3 tests/evidence/verify_t11_cache.py build-output/t11-20260925/linux-b
rtk proxy python3 tests/evidence/verify_t11_cache.py build-output/t11-20260925/pixel-b
rtk proxy python3 tests/evidence/test_t11_cache_negatives.py build-output/t11-20260925/linux-b
rtk proxy python3 tests/evidence/test_t11_cache_negatives.py build-output/t11-20260925/pixel-b
rtk proxy python3 tests/evidence/t11_cache_cost.py summary build-output/t11-20260925/cost-host-d
rtk proxy python3 tests/evidence/t11_cache_cost.py summary build-output/t11-20260925/cost-arm64-c
```
