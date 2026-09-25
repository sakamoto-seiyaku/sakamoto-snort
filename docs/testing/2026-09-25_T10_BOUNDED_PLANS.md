# T10: bounded range plans and compilation limits

Date: 2026-09-25. Scope: [SAKAMOTO-261](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/dc31db60-f3bf-4840-a09a-50b3732c3921).
Result: **PASS for representative T10 acceptance**, with measured performance
limits. [Native contract](../interfaces/T10_BOUNDED_PLANS.md).
Local evidence index: `build-output/t10-20260925/acceptance-index.json`.

## Source and original acceptance

Linux `linux-build-a` / `linux-a` and Android `pixel-build-b` / `pixel-a` share
Product source closure
`51745629569114c3fa839238ce6003826fc8f35244bd45b251fa50e54c5fd5b9`.
Build manifests retain exact sources, dirty diff, compiler logs and artifact
hashes. Runtime witnesses bind installed native/APK or Linux artifact hashes,
configuration bytes, generation/revision/hash, profile, packet bytes and actual
endpoint outcomes. Screenshots/XML document Android operations, not packet proof.

| Original criterion | Implementation and retained evidence |
| --- | --- |
| Exact bounded ranges; 32 complete direct entries by default; no unbounded product or DNF | Each 16-bit port interval has at most 30 disjoint prefix pieces. Count the two covers before expansion; at most 32 complete entries per whole rule are emitted. Larger pairs retain two inclusive interval factors. General OR/NOT remains a bounded source expression. Host tests cover 16/32/900 potential combinations, endpoints, complete-view pressure and the original static/CT predicate set. |
| Conjunction state is query-local; no fragment action or extra logical hit | All entries reference one whole compiled rule at one PRE/POST position. Query-local deduplication permits one complete residual evaluation per rule; the original availability-aware evaluator alone supplies the winner and action. Consecutive complementary port/direction and PRE/POST queries cannot accumulate partial evidence. Every real probe increments logical hits exactly once, including expanded and observe-mode rules. |
| Compare full winner, mode and actions across direct/factor/residual paths | The independent logical AST evaluator now checks all three native budget choices through ALL and actual split PRE/POST execution: **11,604 complete-winner comparisons**. Same-action competitors, priority/order/stable identity, reason, mode, declared/actual actions, unavailable facts, IPv4/IPv6, network/interface and CT/direction remain covered. The cost driver separately compares full-result signatures across every legal plan and scanned budget. |
| Total effective-view/index/condition/temp/update budget; reject only after complete alternatives fail | One entry is reserved for every remaining rule before spending expansion capacity. Entry pressure chooses factors; factor pressure chooses complete residual evaluation. Condition and storage limits apply before mutating the caller view. Fixed storage, both protected banks, preflight/publication, maximum source arrays, compiler/query scratch and management overlap are charged. Tests reduce entry, factor, condition and publication budgets independently; feasible smaller plans succeed and all-plan capacity failures preserve the old view. |
| Compilation failure keeps saved edits and the old running snapshot; no partial-best return | Host accepts 128 large-factor rules, saves an edited ALLOW plus a 129th rule, rejects compilation, reloads the saved edit and proves the old DROP winner still runs; repair publishes the new ALLOW. Linux and both Android profiles repeat a 129-rule save/compile failure after a two-rule factorized snapshot. Saved revision advances, active revision/hash/rule versions stay fixed, typed compile/capacity errors are queryable, and subsequent actual packets retain old winners. |
| Local scale/budget scan measures query/compile/new-old coexistence; keep 32 as the start | `cost-host-b` and `cost-arm64-b` contain **127 configurations × three alternating repetitions per platform**, with 1/8/32/64/128 rules, five expression/range shapes, all three plans, direct limits 1/8/16/32 and minimum-vs-256 entry budgets. Each row times 40 compilations and 20,000 queries while four materialized views coexist; old-reader signatures and three deliberate budget failures are checked. Storage and executable/address-space high-water measurements are retained separately. |
| Engineering defaults have measured reasons and do not alter agreed behavior/architecture | 32 remains the specified initial direct threshold. A 256-entry total bounds index growth while reserving the inherited 128-rule complete fallback. Scans demonstrate mixed plans at 248/252 entries and complete alternatives at 128; extra masks can be slower. No adaptive performance rule, truncation, new user setting, source-format change, cross-language ABI change or universal speedup claim is added. |
| Cross-capability responsibility with T09/T12/T13/T15/T18 | T09 full Rank, residual continuation, whole-rule placement and per-packet snapshot ownership remain intact. The three-plan independent matrix covers every currently implemented static/platform/CT predicate. Later LPI/SNI/domain/cache tickets extend this seam with their new predicates; T10 neither implements those tickets nor invents blocking edges. |
| Representative Host/Linux/Android verification and retained limits | Results below are platform-specific. Real traffic is representative IPv4 UDP; broader address/Boolean/CT combinations and the 128-rule maximum are Host/native-seam coverage. Linux and Pixel have independent verifiers and 37 altered-witness rejection categories each. No Host result is called a device result. |

## Verification

- Complete Host suite: **43/43**. Focused matcher, CT and configuration tests
  pass **ASan/UBSan/LSan**, including failure preservation and range boundaries.
  Existing older sanitizer claims are not broadened.
- Linux: **10 outbound real NFQUEUE probes**, **10 logical hits**, **4 actual
  drops**, all three plans plus observe mode, one compile-limit failure and
  recovery. Four distinct active snapshot resource identities are checked.
- Pixel: Root **10 outbound probes / 4 drops**, controlled VPN **10 / 4**;
  **20 logical hits**, two compile-limit failures and recovery, eight active
  snapshot resource identities. Delivered VPN packets also have independent
  return-packet/completion checks. Controlled VPN remains
  `protectionRunning=false`, not a release protection claim.
- Each platform rejects **37** altered-witness categories: plan/resource
  identities and bounds, complete query/winner fields, saved/active/error/version
  divergence, duplicate logical hits, missing witnesses and lost saved edits.
- Native completion/resource debts close at stop. Pixel finishes stopped in
  VPN profile, saved/active revision **237**, generation **1539**, empty error
  code and no protection running. Temporary endpoint and cost executables are
  removed; the two controlled probe rules and observe binding remain saved.

Diagnostic projection-plus-query time has median **3,561.5 ns** on Linux and
**10,599.5 ns** on Pixel (maxima **9,748 / 18,229 ns**). These are scoped trace
measurements, not matcher throughput or release latency thresholds.

## Local cost and storage experiment

Both targets build the current production compiler/matcher with the same `-O2`
flags. `build.json` binds source files, helper, toolchain/version, flags and
executable hash; Android execution hashes the pushed binary through `./dev/adb`.
Rows preserve raw timings, full-result signatures, selected plans, masks/entries,
condition counts, allocated coexistence and address-space high-water. Alternating
row order reduces ordering bias but does not control frequency, thermal state or
background load. No formal performance/power gate is claimed.

Median query nanoseconds per call (includes identical harness signature work):

| Shape / effective rules | x86-64 default / factors / residual | ARM64 default / factors / residual |
| --- | ---: | ---: |
| 16-entry pair / 1 | 267.6 / 102.3 / 103.9 | 604.4 / 256.7 / 216.3 |
| 16-entry pair / 128 | 392.0 / 118.1 / 117.6 | 691.1 / 255.5 / 261.2 |
| 32-entry pair / 128 | 654.8 / 122.0 / 120.9 | 1,035.2 / 264.4 / 255.9 |
| 900-entry potential pair + CT / 128 | 997.8 / 997.0 / 1,055.8 | 2,113.5 / 1,997.8 / 1,324.3 |
| Large ranges + negated CT / 128 | 822.2 / 826.8 / 818.0 | 1,728.2 / 1,722.4 / 1,795.7 |

“Default” is the compiler's mixed plan under the 32/256 limits. The 900-entry
potential pair is factored, and negated CT retains the residual path in all
variants. Direct expansion often costs more on these sparse/miss-heavy inputs:
for the 32-entry pair with 128 rules it is about **5.42×** x86-64 and **4.05×**
ARM64 relative to residual. The ARM64 CT-factor case also regresses. These
results are retained, not turned into a generic optimization PASS. The 32-entry
pair at 128 rules takes **98.9 / 363.9 microseconds** per default compilation on
x86-64/ARM64, versus **65.4 / 264.2 microseconds** for residual. Budget-limited
factor alternatives remain complete and often cheaper; this bounded local scan
does not justify a new adaptive policy or change to the agreed starting default.
T09's separate 14.05× ARM64 many-mask result remains historical counter-evidence.

Fixed view storage is **55,320 bytes**, versus T09's 38,160: **17,160 bytes**
additional per view. The four materialized publication/preflight/bank views are
**221,280 bytes**. The compiler publication subtotal is **321,396 bytes** under
384 KiB; its compiler/query scratch bounds are **21,376 / 916 bytes**. The full
management representation overlap is **868,684 bytes** under 1 MiB, additionally
charging both existing worker-local empty views, saved/candidate source objects,
serialization, native request/status adaptation and bounded graph/frame/path
scratch. Fixed unused capacity is charged. Compiler `-fstack-usage` records are
retained; they support the fixed scratch reserves for these toolchains.

This storage accounting is separate from process memory. The isolated helper's
`/proc/self/status` address-space high-water ranges **1,652–1,816 KiB** on x86-64
and **3,488–4,000 KiB** on ARM64 while old/new views coexist. Real VPP's Linux
VmHWM is **356,400 KiB** (startup already established that high-water); Pixel
Root/VPN observed VmHWM reaches **98,644 / 98,896 KiB**. Process totals include
unrelated VPP/runtime memory and cannot isolate a short compilation allocation
peak. Existing stack reservation, API transport pools and allocator metadata
are not silently counted as policy representation bytes.

## Review and retained attempts

Independent Standards and Spec reviews report zero findings; final evidence
and harness follow-up is retained in `review-results.md` under the local index.
The full-suite pass includes the tiny VPP-shaped init harness updated with CLI
registration types for the new resource command. Its first run failed only
because those test types were missing; the source-bound real plugin had already
built and run successfully. A restricted sanitizer attempt failed because LSan
cannot operate under the sandbox tracer; unchanged tests pass outside it.

The first Android build attempted a missing historical `/tmp` stage default.
The successful build uses the existing `android-stage-b`, selected by matching
T09's stage manifest hash. Initial independent resource expectations were
corrected for same-mask sharing of the two-sided 1..65534 cover and VPN's retained
high source-port bit; no Product change or loosened resource bound was needed.
Initial `cost-host` / `cost-arm64` runs retain `getrusage` high-water that can
inherit the launcher footprint. Final `-b` runs use `/proc/self/status` and retain
both measurements; earlier runs are not the final memory evidence.

No new physical-network, IPv6-device, maximum-rule live traffic, LPI/SNI/cache,
power/thermal, long-expiry or public-release acceptance is claimed. No Product
source changed after the accepted builds.

```sh
rtk proxy python3 tests/host/product_static_reference_test.py
rtk proxy ctest --test-dir build-output/t10-20260925/host --output-on-failure
rtk proxy python3 tests/evidence/verify_t10_plans.py build-output/t10-20260925/linux-a
rtk proxy python3 tests/evidence/verify_t10_plans.py build-output/t10-20260925/pixel-a
rtk proxy python3 tests/evidence/test_t10_plan_negatives.py build-output/t10-20260925/linux-a
rtk proxy python3 tests/evidence/test_t10_plan_negatives.py build-output/t10-20260925/pixel-a
rtk proxy python3 tests/evidence/t10_plan_cost.py summary build-output/t10-20260925/cost-host-b
rtk proxy python3 tests/evidence/t10_plan_cost.py summary build-output/t10-20260925/cost-arm64-b
```
