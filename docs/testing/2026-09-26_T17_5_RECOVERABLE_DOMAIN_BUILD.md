# T17.5 recoverable domain compilation

Date: 2026-09-26. Decision task:
[SAKAMOTO-287](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/4d89d5d5-e976-45a1-a792-3b2a8f8f9aaf).
User decision, 2026-09-26: **“采用 rax 吧”**. The user accepted the recommendation
after reviewing T17/T17.5 results. T17.5's experiment → user-selection gate is
satisfied; T17's corresponding record is maintained by its own task owner.
Product integration remains T18, subject to its remaining task dependencies.

**Reject the existing VPP hash domain backend under the user's KISS constraint.
Select unmodified pinned Valkey rax with a small explicit recoverable VPP
allocator binding.** The VPP-native C architecture remains unchanged. This
route needs no new allocator, process, IPC, reserved capacity, hash/vec patch,
or Product backend selector. It does not establish recovery for unrelated
allocations elsewhere in the Product compiler.

## Decision and alternatives

| Route | Failure mechanism and cost | Finding |
| --- | --- | --- |
| Unmodified rax + explicit VPP allocation | `_or_null` allocation; checked allocate/copy/free growth; matching size/free. Retains library implementation and adds a small local allocator contract. Extra copying and temporary node coexistence are measured. | Selected by the user: Host and physical ARM64 recover after injected failures and real heap exhaustion. |
| Build a sorted immutable key array | Checked owned storage and sort workspace, then allocation-free binary search at each label suffix. A custom allocation-free sort is another option. | Plausibly compliant, materially different representation, but rejected as the first choice: owns new sorting/search/membership validation code and has no measured ARM64 advantage. It was not implemented or benchmarked here. |
| Existing VPP string hash | Hash creation, collision vectors, growth and resize use unchecked/fatal hash/vec allocation paths. | Rejected: changing a single allocation call cannot supply complete failure propagation and cleanup. T17 already reproduced process termination. |

The [source investigation](../reviews/2026-09-26_T17_5_RECOVERABLE_DOMAIN_ROUTES.md)
documents pins, licenses, exact paths and integration costs. The immutable-array
route is a design comparison, not a fabricated passing experiment or an accepted
fallback. Isolation/IPC would add architecture without solving a remaining need;
it was not prototyped. Pre-sizing and larger heaps are not recovery mechanisms.
libdatrie remains rejected on T17's reproduced unchecked allocation failure and
build cost; those results are reused, not retested or hidden.

## What changed in the allocator experiment

T17's standalone rax used ordinary libc allocation. Here the same unchanged
`rax.c/h` pin `05a9c29c62538519d870d6512978f80ac58a758f` is linked with the actual
Host/Android VPP stage at pin `9258530f3804a152578ce11cc7c8a1e9eab88ed0`.
The two stages export `malloc`, `calloc`, `realloc`, `free` and
`malloc_usable_size`; the new binaries import explicit `clib_mem_alloc_or_null`,
`clib_mem_size`, and `clib_mem_free` instead. Retained symbol tables prove those
actual artifacts, rather than assuming libc symbol names establish ownership.

Allocation returns NULL/ENOMEM. Reallocation first allocates new storage, leaves
the old pointer valid on failure, and copies/frees only after success. NULL free
and usable-size calls are guarded. Native VPP realloc is deliberately not used:
its replacement allocation can panic. Upstream rax's creation and insertion
failures return to the builder; its recursive destruction does not allocate.
This is ordinary fallible allocation, not a pre-reservation scheme. The current
VPP heap must remain the matching allocator for construction and destruction;
the experiment performs both on one thread. Product heap/lifetime ownership is
an integration obligation, not a global allocator-toggle proposal.

## Recovery and semantic evidence

The [plan](../../experiments/t17-5-recovery/PLAN.md) preceded native runs; a dated
addition explains the later bounded 100k fault sample. The
[replay harness](../../experiments/t17-5-recovery/README.md) contains no Product
code changes. Final evidence uses Host `host-d-runs`, ARM64 `android-e-runs`, and
focused sanitizer `sanitize-d-runs` under `build-output/t17-5-20260926`.

Each old snapshot owns its payload/name array and rax nodes. A candidate owns a
different copied array and nodes. New masks shift every list identity by one,
so successful publication has independently observable changed results. The
Python oracle uses label tuples and sets; the new oracle shifts the set's list
identities independently of the native bit operation. Exact/descendant union,
case, label boundaries, invalid names and all memberships retain T17 semantics.

Host and ARM64 each passed **16/16 final native cases**:

- Nine cost runs: three repetitions of each 100k shared/high-entropy/deep-long
  distribution, plus one 67-entry edge cost run with 127 labels, 253 bytes and
  all 64 memberships.
- Every allocation ordinal in the 33-entry shared builder (186) and 67-entry
  edge builder (213), plus continuous failure and pre-publication rejection in
  each. All 403 attempts rejected normally; no optional failure was tolerated
  in these measured cases.
- Three 100k fault runs, each covering ordinals 1–5, 50, 500, midpoint, last,
  continuous failure from ordinal 5, and pre-publication rejection. All 33
  attempts rejected normally. This is a bounded sample, not an exhaustive
  sweep of the 502k–580k allocation calls in these larger builds.
- A real 64 KiB VPP heap exhaustion run, without injected NULLs. With an old
  snapshot already active, the larger candidate exhausted the heap after 119
  successful insertions, returned ENOMEM, reclaimed its partial build, preserved
  old identity/results, then successfully published a fitting corrected version.
  The small heap is a failure trigger, not a proposed Product capacity guarantee.

On every failed attempt, saved version advances before construction while the
active pointer/version remain old; all old oracle queries still match. Adapter
live allocation count and usable bytes return exactly to the old baseline.
After the failure series, the same process builds successfully and publishes
the entire changed snapshot; old results remain valid until explicit retirement.
All adapter allocations are freed at the end. Creation/payload copy/tree root,
insert/growth and pre-publication boundaries are covered. This route has no
conversion, relocation or load step to inject.

The saved/active sequence is a **component model**, not real configuration-file
I/O or a Product control/API test. It preserves the agreed save-before-compile
contract rather than substituting atomic saving. Publication is single-threaded;
worker barriers, delayed readers and complete policy snapshots require T18's
real integration. Healthy management service behavior during whole-compiler OOM
is not established by this isolated component.

## Costs and memory interpretation

The [full normal-run CSV](2026-09-26_T17_5_RECOVERABLE_DOMAIN_BUILD.csv) retains
every final measurement. ARM64 is Pixel 6a, NDK r29/API31, `-O2`, actual linked
VPP library, native fresh processes. No affinity/frequency pinning, concurrent
packet readers, IPC or wakeup pipeline. Host uses GCC on the same T17 machine.
Query cost includes normalization, all label probes and membership aggregation;
sample p99 includes clock calls and is not a packet-path p99.

The final table is generated from the accepted raw series below. No numeric
performance gate was invented, and a limited mobile microbenchmark is not an
energy, thermal or end-to-end protection claim.

| Distribution | Old/new build ms | Batch ns/query | Sample p99 ns | Max failed-build cleanup ms | Max failed attempt ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| shared | 41.28 / 42.05 | 308 | 1302 | 10.84 | 45.95 |
| entropy | 37.05 / 37.88 | 357 | 1221 | 11.08 | 40.63 |
| deep | 51.18 / 52.56 | 2551 | 4231 | 10.15 | 55.74 |

| Distribution | Old/new coexist usable MiB | Transient peak usable MiB | Active usable MiB | Input RSS MiB | Coexist / after-retire RSS MiB | Process peak MiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| shared | 64.70 | 64.70 | 32.35 | 54.51 | 123.09 / 123.09 | 123.09 |
| entropy | 67.93 | 67.93 | 33.97 | 54.52 | 125.67 / 125.67 | 125.93 |
| deep | 64.13 | 64.13 | 32.07 | 54.38 | 121.92 / 121.92 | 122.18 |

Normal columns are medians of three fresh processes. Failure columns are maxima
among eleven targeted attempts in one process per distribution, including a
fully built candidate rejected before publication; they are observed costs, not
worst-case guarantees. Actual heap exhaustion returned in 0.147 ms including
0.024 ms cleanup, then retry succeeded. Old-snapshot retirement medians were
11.87–16.67 ms. The final series battery-temperature observations are retained
with the raw device environment; no power measurement was performed.

Each 100001-entry snapshot deliberately uses T17's simple 272-byte `Entry`
layout: about 25.94 MiB of owned names/masks before trie nodes. The original
input array and query fixtures remain resident during both builds. This raises
the total versus T17's index-only rebuild sharing one input/payload array.
Neither table estimates the complete Product source graph or full compiled
snapshot, and the RSS numbers are not a like-for-like regression comparison.

Usable-byte accounting covers all candidate snapshot, payload and node
allocations, including temporary realloc old/new storage. It excludes VPP heap
metadata, libc/stdio, executable pages and static input/query arrays. RSS covers
the whole process. VPP retains freed heap pages: active-only logical ownership
does not mean RSS immediately falls after old retirement. Usable sizes may also
differ with allocator placement despite equal requested payload sizes; the
verifier checks exact old-plus-new conservation, not assumed byte equality.

## Verification, limits and integration scope

All final binaries, VPP libraries, consumed source/header closures, archives,
commands, workload bytes, native run identities and raw outputs are retained.
The final ARM64 run checks device-side workload hashes as well as executable and
library hashes before running. Remote timeout and absence of the nonce-owned
process are checked before the next case; final deployment cleanup passed.
There was no APK, VPN/Root, KernelSU or Product configuration change.

Focused ASan/UBSan passed five Host cases, including both full small/edge failure
sweeps and actual exhaustion. VPP's prebuilt allocator is not instrumented and
custom heap allocations lack ordinary per-object ASan redzones. LSan remains
disabled for the known T17 environment limitation. The adapter's zero-live
ledger is scoped cleanup evidence, not a whole-process leak or exhaustive OOM
certificate. Heap corruption, kernel OOM kill, process termination and failure
in unrelated fatal allocation paths are outside this return-NULL contract.

The evidence verifier rejects ten mutations on Host and twelve on ARM64;
four wrong/malformed native fixtures and a modified copied rax source are also
rejected. Earlier `a/b/c/d` development evidence is retained, including the ADB
sandbox denial and an initial verifier assumption that usable sizes would be
identical. That assumption was corrected to allocation conservation; no native
failure was relabeled PASS. Only the explicitly named final series feeds this
report. The native source is identical between Android `d` and `e`; `e` adds
pre-run remote workload identity verification.

For the selected direction, T18 should add the pinned rax source/notices and a newly designed
local C binding, never import the experimental adapter. Integrate owned
name/payload lifetime with the existing VPP compiler/snapshot, retain exact and
descendant memberships and complete Rank, and test actual saved/active status,
all allocation/error diagnostics, partial cleanup, delayed readers, retirement,
cache invalidation and TCP/QUIC SNI consumer combinations. The allocator must
remain correctly paired across real runtime initialization and teardown.
There is no justification here for a generic multi-backend layer, library fork,
private trie walker or separate service.

The recorded user choice completes T17.5's decision requirement. It does not
convert this component evidence into Product acceptance or waive T18's real
integration and remaining dependencies.

## Standards

Independent review found no hard breaches or blocking correctness findings in
the 12 committed files since `1249cb6`. The experiment respects AGENTS.md and
ADR-0008: isolated C evidence, unchanged pinned rax, no Product integration or
removed-C++ reuse. Android operations use `dev/adb`. Documentation preserves
failed attempts, source identities, scope and limits; Plane remains the decision
authority. Read-only verification confirmed acceptance artifact hashes, all
three source closures, retained source/binary hashes, independent workload
expectations and raw records: Host 16/16, ARM64 16/16, sanitizer 5/5, with
403 small/edge plus 33 targeted attempts per native platform. Evidence mutations
were rejected: 10 Host, 12 ARM64, 10 sanitizer.

One optional **Primitive Obsession** heuristic concerns `recovery.c`'s schedule:
`{1,2,3,4,5,50,500,total/2,total,total+1,total+2}` also encodes continuous failure
and pre-publication modes. Named modes could make future extension clearer.
This is nonblocking for the fixed verified experiment; no generic framework is
warranted. Sanitizer and single-thread publication limits are accurately stated.

## Spec

Independent review found no missing experiment deliverable, scope creep or
wrong implementation within the component envelope. At review time, ticket §9's
required user selection was still pending; it is now recorded above. Actual file saving, management availability and
concurrent publication are explicitly untested Product integration, consistent
with §4's model/component distinction. The second route is acceptable under
§2's permission to reject by read-only analysis: its ownership, fallible workspace,
allocation-free search, algorithmic costs and maintenance burden are documented;
KISS rejection is a recommendation, not measured inferiority.

No hash/vec rewrite, reserve-based recovery, IPC, Product implementation or
premature selection appears. Native checks exercise creation/insertion failure,
continuous failure, pre-publication rejection, real exhaustion, unchanged old
identity/results, baseline allocation recovery and changed-snapshot retry.
Saved version advances before construction. Independent read-only verification
accepted Host 16/16, ARM64 16/16 and sanitizer 5/5 and matched all artifact hashes.
The evidence does not claim full Product recovery.

Review totals: Standards 0 hard findings and 1 optional readability heuristic;
Spec 0 findings. There is no outstanding experimental correctness blocker.
