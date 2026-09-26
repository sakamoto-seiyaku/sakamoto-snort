# T17 ARM64 domain matcher comparison

Date: 2026-09-26. Decision task: [SAKAMOTO-268](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/063537dd-410c-44e9-9ec1-dcfdbf5b26eb).
This report supplies the experiment and the user's recorded selection below.
T17's selection gate is satisfied; Plane records task closure. T18 still follows
its complete dependency set, including T17.5's separate closure record.

## User selection — 2026-09-26

After reviewing T17 and the additional
[T17.5 recovery experiment](2026-09-26_T17_5_RECOVERABLE_DOMAIN_BUILD.md), the user
explicitly chose: **“采用 rax 吧”**.

The selected direction is unmodified Valkey rax at
`05a9c29c62538519d870d6512978f80ac58a758f`, with a small explicit binding to VPP's
fallible allocation APIs. T17.5's evidence at commit
`453ed2dad5a3a230ff55b27b240d0c0aaccb951e` validates checked allocate/copy/free
growth, paired size/free operations, old-snapshot preservation, cleanup and retry
on Host and physical ARM64, including actual heap exhaustion. It resolves the
standalone allocator integration question left by this original experiment.

This choice does not adopt the existing VPP hash backend, modify hash/vec,
reserve capacity as a recovery guarantee, or introduce a new allocator, process,
IPC or backend selector. It preserves VPP configuration ownership and the fixed
domain/rule semantics. T18 must implement its own narrow Product binding and
validate real saved/active state, complete snapshots, readers/retirement and
TLS/QUIC consumer integration. Experimental code is not Product source; the
component results do not prove recovery for unrelated compiler allocations.

**Recommend maintained Valkey rax for the measured first-version envelope.**
It built 100k dictionaries in 43–50 ms on this Pixel and returned recoverable
errors at all four injected allocation-failure points on both platforms. Its
query and retained-memory costs exceed VPP hash in several workloads. That is a
real tradeoff: VPP hash was a strong normal-path baseline, but its exhausted
private heap terminated the process; libdatrie had both long builds and a
reproduced allocation-failure memory error. Preserving an active configuration
when compilation fails matters more here than selecting the best throughput
column. These bounded probes are not exhaustive OOM certification.

## Fixed scope and provenance

The [pre-run plan](../../experiments/t17-domain-matcher/PLAN.md) was written before
candidate execution. The [replay instructions](../../experiments/t17-domain-matcher/README.md)
and [source manifest](../../experiments/t17-domain-matcher/sources.json) accompany
the experiment. No Product source, dependency declaration or configuration ABI
was changed. Experimental adapters must not be imported into Product.

| Candidate | Bound source | Notice and dependency cost |
| --- | --- | --- |
| libdatrie | [665edc5e](https://github.com/tlwg/libdatrie/tree/665edc5ec1639a81df004d4f92f07a73d5b96aba), seven C compilation units | LGPL-2.1-or-later notices; public AlphaMap/TrieState API; library source compiled directly, without CLI/iconv tools |
| Valkey rax | [05a9c29c](https://github.com/valkey-io/valkey/tree/05a9c29c62538519d870d6512978f80ac58a758f/src), rax.c/h | BSD-3-Clause-style file notices; libc allocator/usable-size and assertion adapters; libc/libm, no Valkey server runtime |
| VPP string hash | [9258530f](https://github.com/FDio/vpp/tree/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vppinfra), current verified Product stages | hash.c/h carry Apache-2.0 OR MIT; supporting VPP files retain their own notices. Existing Product vppinfra, no new Product library |

Knot QP was not measured. The required three candidates yielded a viable
direction; adding another implementation did not resolve a remaining selection
question. It remains an optional future comparison, not an implied fallback.

The actual extracted libdatrie C/headers and copied rax files were compared
byte-for-byte with retained immutable archive members. Each platform's
`source-closure.json` also binds installed VPP headers, shared library and stage
manifest. The initial runs gained that verification after review; the final
replay builder performs it before compilation. Binary hashes were checked on
the device and independently against build records. Neither a revision label
nor an archive hash alone is treated as proof of consumed source.

Android used a physical Pixel 6a, arm64-v8a, NDK 29.0.14206865/API31 Clang,
`-O2`, and the existing `android-stage-b`. Linux used GCC on an AMD Ryzen 5 5600
and `host-stage-b`. Full compiler strings, commands, kernel/build fingerprint
and library hashes are local evidence. No emulator result substitutes for
ARM64. Device selector is not published here.

Runs were single-threaded, in fresh native processes, with immutable dictionaries
and no IPC/wakeup pipeline, concurrent mutation, policy cache or packet capture.
Candidate order rotated across three repetitions. CPU affinity/frequency were
not forced. Battery temperature rose from 30.5°C to 34.6°C during the Android
series; this is a recorded environmental change, not an energy or CPU thermal
measurement. Absolute numbers are not a phone-wide latency SLO.

## Semantics and correctness

Each canonical name has distinct exact and descendant 64-bit list-membership
masks. Full-name lookup includes both; proper label-boundary ancestors include
descendants only. Results union every applicable list, with no longest-name,
whitelist or action priority. ASCII case folds; import fixtures normalize one
trailing dot. Query fixtures follow the plan's strict hostname subset, including
already-converted A-labels, and reject trailing dots, URLs, glob syntax, invalid
labels, non-ASCII, embedded NUL and excessive lengths. Invalid is a separate
status, not a policy NoMatch or confirmed-no-SNI result.

libdatrie walks reversed bytes with one reusable public cursor. Rax uses public
exact lookups on reversed label prefixes. VPP hash probes suffix views of the
normalized name. No candidate uses a custom private ancestor walker, probabilistic
fingerprint result, regex engine or early first-match shortcut.

The independent Python oracle works on label tuples and sets of list identities.
All 81/81 normal runs passed on Linux and 81/81 on ARM64, each checking 25,020
results before timed batches. Three additional runs per platform passed 1,138
edge queries covering 127 labels, 253 bytes, all 64 memberships simultaneously,
case/label-boundary near misses and every ASCII leading byte. This is 2,030,034
oracle comparisons per platform. Three hand-authored oracle tests passed.

Focused ASan/UBSan normal-path checks passed for all three adapters on the small
shared and edge workloads (78,474 comparisons). Static libdatrie/rax source is
instrumented; prebuilt vppinfra is not. LeakSanitizer was disabled after its
ptrace/sandbox fatal error, which remains retained. No leak-free claim follows.
Nine native malformed-input/wrong-oracle cases were rejected, nine mutated
evidence records per platform were rejected, and a modified rax source copy was rejected by
the archive verifier.

Wrapped malloc/calloc/realloc query counts were zero. This instrumentation covers
the executable/static candidates, not VPP's shared-library private heap. The
[pinned source audit](../../experiments/t17-domain-matcher/README.md#query-allocation-source-audit)
separately establishes no allocating branch in VPP GET; it also checks the
libdatrie cursor and rax exact paths. Do not generalize this to other APIs or
future library versions.

## ARM64 measurements

The complete [54-row CSV](2026-09-26_T17_DOMAIN_MATCHER.csv) records medians and
min/max across all 1k/10k/100k × shared-suffix/high-entropy/deep-long workloads
on both platforms. Canonical counts are requested size + 1 after the fixed
overlap fixture. Table below gives 100k medians across three fresh processes.
Batch cost includes normalization and all ancestor aggregation. Per-query p99
also includes two clock reads; it is not a packet-path p99.

| Distribution | Candidate | First build ms | Batch ns/query | Sample p99 ns | One-index RSS Δ MiB | Two-index RSS Δ MiB | After-old-free RSS Δ MiB | Process peak MiB |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Shared suffix | libdatrie | 34534.8 | 257.2 | 977 | 6.535 | 12.379 | 9.098 | 67.992 |
| Shared suffix | rax | 46.2 | 370.1 | 1586 | 9.102 | 17.449 | 18.590 | 72.754 |
| Shared suffix | VPP hash | 49.6 | 301.0 | 1018 | 8.504 | 14.434 | 14.434 | 74.035 |
| High entropy | libdatrie | 52479.4 | 304.9 | 1221 | 8.121 | 15.535 | 12.242 | 71.324 |
| High entropy | rax | 42.9 | 392.1 | 1465 | 12.688 | 23.164 | 24.090 | 78.391 |
| High entropy | VPP hash | 52.7 | 370.0 | 1221 | 8.504 | 14.434 | 14.434 | 74.039 |
| Deep/long | libdatrie | 50458.6 | 1598.7 | 2604 | 6.703 | 12.648 | 9.270 | 68.348 |
| Deep/long | rax | 49.9 | 2554.9 | 4313 | 10.102 | 17.070 | 18.027 | 72.242 |
| Deep/long | VPP hash | 76.7 | 1943.7 | 2766 | 8.504 | 14.434 | 14.434 | 74.043 |

RSS deltas subtract the process's post-input baseline. Input names/payloads,
queries and samples remain live. Two dictionaries are a same-source index
rebuild sharing that immutable input/payload array; this is not the full peak of
two different Product configuration graphs. VPP hash borrows input name storage;
rax/libdatrie copy encoded keys. Source layout reserves 272 bytes per entry on
LP64, rather than a packed Product string arena. Do not quote the delta as
isolated dictionary bytes, or omit shared names/payloads from a future budget.
Allocator retention can make after-free RSS exceed the prior sample, especially
with Android rax. Process peak includes those effects and runtime overhead.
The linked VPP library also exports calloc and eagerly zeroes the harness's
fixed-capacity arrays; its post-input baseline therefore materializes pages
that libc may leave untouched in the other executables. Total RSS is a process
measurement, not an isolated or allocator-neutral dictionary comparison.
VPP reserves a 256 MiB virtual arena; resident pages, not that reservation, appear
in RSS. Product integration must use its actual allocator/snapshot budget.

Android benchmark ELF text sizes were 29,231 bytes (libdatrie), 24,618 (rax), and
6,999 (VPP adapter), including the common harness. Unstripped files were 147,576,
104,608 and 33,000 bytes. VPP additionally links the existing 466,920-byte
libvppinfra.so. Single local NDK compile/link wall times were 0.500/0.340/0.217 s;
these are recorded build costs, not a statistically ranked compile benchmark.

## Builder failure experiment and diagnosis

After normal-path measurements, a separate small native probe tested builder
failure because the accepted configuration contract retains the old active
snapshot on compilation failure. It does not alter the timed benchmark binary
or substitute failure-path time for normal measurements.

The probe creates a valid seed, then injects one libc allocation failure at
allocation 1, 5, 50 or 500 during insertion. It checks the seed and destroys the
builder when control returns. For VPP's separate allocator, a 64 KiB private
arena is exhausted instead; that is a different fault mechanism, not an equal
allocation-number comparison. Each probe is an isolated process with core dumps
disabled and bounded runtime. No Product process is fault-injected.

| Candidate | Linux | Android ARM64 | Interpretation |
| --- | --- | --- | --- |
| libdatrie | #1/#5 return failure; #50 returns without error; #500 reproducible SIGABRT/heap damage | #1/#5 return failure; #50/#500 exit134 | Cannot claim recoverable build failure for the unmodified pin |
| Valkey rax | Four injected failures return failure and preserve seed | Same four failures return failure and preserve seed | Positive bounded evidence for controlled compiler rejection; not exhaustive allocator-failure coverage |
| VPP hash | Seed initialized, exhausted arena aborts | Seed initialized, exhausted arena exits134 | Default hash/vec allocation path is not a recoverable compile error |

Uninjected libdatrie and rax controls pass. Host ASan localizes libdatrie #500
to `tail_set_data` (`tail.c:475`): `trie_branch_in_branch` (`trie.c:536–538`)
does not check `tail_add_suffix`'s error result before using it as a tail index.
The allocator wrapper returns NULL with ENOMEM while leaving the previous
realloc allocation intact. Repeated Host reproduction, ASan and ARM64 failure
exclude a mere benchmark checksum error. No upstream patch was applied; this
report assesses the bound source. The initial ASan probe source is retained and
its hash matches the original build record.

VPP's source route through hash growth, vec allocation and
`clib_mem_heap_alloc_aligned` invokes `os_out_of_memory` on exhaustion. A
preflight size estimate alone does not make that path recoverable. Choosing
VPP hash for Product would require a separately validated failure strategy;
it is not recommended here solely because it is already available.

## Product handoff and interpretation

Rax is recommended with its measured cost, not described as the fastest or
smallest. At 100k it costs about 6–31% more batch query time than VPP hash in
these distributions, while avoiding the observed unmodified-builder failure
behavior. Preserve upstream file notices and pin; maintain explicit small
allocator/assertion integration. Public exact lookup at label boundaries is
the measured algorithm. A custom one-pass walker needs separate evidence.

T18 must implement its own narrow Product C module after the user chooses:

- Main-thread compilation owns construction and recoverable failure; workers
  borrow a published immutable snapshot with per-owner scratch and no shared
  mutable cursor. Keep old snapshot lifetime until readers finish.
- Preserve exact/descendant modes and all list memberships. The rule engine
  retains full Rank, availability/negation and whole-rule TLS/QUIC applicability;
  this matcher does not decide ALLOW/DROP or fabricate confirmed absence.
- Keep cache guards bound to the full relevant snapshot/SNI facts. Consume actual
  T14 TCP split/reordered and T16 QUIC split/reordered/coalesced names in T18's
  real Root/VPN tests; this experiment sends no product traffic.
- Bound names, entries, membership payload and compiler allocation work. Validate
  the chosen allocator's recoverable failure and complete old/new configuration
  peak at the Product seam. More than 100k entries, more than 64 lists, different
  payload/source layout, concurrent workers, Unicode conversion, persistence,
  adversarial collisions and real-list/population distributions require added
  measurements and reassessment. No multi-backend switch is proposed.
- Use an explicit allocator/usable-size pair when embedding rax in VPP; the
  standalone libc adapter does not prove behavior under VPP symbol interposition.

## Evidence, failures and review

Local root: `build-output/t17-20260926/`; machine index:
`acceptance-index.json`. Normal accepted series are `host-b-runs` and
`android-c-runs-2`; edge series are `host-edges`/`android-edges`; focused normal
sanitizers are `sanitize-c-no-lsan`/`sanitize-edges`. Builder failure evidence is
`host-builder-failure-b`/`android-builder-failure-b`, with
`datrie-failure-diagnosis.json`. `verification.json`, `failures-host.json`,
`source-negative.json`, per-build `source-closure.json` and `binary-cost.json`
bind the evidence and rejection checks.

Retained earlier failures: missing libm in first rax link, unsupported separate
Android libpthread link, sandbox-denied ADB server connection, and LeakSanitizer
ptrace failure. Compiler warnings from upstream rax removal code and installed
VPP headers remain in logs; the experiment does not call raxRemove. No failed
attempt is counted as a successful candidate measurement.

Independent Standards and Spec review identified consumed-source verification
and remote timeout/exit handling gaps. Source closure now verifies archive
members and runtime library identity; altered-source rejection was tested.
Replay now uses a device-side timeout and stops on uncertain transport state,
with explicit process-exit checks exercised by the edge/failure series. All 81
original device cost runs exited normally; none depended on the deficient
timeout path. The original runner is retained with its matching recorded hash.
Final reviewer dispositions are recorded in the evidence index and Plane.

The explicit user selection above completes T17's decision requirement, rather
than treating a normal benchmark PASS as approval. T17.5's execution owner
records its own closure; T18 may start only when its complete dependencies are
satisfied. No Product implementation was performed as part of this decision record.
