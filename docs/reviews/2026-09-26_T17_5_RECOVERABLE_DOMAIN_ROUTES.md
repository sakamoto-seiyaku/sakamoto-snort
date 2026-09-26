# T17.5 recoverable domain-index routes

Date: 2026-09-26. Research only; no Product implementation or backend selection.
The [T17 report](../testing/2026-09-26_T17_DOMAIN_MATCHER.md) measures standalone
rax, libdatrie and VPP hash. It does not certify an allocator binding inside VPP.
[ADR-0009](../adr/0009-unified-rules-and-vpp-owned-configuration.md) requires
compilation failure to retain the active snapshot and management availability.
Ordinary allocation failure must therefore return to the compiler. A reserve,
larger heap, pool or budget is not that failure contract.

## Conclusion

The narrowest source-supported next experiment is **Valkey rax with an explicit
recoverable VPP allocator adapter**. Use `clib_mem_alloc_or_null`, a small
allocate/copy/free reallocation adapter, `clib_mem_size`, and matching free.
Do not use VPP's native realloc or assume calls named malloc are libc calls.
This needs no new allocator, subprocess, IPC, global allocator switch, or broad
VPP patch. It is a source-supported candidate, not a claim that the complete
configuration compiler already recovers.

A **sorted immutable array plus owned name storage** is a materially different
build/read-only route. It can make the allocation surface smaller, but is custom
Product work, has not been benchmarked here, and has no demonstrated advantage
over rax. Existing VPP hash has no comparably narrow recoverable builder route.

## Pins, provenance and maintenance

| Route | Exact source/API | License and maintenance cost |
| --- | --- | --- |
| rax | Valkey `05a9c29c62538519d870d6512978f80ac58a758f`, `src/rax.c`, `rax.h`; `raxNew`, `raxInsert`, `raxFind`, `raxFree`; compile-time `RAX_MALLOC_INCLUDE` | BSD three-clause file notices must accompany copied source/distribution. Two source/header files plus explicit allocator/assertion integration; no Valkey server. Retain pin and review upstream changes in consumed files. This review does not assert current upstream activity from a historical pin. |
| VPP hash | FD.io VPP `9258530f3804a152578ce11cc7c8a1e9eab88ed0`, `src/vppinfra/hash.c/h`, vec and allocator dependencies | hash files carry Apache-2.0 OR MIT; supporting files have their own notices. Already present in Product, but making its mutating paths recoverable expands the maintained patch surface beyond this task. |
| Sorted immutable array | Proposed new C representation, no implementation or external pin | Repository-maintained comparator, checked builder, ownership and lookup semantics. No additional third-party library notice; all correctness/performance maintenance belongs to this repository. |

Sources: [rax source and notice](https://github.com/valkey-io/valkey/blob/05a9c29c62538519d870d6512978f80ac58a758f/src/rax.c),
[rax allocator selection](https://github.com/valkey-io/valkey/blob/05a9c29c62538519d870d6512978f80ac58a758f/src/rax_malloc.h),
[VPP hash](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vppinfra/hash.c).
Actual local reads used `build-output/t17-20260926/host-b/rax.c`, the retained
Valkey archive extraction, and `build-output/pinned-vpp-clean/src/vppinfra/`.
T17's [manifest](../../experiments/t17-domain-matcher/sources.json) and per-build
source closure bind the experiment, not a future Product build. Online opens of
the immutable GitHub pages returned cache misses during this research; claims
above and below come from the actual local source copies, with immutable
upstream links for reproduction.

## Explicit allocator binding and failure contract

At the VPP pin, `mem_dlmalloc.c:362–383` calls `mspace_memalign` and returns NULL
when its `os_out_of_memory_on_failure` argument is zero. The exported
`clib_mem_alloc_or_null` and `clib_mem_heap_alloc_or_null` select zero. The
underlying `dlmalloc.c:4660` dispatches to `mspace_malloc` or
`internal_memalign`; normal exhausted `sys_alloc` ends at lines 2848–2849 with
`MALLOC_FAILURE_ACTION; return 0`. On Linux/Android the default action in
`dlmalloc.h:668–670` sets `errno = ENOMEM`. Invalid heap metadata can still take
allocator corruption assertions; this is a contract for ordinary allocation
failure on a valid initialized heap, not arbitrary memory corruption.
[Allocator implementation](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vppinfra/mem_dlmalloc.c),
[mspace implementation](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vppinfra/dlmalloc.c),
[allocator defaults](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vppinfra/dlmalloc.h).

In contrast, `clib_mem_heap_realloc_aligned` allocates its replacement through
`clib_mem_heap_alloc_inline(..., 1)` at line 468. Both ordinary and heap-specific
realloc wrappers reach that implementation. The failure hook
`unix-misc.c:232` calls `os_panic`. Merely replacing rax malloc while retaining
VPP realloc does not fix failure recovery.
[Failure hook](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vppinfra/unix-misc.c).

The narrow adapter contract is:

1. Allocate with the explicit `_or_null` API; report NULL/ENOMEM.
2. For realloc, allocate new storage first, return NULL without modifying or
   freeing the old allocation on failure, copy at most the lesser of old usable
   size and requested size on success, then free old storage. Handle NULL and
   zero-size semantics explicitly. This costs extra copies and temporary
   old-plus-new node storage compared with successful in-place realloc.
3. Size and free must belong to that same allocator/heap. `clib_mem_size` calls
   `mspace_usable_size`; the latter returns zero for NULL (`dlmalloc.c:4810`).
   Keep an explicit NULL guard anyway: `raxNew` asks for head usable size before
   checking whether head allocation failed (`rax.c:195`). Guard free(NULL):
   `clib_mem_heap_free` asserts heap membership before calling mspace free.
4. The current-heap functions require construction and eventual destruction to
   run with the correct heap selected. Heap-specific `_or_null` and free calls
   can bind the intended heap explicitly if necessary; rax's macro interface
   has no per-tree allocator context, so do not silently invent concurrent
   global context switching. Keep this ownership decision local to the compiler.

These are adapter requirements derived from the pinned APIs, not imported POC
code. No reserved arena is necessary to the recovery property: actual allocator
exhaustion must return through the same NULL path.

### Why plain malloc is not a safe embedding assumption

`mem_intercept.c` exports `malloc`, `calloc`, `realloc`, `free` and
`malloc_usable_size` when compiled with `VPP_ALLOC_FREE_INTERCEPT`
(`CMakeLists.txt:127`). With interception enabled at runtime, malloc uses
`clib_mem_alloc_aligned_or_null`, but realloc of an existing pointer uses
`clib_mem_realloc_aligned`, including its fatal fallback. Free dispatches using
the global intercept state, not pointer provenance. Allocations cannot safely
cross different allocator states by assumption.
[Interposition source](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vppinfra/mem_intercept.c),
[build inclusion](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vppinfra/CMakeLists.txt).

The pin also contains a source-level defect in intercept-disabled
`malloc_usable_size`: it returns through a static initially NULL function
pointer before its `dlsym` initialization statement. This makes simply toggling
interception off an especially poor proposed fix. Actual symbol binding is
build/load dependent; inspect exports and execute the linked integration probe.
An explicit allocator quartet avoids both symbol ambiguity and that branch.
An explicitly resolved libc quartet could also work in principle, but introduces
Linux/Android loader and handle-lifetime obligations. `__libc_malloc` is a glibc
detail, not an Android solution; `RTLD_NEXT` depends on link-map position. It is
not the simplest route when existing `_or_null` APIs suffice.

## rax builder, query and cleanup

`raxNew` returns NULL on either initial allocation failure. `raxInsert` returns
zero both for overwrite and OOM, so check its documented errno distinction,
not only the integer return. `raxGenericInsert` contains explicit partial-tree
OOM cleanup at lines 879–893. `raxFree` recursively traverses and frees nodes
(`rax.c:1219–1249`) without allocating; a user payload callback must separately
honor its own cleanup contract. Public `raxFind` calls the low-level walk with
no stack and does not allocate in the audited path. Use it at every required
label boundary and union memberships; do not introduce a private ancestor
walker or first-match shortcut. All findings refer to the
[pinned rax implementation](https://github.com/valkey-io/valkey/blob/05a9c29c62538519d870d6512978f80ac58a758f/src/rax.c).

The T17 four-failure injection result is positive bounded evidence, not proof
for every insertion shape, every allocation position, sustained exhaustion,
creation, publication or full compiler failure. The next linked probe must
cover those relevant boundaries, ensure a previously published index remains
queryable, and verify failed-builder cleanup. Payload/name ownership and
diagnostic construction must also avoid fatal allocation paths.

## Materially different route: sorted immutable array

This is a proposed design, not an experiment result. Count and validate input,
check size arithmetic, allocate owned entry/name storage using recoverable
calls, sort canonical names, union duplicate exact/descendant membership masks,
and publish only the complete array. Query uses binary search for the full name
and every proper label-boundary suffix, unioning both masks for the full name
and descendant masks only for proper ancestors. This preserves T17 semantics
without requiring a trie or hash table. Use the same invalid-input distinction.

For N entries and D suffix probes, the lookup has O(D log N) comparisons;
comparison cost additionally depends on name length. A comparison sort takes
O(N log N) comparisons. Packed names could reduce per-node overhead, but total
memory includes names, masks, entry metadata, source model, sort workspace and
simultaneously live snapshots. Neither memory savings nor acceptable ARM64
latency has been measured. Do not present either as a result.

Sorting is part of the failure audit: an unexamined library sort may allocate
internally. A deliberately allocation-free in-place heapsort, or a sort with
explicit checked workspace allocated before mutation, makes the contract
reviewable at the cost of owned algorithm code. Binary search itself can be a
small allocation-free loop. All partial construction is discarded on failure;
old snapshot remains untouched. Name storage must outlive workers and cannot
borrow a temporary compiler input buffer.

This route trades upstream trie maintenance and many node allocation sites for
custom sorting/search code and potentially greater query work. It needs its own
oracle/edge tests, failure injection, ARM64 performance and full snapshot peak
measurement before selection. It is not a benchmark-equivalent fallback.

## Why not patch existing VPP hash for this task

The pinned `_hash_create` allocates a vector at `hash.c:531`, immediately uses
its header, then allocates the occupancy bitmap with `vec_validate_aligned`.
Collisions allocate vectors or raw memory at lines 208/212; extension uses
`vec_add2` or fatal realloc at 245/256. `_hash_set3` may resize after mutating
the table; resize constructs and repopulates another table before freeing the
old one. `vec.c:35,94` calls fatal allocation/reallocation APIs. Thus changing
one allocator to return NULL leaves unchecked uses and partial-mutation
semantics throughout the stack. Public GET is allocation-free, but the builder
does not expose an adequate recoverable failure protocol.
[Hash implementation](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vppinfra/hash.c),
[vector implementation](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vppinfra/vec.c).

Pre-sizing, disabling automatic growth or checking a budget does not remove
collision allocation and does not turn real allocation failure into a returned
error. A recoverable hash/vec rewrite or out-of-process builder would impose
precisely the wider maintenance or IPC cost excluded from this decision.
Therefore reject the unmodified VPP hash builder on the required failure
contract, while retaining its T17 normal-path measurements as comparison data.
