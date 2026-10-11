# C radix candidates for Sakamoto domain predicates

Date: 2026-09-15. Bounded primary-source review; no implementation, dependency import, or new benchmark. Required workload is exact host plus apex-and-subdomains membership on personal/mobile endpoints. List formats are intentionally outside this note.

Durable supporting evidence for the [consolidated candidate assessment](2026-09-15_DOMAIN_MATCHER_RESEARCH.md) and [discussion record](2026-09-14_RULE_ENGINE_DISCUSSION_TMP.md). Candidate recommendations remain provisional; final selection requires measurements on the target device.

## Assessment

**Keep maintained Valkey rax as the stronger C radix candidate; treat old standalone rax as provenance, not the maintained code version. Armon libart is a small speed-oriented baseline, but it is a weaker direct dependency fit because it retains full keys per leaf, lacks graceful allocation-failure handling, and has no public ancestor query.** This is an integration assessment, not a measured claim that rax wins on Sakamoto traffic.

All candidates can support immutable shared dictionaries with owner-local query state. None supplies rule ranking, domain normalization, exact-versus-descendant policy metadata, or safe snapshot publication/reclamation for the application.

## Pinned source identities

| Candidate | Inspected revision | Status relevant to selection |
|---|---|---|
| [antirez/rax](https://github.com/antirez/rax/commit/1927550cb218ec3c3dda8b39d82d1d019bf0476d) | `1927550cb218ec3c3dda8b39d82d1d019bf0476d` | Standalone default head observed; 2020-04-04 |
| [armon/libart](https://github.com/armon/libart/commit/301046804af165269e37da6725f5a4aec9ecc881) | `301046804af165269e37da6725f5a4aec9ecc881` | Default head observed; 2021-02-11 |
| [Valkey vendored rax](https://github.com/valkey-io/valkey/tree/05a9c29c62538519d870d6512978f80ac58a758f/src) | `05a9c29c62538519d870d6512978f80ac58a758f` | Maintained product repository, pinned unstable head; 2026-09-15 |
| [Redis vendored rax](https://github.com/redis/redis/tree/864780a68b1bb794082dcbbaf8306cb23df24893/src) | `864780a68b1bb794082dcbbaf8306cb23df24893` | Maintained product repository, pinned unstable head; 2026-09-14 |
| [tlwg/libdatrie](https://github.com/tlwg/libdatrie/commit/665edc5ec1639a81df004d4f92f07a73d5b96aba) | `665edc5ec1639a81df004d4f92f07a73d5b96aba` | Third compact C alternative; root agent investigates in depth |

Development-head inspection is not certification of a production release. These dates establish source recency, not correctness by themselves.

## rax: strong reusable core, ancestor adapter still needed

Rax is a C byte-key radix tree with compressed paths and packed, variable-sized nodes. It owns the inserted key bytes within nodes rather than keeping a full duplicate key in a separate leaf record. Terminal values are opaque pointers; a NULL-valued membership set can omit that pointer. That particular saving may disappear when Sakamoto stores per-terminal policy/provenance handles. The project documents fuzz and allocation-failure testing. [README](https://github.com/antirez/rax/blob/1927550cb218ec3c3dda8b39d82d1d019bf0476d/README.md).

`raxFind` performs a read-only exact traversal without heap allocation or query-key copying. Node accesses use memcpy for pointer values. With normal debug-disabled builds, frozen nodes/payloads and correctly published lifetime, concurrent exact readers need no per-query lock; this concurrency conclusion is source-derived, not a concurrent-update guarantee. [Exact lookup and traversal](https://github.com/antirez/rax/blob/1927550cb218ec3c3dda8b39d82d1d019bf0476d/rax.c#L459).

The public API offers exact lookup and lexicographic iteration, not a callback for every stored ancestor of a query. Reverse-domain encoding can exploit shared suffixes, but does not change that API limitation. Safe unmodified-library adaptation: exact-probe the full reversed name and each relevant label-boundary prefix; accept ancestor entries only when their policy includes descendants. This repeats root traversal. A single-pass all-ancestor walker is a small but real maintained adaptation, because the existing low-level walker is private and does not report each terminal. One lexicographic predecessor lookup is not a general substitute for ancestor matching. [Public API and terminal-node representation](https://github.com/antirez/rax/blob/1927550cb218ec3c3dda8b39d82d1d019bf0476d/rax.h#L98).

Iterators are not universally allocation-free: their default local key storage is 128 bytes and local ancestor stack holds 32 pointers; deeper/larger traversals can grow onto the heap. They can be reused, but are less attractive than exact lookup for a strict allocation-free packet path. There is no built-in serialized-image load/save or mmap API; the tree is a pointer graph constructed dynamically. [Iterator/public declarations](https://github.com/antirez/rax/blob/1927550cb218ec3c3dda8b39d82d1d019bf0476d/rax.h#L139).

ARM64: the core uses ordinary C byte operations and memcpy rather than architecture-required intrinsics. The original documents alignment-safe access. Native AArch64/NDK compilation and integration tests remain to be performed; none were run here. [Portability description](https://github.com/antirez/rax/blob/1927550cb218ec3c3dda8b39d82d1d019bf0476d/README.md).

### Do not freeze on the 2020 standalone copy

Valkey’s maintained descendant preserves a relatively small rax core, but adds size accounting, newer fixes, and `memchr` child-edge lookup. Its exact API now returns success separately from the value, removing the old reserved-pointer constraint. It includes `serverassert.h`; its allocator shim selects `zmalloc`, `zrealloc`, `zfree` and an allocated-size query. A standalone integration must supply small assertion/allocator adapters and keep its upstream patch provenance. It is therefore reusable source, not an already packaged independent library. The old antirez standalone package is easier to embed directly because its default allocator is libc and it is detached from the server; choosing it would require explicitly accepting or reconciling its older fix baseline. [Valkey rax.c](https://github.com/valkey-io/valkey/blob/05a9c29c62538519d870d6512978f80ac58a758f/src/rax.c#L33), [rax.h](https://github.com/valkey-io/valkey/blob/05a9c29c62538519d870d6512978f80ac58a758f/src/rax.h#L187), [allocator shim](https://github.com/valkey-io/valkey/blob/05a9c29c62538519d870d6512978f80ac58a758f/src/rax_malloc.h).

Concrete ongoing maintenance includes a 2025 oversized-key removal fix and the 2026 memchr change. These do not establish a domain-specific performance advantage, but refute treating standalone HEAD as equivalent to current production code. [Removal fix history](https://github.com/valkey-io/valkey/commit/d588bb3bee01), [memchr change](https://github.com/valkey-io/valkey/commit/c4db208e9b2c1d41b3a8c6db8a8b982df2dc11c0).

Redis has diverged further: fixed-length leaf inlining, find-link/insert-at interfaces, allocator-usable-size optimizations and iterative freeing. Some target fixed-length/sequential stream IDs rather than variable-length reversed domains. Its allocator/assertion integration is wider, and current file licenses differ from standalone/Valkey. [Redis public types/API](https://github.com/redis/redis/blob/864780a68b1bb794082dcbbaf8306cb23df24893/src/rax.h), [sequential-key optimization](https://github.com/redis/redis/commit/63d841c3ae8760668a33c41acd2255f61669fe85), [allocator shim](https://github.com/redis/redis/blob/864780a68b1bb794082dcbbaf8306cb23df24893/src/rax_malloc.h).

### Memory and benchmark evidence

For standalone rax, payload allocation per node is computed from: header + stored edge/path bytes + alignment padding + child pointers + optional terminal-value pointer. Compressed nodes need one child pointer. Allocator size-class rounding and metadata are additional. There is no source-supported universal bytes-per-domain figure. [Allocation formula](https://github.com/antirez/rax/blob/1927550cb218ec3c3dda8b39d82d1d019bf0476d/rax.c#L173).

Valkey tracks actual tree allocation sizes through its allocator shim and exposes `raxAllocSize`; this is useful for later evidence gathering, but is not whole-process RSS, external values, or simultaneous old/new snapshot peak usage. [Size-accounting change](https://github.com/valkey-io/valkey/commit/f85d8bfde9310541882b1d9d2bb9a330d84055bb).

The old bundled benchmark performs 5 million integer/alphanumeric insertions and exact lookups; it is not a domain/ancestor workload. [Benchmark source](https://github.com/antirez/rax/blob/1927550cb218ec3c3dda8b39d82d1d019bf0476d/rax-test.c#L826).

The Valkey memchr commit reports repeated microbenchmarks on macOS M4 Pro and Linux Ryzen, including an M4 1-million/16-byte-key exact-lookup result from 2.92 to 6.53 Mops/s. This is contributor-reported evidence of one internal optimization on those test systems; it does not compare whole candidates, establish Android Bionic behavior, or measure domain normalization, suffix matches, cache misses, or policy result storage. [Primary benchmark report](https://github.com/valkey-io/valkey/commit/c4db208e9b2c1d41b3a8c6db8a8b982df2dc11c0).

## armon/libart: concise ART with integration liabilities

The library is C99, with adaptive 4/16/48/256-child node classes. Its header exposes exact lookup and descendant-prefix enumeration, not an all-ancestor operation. All inserted strings should include an explicit terminator when one key can prefix another; its string tests consistently include that terminator. Prefix enumeration returns stored keys beginning with a query prefix, which is the reverse of the required ancestor query. [API/data layout](https://github.com/armon/libart/blob/301046804af165269e37da6725f5a4aec9ecc881/src/art.h), [prefix tests](https://github.com/armon/libart/blob/301046804af165269e37da6725f5a4aec9ecc881/tests/test_art.c#L304).

Exact search allocates nothing and does not mutate the tree. Insertion copies the entire key into each leaf; node allocations use calloc and are dereferenced without NULL checks. Those builder failure paths require work before considering it a robust memory-budgeted dependency. x86 gets SSE comparisons for Node16, while non-x86 has a scalar fallback and compiler bit-scan builtin; AArch64 therefore has a source-level path but no explicit NEON optimization here. Concurrent frozen-tree reads are a source-derived fit, while writer synchronization and reclamation remain external. [Search, leaf allocation, architecture branches](https://github.com/armon/libart/blob/301046804af165269e37da6725f5a4aec9ecc881/src/art.c#L126).

The public API has no persistence or mmap support. It is dynamically built with pointer-tagged leaves. For conventional LP64 layout, source-derived node sizes are 56, 160, 656 and 2064 bytes before allocator overhead; each leaf allocation adds roughly `sizeof(art_leaf) + key_len`, with sizeof commonly 16 bytes. These are layout estimates, not measured RSS. Full leaf keys make common-prefix sharing less decisive for total memory than the inner-tree diagram suggests. [Structures](https://github.com/armon/libart/blob/301046804af165269e37da6725f5a4aec9ecc881/src/art.h).

Do not turn the README’s 52-byte/key bound into a total mobile-domain memory budget. The original ART paper’s bound analyzes inner nodes and excludes separately stored leaf keys; it uses its own layout assumptions. Its evaluations used an Intel i7-3930K/Linux/GCC desktop and database/microbenchmark workloads, not this library on ARM64 domain lists. [README](https://github.com/armon/libart/blob/301046804af165269e37da6725f5a4aec9ecc881/README.md), [original paper, §III-E and §V](https://db.in.tum.de/~leis/papers/ART.pdf).

## Third C alternative: libdatrie, brief handoff

Libdatrie is C and supplies an incremental public TrieState cursor, terminal checks and terminal data. A cursor is allocated at creation but can be reused per worker; ordinary walk/data operations and exact retrieval do not allocate or modify the dictionary. With reversed names, terminal checks at label boundaries provide all ancestor matches in one traversal without altering library internals. This is an adapter using the public API, not built-in DNS semantics. [Public API](https://github.com/tlwg/libdatrie/blob/665edc5ec1639a81df004d4f92f07a73d5b96aba/datrie/trie.h), [implementation](https://github.com/tlwg/libdatrie/blob/665edc5ec1639a81df004d4f92f07a73d5b96aba/datrie/trie.c#L376).

It has save/load/serialize support, but load allocates the double-array and individual suffix strings; serialized data is not directly queried through mmap. Its double-array cells store two 32-bit indices, but each tail also has metadata and a suffix pointer/allocation. Do not substitute serialized file size for loaded RSS. Root is handling deeper comparison. [Double-array allocation](https://github.com/tlwg/libdatrie/blob/665edc5ec1639a81df004d4f92f07a73d5b96aba/datrie/darray.c#L232), [tail load/layout](https://github.com/tlwg/libdatrie/blob/665edc5ec1639a81df004d4f92f07a73d5b96aba/datrie/tail.c#L60).

## License metadata

- Standalone rax: root COPYING and README say BSD-2-Clause, but the inspected rax.c/rax.h headers include a third non-endorsement clause. Retain the actual file notices; do not summarize all files as uniformly two-clause. [COPYING](https://github.com/antirez/rax/blob/1927550cb218ec3c3dda8b39d82d1d019bf0476d/COPYING), [file header](https://github.com/antirez/rax/blob/1927550cb218ec3c3dda8b39d82d1d019bf0476d/rax.h#L1).
- Valkey rax files carry BSD-3-Clause-style notices. [File header](https://github.com/valkey-io/valkey/blob/05a9c29c62538519d870d6512978f80ac58a758f/src/rax.h#L1).
- Current Redis rax files give RSALv2, SSPLv1 or AGPLv3 choices. This differs materially from old BSD source. [File header](https://github.com/redis/redis/blob/864780a68b1bb794082dcbbaf8306cb23df24893/src/rax.h#L1).
- Armon libart: BSD-3-Clause text. [LICENSE](https://github.com/armon/libart/blob/301046804af165269e37da6725f5a4aec9ecc881/LICENSE).
- Libdatrie: LGPL-2.1-or-later, explicitly clarified in the pinned README. [README](https://github.com/tlwg/libdatrie/blob/665edc5ec1639a81df004d4f92f07a73d5b96aba/README).

These are verified source notices, not legal compatibility conclusions.

## Concrete unresolved integration work

1. Candidate selection needs representative ARM64 measurements of full exact-plus-ancestor queries and measured allocations/RSS, including match payloads and update peak memory. No benchmark from this review answers that comparison. No NDK compilation, Android/device validation, or target workload benchmark was performed.
2. Rax/libart require repeated exact probes or an added one-pass ancestor traversal. Libdatrie already exposes suitable incremental traversal.
3. Safe immutable publication, worker-local scratch/cursors and old-snapshot retirement belong in Sakamoto’s existing snapshot design.
4. Domain terminal values must distinguish exact-only from include-descendants and return all relevant matches; longest-name selection alone must not silently replace existing policy ordering.
5. Native C is straightforward for these candidates. This note makes no claim that a C++ implementation with a C wrapper is impossible; that would be a separate build/runtime tradeoff.
