# DNS-native QP tries for Sakamoto domain matching

Research date: 2026-09-15. Scope: primary-source inspection only; no implementation or benchmarks. Required matching is exact hostname plus domain-and-subdomains, producing candidates for the existing complete rule ranking. SNI is the current consumer; independent DNS filtering is a future consumer. This note does not investigate blocklist sources or historic Sakamoto C++.

Durable supporting evidence for the [consolidated candidate assessment](2026-09-15_DOMAIN_MATCHER_RESEARCH.md) and [discussion record](2026-09-14_RULE_ENGINE_DISCUSSION_TMP.md). Candidate recommendations remain provisional; final selection requires measurements on the target device. “Current consumer” describes the agreed version scope, not an already implemented SNI module.

## Recommendation

**QP tries are a credible production-proven family, but none reviewed is a ready-made small C domain-filter library with the precise required policy API and a serialized immutable image.** Of this group, Knot DNS's implementation is the strongest bounded extraction candidate; BIND is a valuable design/API reference whose integration burden is much higher. The original fanf2 generic C implementation is lightweight, but its DNS-specific experimental variant should not be selected as production code.

This is an integration assessment, not a measured performance ranking. Do not infer mobile ARM speed or final memory use from whole-server DNS results.

## Pinned upstream snapshots

Public GitHub API returned these HEAD revisions during this investigation. They are inspected source snapshots, not a claim that HEAD is a stable product release:

| Repository | Revision | Last commit UTC | Relevant license metadata |
|---|---|---|---|
| [fanf2/qp](https://github.com/fanf2/qp/commit/90fc7de8d0b3c9c1aaa5cd9d7b1765b122fad2e5) | `90fc7de8d0b3c9c1aaa5cd9d7b1765b122fad2e5` | 2022-07-12 | Studied C files link CC0 1.0 in headers |
| [CZ-NIC/knot](https://github.com/CZ-NIC/knot/commit/990a2430328a0f343b3a2130f801bb6a032a7378) | `990a2430328a0f343b3a2130f801bb6a032a7378` | 2026-09-11 | `trie.c`, `trie.h`, allocator headers: GPL-2.0-or-later |
| [CZ-NIC/knot-resolver](https://github.com/CZ-NIC/knot-resolver/commit/16d3d01e421d19a02602df5c3c07e603c714735e) | `16d3d01e421d19a02602df5c3c07e603c714735e` | 2026-09-14 | Studied `lib/generic/trie.h`: GPL-3.0-or-later |
| [isc-projects/bind9](https://github.com/isc-projects/bind9/commit/c5b5313fc82e47db198d82b72c84aa3275013198) | `c5b5313fc82e47db198d82b72c84aa3275013198` | 2026-09-14 | Studied QP code: MPL-2.0 |

These are source metadata observations, not a legal compatibility determination.

## fanf2/qp: small generic implementation, DNS experiment unsuitable

The public project recommends the newer generic five-bit `fn` variant; its README notes that most code was tested primarily on 64-bit little-endian machines. Build examples are test/benchmark programs, not a packaged stable dependency contract. [README](https://github.com/fanf2/qp/blob/90fc7de8d0b3c9c1aaa5cd9d7b1765b122fad2e5/README.md)

`Tbl.h` provides exact lookup, insert/delete and lexicographic iteration. Keys and values are borrowed, not copied; values must satisfy pointer alignment. There is no direct all-ancestors/domain-suffix API. A caller can perform repeated exact queries on label-aligned suffixes. [Tbl.h](https://github.com/fanf2/qp/blob/90fc7de8d0b3c9c1aaa5cd9d7b1765b122fad2e5/Tbl.h)

`fn.c` includes only C standard headers and local `Tbl.h`/`fn.h`; its exact traversal uses prefetch/popcount and `strcmp`, with no heap allocation or trie mutation on the inspected read path. Treat NUL-terminated input as mandatory even where the API takes a length. **Inference:** immutable concurrent readers can share it if publication/reclamation and pointed-to key/value lifetimes are handled externally. Mutating the shared trie concurrently is not supplied by this API. [fn.c](https://github.com/fanf2/qp/blob/90fc7de8d0b3c9c1aaa5cd9d7b1765b122fad2e5/fn.c)

The DNS-tuned `dns.h` explicitly warns against use and redirects readers to an NSD fork. It says its test-harness adaptation searches strings left-to-right, remains case-sensitive and treats dots as ordinary common characters. Therefore the name “DNS trie” does **not** mean this file directly supplies normalized DNS suffix matching. [dns.h](https://github.com/fanf2/qp/blob/90fc7de8d0b3c9c1aaa5cd9d7b1765b122fad2e5/dns.h)

## Knot DNS: production source with relatively small extraction surface

`trie.h` exposes binary length-delimited keys, exact lookup, predecessor search and iterators. Keys are copied; values are `void *`. `trie_it_parent()` advances to a stored longest prefix. `trie_get_try_wildcard()` assumes root-to-leaf zero-separated labels and implements **DNS wildcard semantics**, expressly different from ordinary suffix expectations. COW transactions exist, but write locking, root publication and reader grace periods are explicitly caller responsibilities; the API suggests RCU as an example rather than requiring it internally. [trie.h](https://github.com/CZ-NIC/knot/blob/990a2430328a0f343b3a2130f801bb6a032a7378/src/contrib/qp-trie/trie.h)

The C file depends on standard C, Knot macros, error codes and allocator wrappers. It uses 16-byte nodes on a conventional 64-bit ABI, separately allocated copied keys with a four-byte header, and packed child arrays. Exact `trie_get_try()` neither allocates nor writes the trie. Iterator construction allocates an object containing 250 pointer slots; deeper stacks can allocate again. Thus the stock parent-iterator path is not a heap-free per-query primitive. Insertion allocates keys and child arrays, grows arrays and moves elements. [trie.c](https://github.com/CZ-NIC/knot/blob/990a2430328a0f343b3a2130f801bb6a032a7378/src/contrib/qp-trie/trie.c)

The allocator context is only `{context, alloc, free}`. Its implementation defaults to libc but custom-context reallocation performs allocate/copy/free; the complete allocator source also includes optional Knot pool/string helpers. Extraction would require retaining or replacing this small support layer, not automatically linking the resolver's full RCU/event machinery. **Inference:** build a new trie privately, freeze it and publish through Sakamoto's existing immutable policy lifetime; COW is unnecessary for the initial design. [mm_ctx.h](https://github.com/CZ-NIC/knot/blob/990a2430328a0f343b3a2130f801bb6a032a7378/src/libknot/mm_ctx.h), [mempattern.c](https://github.com/CZ-NIC/knot/blob/990a2430328a0f343b3a2130f801bb6a032a7378/src/contrib/mempattern.c)

`knot_dname_lf()` reverses labels into caller-supplied storage, using zero separators; the inspected conversion copies label bytes without lowercasing. Normalization must therefore occur separately. A dedicated label-boundary ancestor query or repeated exact label-prefix probes is still needed for our policy semantics; closest DNS wildcard is not a substitute. [dname.c](https://github.com/CZ-NIC/knot/blob/990a2430328a0f343b3a2130f801bb6a032a7378/src/libknot/dname.c#L754)

Knot Resolver's current header says its trie is a synchronized older Knot implementation with mostly include/export/assertion changes. Its exposed API is smaller (exact/predecessor/iteration, no current Knot COW/parent interface) and carries different GPL-3.0-or-later metadata. It is evidence of reuse, but not a better standalone ancestor-matcher package. [Resolver trie.h](https://github.com/CZ-NIC/knot-resolver/blob/16d3d01e421d19a02602df5c3c07e603c714735e/lib/generic/trie.h)

## BIND9: excellent ancestor semantics, substantial runtime framework

The QP API provides `dns_qp_getname()` for exact matching and `dns_qp_lookup()` for exact-or-ancestor lookup. An optional chain contains every populated ancestor along the search, allowing candidate collection rather than imposing closest-name priority. Keys derive from leaf values through caller methods instead of being stored independently. The API includes single-threaded read/write tries, concurrent query handles and heavyweight snapshots. Concurrent queries require liburcu-registered threads; leaf ownership uses supplied reference-count callbacks. [qp.h](https://github.com/isc-projects/bind9/blob/c5b5313fc82e47db198d82b72c84aa3275013198/lib/dns/include/dns/qp.h)

The implementation imports ISC memory, atomics, mutexes, reference counting, logging, thread identity, time and URCU, plus DNS name/types and private QP infrastructure. Exact and ancestor traversals use stack keys/chains/iterators. `dns_qpmulti_query()` enters RCU, while snapshot creation locks and allocates a copied base-pointer table. Removing all this is appreciably more work than borrowing a two-file map implementation. [qp.c](https://github.com/isc-projects/bind9/blob/c5b5313fc82e47db198d82b72c84aa3275013198/lib/dns/qp.c)

BIND normalizes DNS lookup keys by reversing label order, lowercasing ASCII and distinguishing label separators. It optimizes common hostname bytes into a packed bitmap trie. Chunk-relative 32-bit references save interior-node space; the allocator and copying GC address locality, fragmentation and multi-version reclamation. This is useful design evidence, but far beyond the machinery needed for infrequently rebuilt immutable rule dictionaries. [Design notes](https://github.com/isc-projects/bind9/blob/c5b5313fc82e47db198d82b72c84aa3275013198/doc/design/qp-trie.md)

Production status is stronger than “experimental”: ISC says QP backends are BIND 9.20's default and replace RBTDB in 9.22. [ISC maintainer announcement](https://lists.isc.org/pipermail/bind-users/2025-November/110287.html)

## Performance evidence and limits

- Original QP's author reports roughly one-third less **overhead** than crit-bit and about 30% faster in older tests. That is not bytes per complete domain entry. The author separately clarifies that key/value pointers were treated as sunk cost. [Project README](https://dotat.at/prog/qp/README.html), [memory-accounting explanation](https://dotat.at/prog/qp/notes-generic-leaves.html)
- Knot's introducing merge request reports a large RSS reduction for many small zones, but roughly 1–2% higher memory on large zones with its then-current allocator; alternative allocators changed the comparison. Lookup-speed observations were mixed and preliminary. This does not establish universal QP superiority. [Knot MR 574](https://gitlab.nic.cz/knot/knot-dns/-/merge_requests/574)
- ISC's current 9.20 transition note says CPU and RAM can initially be slightly higher while scaling improves, with results dependent on workload. Whole-server claims are not standalone domain-index measurements. [ISC 9.20 changes](https://kb.isc.org/docs/bind-920-changes)
- Current Knot server benchmarks use large EPYC/DDR5 machines and 400GbE, not mobile devices. Their own disclaimer says hardware, data and configuration materially affect results. [Knot benchmark](https://www.knot-dns.cz/benchmark/)

No inspected public trie API supplies a relocatable serialized/mmap image or a bulk-build contract. This is a bounded API/source inspection result, not a claim that no downstream serializer exists. Snapshot replacement must account for old index, new index and builder temporaries. Key storage, memberships/candidate metadata and allocator rounding remain part of real memory use.

## Implications for the product discussion

Keep exact and suffix terminal meanings explicit. Query all relevant candidates, then apply existing full-rule Rank; domain specificity must not create hidden priority. A single domain can carry compact references to several lists/conditions. Independent DNS filtering can reuse the same normalized condition representation without inheriting packet fields or inventing cross-stage rules.

Shortlist conclusion: **Knot QP is worth comparing against simpler standalone C indices; BIND QP is an architectural reference; fanf2 `fn` is a small algorithm/library seed, while fanf2 `dns` is not a production dependency recommendation.** Actual CPU/memory ranking remains unmeasured and should not be frozen from these sources alone.
