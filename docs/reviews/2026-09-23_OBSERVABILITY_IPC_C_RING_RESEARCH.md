# C ring primitives for observability IPC

Date: 2026-09-23. Supporting research, not an implementation decision or Android
acceptance result. Scope: VPP-native C producers and one logical Rust consumer,
Android ARM64/minSdk 31 and Linux. Normal and debug export remain separate bounded
channels; VPP does not wait for delivery, ACK, or replay. Per-worker SPSC rings are
one candidate topology. No product source, build, device test, or performance
measurement was changed or run. No removed Snort C++ source or POC implementation
was used.

## Result

The useful shortlist is **typed Concurrency Kit `ck_ring` for fixed-size records**
and **Aeron's C SPSC ring primitive for variable-size records**. Both leave mapping,
FD transfer, wakeup, lifecycle, and the record ABI to Sakamoto. Aeron 1.53.2 is a
released audit candidate; CK's newer fence correction is present in the inspected
source snapshot but absent from its latest observed 0.7.2 tag. Neither candidate
is qualified here for Android. The detailed source evidence below supports these
conclusions; it does not establish relative speed, power use, or device correctness.

| Candidate | Different virtual addresses | Producer/full behavior | Record shape | Assessment |
| --- | --- | --- | --- | --- |
| CK typed SPSC | Explicit multiple-address-space design; use pointer-free typed entries | Wait-free SPSC API; false on full | Fixed `sizeof(struct T)` slots | Smallest reusable fixed-record primitive |
| Aeron C SPSC, 1.53.2 | Shared region has integer positions and record bytes; pointers are in each process's local handle; suitability inferred from source | No allocation, mutex, syscall, or retry loop in `write`; `FULL`/`ERROR` returns | Variable bytes, type ID, aligned header/padding | Most useful variable-record primitive; subset packaging needs a small adaptation |
| liblfds 7.1.1 | Ringbuffer explicitly requires identical virtual addresses; SPSC state also embeds an array pointer | SPSC rejects full; separate MPMC ringbuffer overwrites oldest and can retry | Pointer-sized key/value pairs | Reject for relocatable Android IPC as supplied |
| libqb qbrb, 2.0.8 | Explicit process IPC; pointers are local, shared positions are indexes | Normal mode rejects full; notification backend matters | Variable chunks | Real IPC comparison, but mapping/notification/dependency model is a poorer mobile fit |

## Inspected identities

- CK: [0.7.2 source commit](https://github.com/concurrencykit/ck/commit/981e14290df3d4339974eade5d8820dafd506b58), compared with
  [source snapshot `1ca0c1f1f2bf8d20e6f5d446ca32598e435ff71b`](https://github.com/concurrencykit/ck/commit/1ca0c1f1f2bf8d20e6f5d446ca32598e435ff71b), dated 2026-09-17.
  Official `refs/tags/0.*` ended at 0.7.2 when queried. The snapshot is an audit
  input, not a recommendation to follow a moving branch.
- Aeron: [1.53.2, `664f58e705f850dfb926f6293707b204ba804726`](https://github.com/aeron-io/aeron/releases/tag/1.53.2), released 2026-09-18.
  The SPSC/ring/atomic/platform files match the subsequently inspected development
  snapshot; all Aeron source links below use the release commit.
- liblfds: official `liblfds7.1.1` Git repository commit
  `d28d20e4750aa9e5b678639b2bb9d5b67a360819`, imported 2022-07-09; release 7.1.1
  dates to 2017-02-20. The [official repository instructions](https://liblfds.org/pages/git.html)
  and [versioned source archive](https://liblfds.org/downloads/liblfds%20release%207.1.1%20source.tar.bz2)
  are the source references; the project moved its source away from GitHub.
  Retrieved archive SHA-256:
  `4cb93868e5830bc02214b90bb76bdce836c38007757eec96d56eb5d9a4b78c47`.
  Version-specific static documentation links below are the working published
  URLs; the former dynamic `index.php?title=...` URLs returned 404.
- libqb: [v2.0.8, `002171bbcf4bc4728da56c1538afd9e9d814ecaf`](https://github.com/ClusterLabs/libqb/tree/002171bbcf4bc4728da56c1538afd9e9d814ecaf).

## Concurrency Kit: a small fixed-record option

**Contract and relocation.** The SPSC enqueue manual explicitly identifies
multiple address spaces as a reason for separating ring metadata from the buffer,
and documents one producer, one consumer, wait-free progress, and rejection when
full. This is stronger evidence than a generic thread-safe claim.
[Upstream SPSC manual](https://github.com/concurrencykit/ck/blob/1ca0c1f1f2bf8d20e6f5d446ca32598e435ff71b/doc/ck_ring_enqueue_spsc).

The shared `ck_ring_t` has integer counters, capacity/mask, and padding, with no
embedded buffer pointer. The default `ck_ring_buffer_t` stores `void *`, which must
not contain a producer address for the Rust process to dereference.
`CK_RING_PROTOTYPE(name, type)` supplies inline fixed-size struct copies instead;
the producer and consumer pass their own mapped buffer address on each call.
Consequently pointer-free POD records or explicitly defined offsets are a usable
layout. Capacity is a power of two, with one slot unavailable for records.
[Metadata and typed API](https://github.com/concurrencykit/ck/blob/1ca0c1f1f2bf8d20e6f5d446ca32598e435ff71b/include/ck_ring.h).

**Hot path and atomics.** The SPSC path copies one entry and publishes its counter,
without allocation, a mutex, CAS retry, or kernel notification. It uses CK loads,
stores, and fences, not C11 `_Atomic` declarations. The ARM64 backend provides
compiler barriers and `dmb` variants. This requires the correct CK configuration
and aligned shared storage, not a Rust recreation based only on field names.
[SPSC implementation](https://github.com/concurrencykit/ck/blob/1ca0c1f1f2bf8d20e6f5d446ca32598e435ff71b/include/ck_ring.h#L177),
[ARM64 atomics](https://github.com/concurrencykit/ck/blob/1ca0c1f1f2bf8d20e6f5d446ca32598e435ff71b/include/gcc/aarch64/ck_pr.h).

The exact later change is [commit `c7945fe3a7817549f573b0cb902f797c7df071a0`](https://github.com/concurrencykit/ck/commit/c7945fe3a7817549f573b0cb902f797c7df071a0), 2026-06-11.
It strengthens consumer publication from a store fence to a load/store fence and
fixes the diagnostic validity check across counter wrap. Upstream characterizes
the fence concern as theoretical with no impact on a real modern CPU; this review
does **not** claim an observed ARM64 failure. Nevertheless, a new source audit
should include this correction rather than assume 0.7.2 contains it.

**Mobile, size, and license.** CK lists ARM64 Linux GCC and Darwin Clang CI plus
specialized AArch64 support. That establishes relevant architecture/compiler work,
not Android NDK/Bionic support. No explicit Android CI or acceptance was found in
the inspected README/workflow. Ring operations are header-inline; integration
needs `ck_ring.h`, CK's transitive compiler/atomic/string headers and generated
`ck_md.h` configuration, not a queue service or broker. Its ring source carries
the two-clause BSD license. No binary footprint was measured.
[Build/support](https://github.com/concurrencykit/ck/blob/1ca0c1f1f2bf8d20e6f5d446ca32598e435ff71b/README.md),
[configure](https://github.com/concurrencykit/ck/blob/1ca0c1f1f2bf8d20e6f5d446ca32598e435ff71b/configure),
[license and includes](https://github.com/concurrencykit/ck/blob/1ca0c1f1f2bf8d20e6f5d446ca32598e435ff71b/include/ck_ring.h#L1).

**Remaining product work.** There is no variable-length byte-record allocator or
wakeup protocol. A bounded record envelope plus length is straightforward but
spends the full slot size. A separate variable-data arena introduces another
ownership/reclamation problem. Neither is supplied by CK. FD/mapping setup,
bounded drain scheduling, notification, generation changes, drop counters, and
Rust binding remain outside this primitive.

## Aeron C SPSC: the stronger variable-record candidate

**Scope and layout.** This candidate is only `aeron_spsc_rb`, not an Aeron Media
Driver, network transport, archive, cluster, or JVM. The local `aeron_spsc_rb_t`
holds the buffer/descriptor pointers. The shared trailer holds padded integer
positions and optional counters; record headers contain length and message type.
Each endpoint initializes its own handle from its own mapping base. There are no
process addresses in the shared ring format. Different-address use is therefore
a source-level inference, not an Android-specific upstream promise.
[Local handle](https://github.com/aeron-io/aeron/blob/664f58e705f850dfb926f6293707b204ba804726/aeron-client/src/main/c/concurrent/aeron_spsc_rb.h),
[shared layout](https://github.com/aeron-io/aeron/blob/664f58e705f850dfb926f6293707b204ba804726/aeron-client/src/main/c/concurrent/aeron_rb.h).

**Records and try-write.** `write` copies bounded bytes and returns success, full,
or invalid-message error. It has no allocation, mutex, syscall, or producer retry
loop. `try_claim`/`commit` can write directly into a reservation; `abort` publishes
padding. The consumer invokes a callback while data is readable, then advances
the head. These are SPSC operations; arbitrary worker threads cannot publish to
one instance concurrently. No overwrite-oldest mode is exposed.
[Implementation](https://github.com/aeron-io/aeron/blob/664f58e705f850dfb926f6293707b204ba804726/aeron-client/src/main/c/concurrent/aeron_spsc_rb.c).

Capacity is a power of two below `INT32_MAX`; maximum nonempty payload is
capacity/8. Each record has an eight-byte header and eight-byte alignment, with
padding at wrap. With the defined 64-byte cache line constant, the trailer is
768 bytes, derived from six 128-byte regions. Neither this arithmetic nor source
file size is a compiled memory/performance measurement. Full can still publish
wrap padding, so failure does not mean every shared byte stayed unchanged.
[Constants/layout](https://github.com/aeron-io/aeron/blob/664f58e705f850dfb926f6293707b204ba804726/aeron-client/src/main/c/concurrent/aeron_rb.h),
[capacity claim](https://github.com/aeron-io/aeron/blob/664f58e705f850dfb926f6293707b204ba804726/aeron-client/src/main/c/concurrent/aeron_spsc_rb.c#L22).

**Ordering and release selection.** Publication uses `AERON_SET_RELEASE` on record
length; the reader uses `AERON_GET_ACQUIRE` before reading bytes. Consumer head
publication and producer refresh supply slot-reuse ordering. On AArch64 the
backend implements these using volatile accesses with C11 fences; this is not
equivalent to merely treating volatile fields as Rust atomics. Platform detection
accepts GNU-compatible compilers and requires C11 atomics on AArch64.
[ARM atomic backend](https://github.com/aeron-io/aeron/blob/664f58e705f850dfb926f6293707b204ba804726/aeron-client/src/main/c/concurrent/aeron_atomic64_c11.h),
[platform selection](https://github.com/aeron-io/aeron/blob/664f58e705f850dfb926f6293707b204ba804726/aeron-client/src/main/c/util/aeron_platform.h).

[Fix `12e16428e006ae283ae256f4c82c9bd29f84fcda`](https://github.com/aeron-io/aeron/commit/12e16428e006ae283ae256f4c82c9bd29f84fcda), 2026-04-23,
corrects a failed wraparound capacity claim that previously could overwrite unread
content; upstream includes regression tests and explicitly describes corruption.
It is listed under [1.51.0 in the changelog](https://github.com/aeron-io/aeron/blob/664f58e705f850dfb926f6293707b204ba804726/CHANGELOG.adoc#L375)
and is present in the inspected 1.53.2 release. The earlier inspected 1.50.4 tag
lacks the fix. This is source verification, not execution of those tests.

**Can it be a small C subset?** Yes as an integration candidate, with an explicit
packaging seam; upstream does not supply a standalone SPSC CMake target. The
minimal reviewed ARM64 ring dependency set is:

- `concurrent/aeron_spsc_rb.c` and `.h`, `aeron_rb.h`, `aeron_atomic.h`,
  `aeron_atomic64_c11.h`;
- `util/aeron_bitutil.h`, `util/aeron_platform.h`, `util/aeron_error.h`,
  and `aeron_common.h`;
- libc copying and compiler atomic support; a Linux x86-64 build selects
  `aeron_atomic64_gcc_x86_64.h` instead of the ARM backend;
- one unresolved upstream error service, `aeron_err_set`, reached by invalid
  initialization. A small project error adapter can implement this service or
  replace that initialization error seam; that is a maintained adaptation.

These dependencies follow the [ring includes and calls](https://github.com/aeron-io/aeron/blob/664f58e705f850dfb926f6293707b204ba804726/aeron-client/src/main/c/concurrent/aeron_spsc_rb.c)
and [error declaration](https://github.com/aeron-io/aeron/blob/664f58e705f850dfb926f6293707b204ba804726/aeron-client/src/main/c/util/aeron_error.h).
Keeping the complete upstream error implementation instead adds
`util/aeron_error.c`, `concurrent/aeron_thread.h`, `aeronc.h`,
`aeron_client_error.h`, and `aeron_archive_client_error.h`; its POSIX branch uses
pthread TLS/once and allocates an error buffer when first needed. It also calls
`aeron_fprintf`, located in `aeronc.c` alongside client connection code. Thus
copying one `.c` file alone is not a proven standalone link recipe, and pulling
`aeronc.c` whole loses the clean small-subset boundary.
[Error service](https://github.com/aeron-io/aeron/blob/664f58e705f850dfb926f6293707b204ba804726/aeron-client/src/main/c/util/aeron_error.c),
[POSIX aliases](https://github.com/aeron-io/aeron/blob/664f58e705f850dfb926f6293707b204ba804726/aeron-client/src/main/c/concurrent/aeron_thread.h),
[printing service](https://github.com/aeron-io/aeron/blob/664f58e705f850dfb926f6293707b204ba804726/aeron-client/src/main/c/aeronc.c#L37).

No Media Driver or JVM is required by the ring algorithm or this proposed subset.
The stock client build is broader and links platform services; it must not be
used as evidence that the isolated subset has already built on Android. The
inspected C platform/CI sources establish AArch64 and Clang-related code, but no
explicit Android/Bionic qualification. The source is Apache-2.0 licensed.
[Client build](https://github.com/aeron-io/aeron/blob/664f58e705f850dfb926f6293707b204ba804726/aeron-client/src/main/c/CMakeLists.txt),
[license](https://github.com/aeron-io/aeron/blob/664f58e705f850dfb926f6293707b204ba804726/LICENSE).

**Remaining product work.** Caller-owned zeroed/aligned mapping, a local handle per
process, versioned payload encoding, notification and restart rules remain
necessary. The ring exposes no eventfd/epoll sleep protocol. Its heartbeat and
correlation fields do not provide ACK, replay, reconnect, or abandoned-claim
recovery. A consumer must finish reading or copy the callback bytes before its
head release permits producer reuse.

## liblfds: process-safe does not mean relocatable

The official [7.1.1 ringbuffer documentation](https://liblfds.org/mediawiki/index.php%3Ftitle=r7.1.1:Ringbuffer.html)
explicitly requires the same virtual addresses in all processes when using shared
memory. It is an MPMC key/value ring built from a freelist and queue, automatically
reclaims the oldest unread entry when full, and uses contention backoff. It
performs no allocation itself, but is not a bounded single-attempt SPSC export
primitive. Its documentation also distinguishes the library's permissive grant
from uncertainty it records about the underlying Michael–Scott queue design's
license; that wording should not be silently replaced with a conventional SPDX
claim.

The separate [bounded SPSC queue](https://liblfds.org/mediawiki/index.php%3Ftitle=r7.1.1:Queue_(bounded,_single_producer,_single_consumer).html)
rejects full, preserves FIFO, and uses caller allocation. Its public header in
the pinned source contains `read_index`, `write_index`, **`element_array`**, and
`user_state` in the same state; entries are two pointer-sized values. Unlike CK,
the array address is not passed independently for each endpoint. Encoding payload
offsets in the key/value does not fix the embedded array pointer. Duplicating the
state locally would duplicate the cursors too. Making this relocatable requires
changing the library's shared state/access code, not just adding `mmap`.
[Versioned source archive](https://liblfds.org/downloads/liblfds%20release%207.1.1%20source.tar.bz2), path
`liblfds711/inc/liblfds711/lfds711_queue_bounded_singleproducer_singleconsumer.h`.

The source SPSC enqueue/dequeue have no allocation or mutex and use volatile
indices plus the library's load/store barrier macros. GCC PAL branches use
`__sync_synchronize` or `__atomic_thread_fence`; this is not a documented
C/Rust cross-language atomic ABI. No variable-byte record allocator, FD handoff,
or wakeup mechanism is provided. The tiny bare-C dependency model is attractive,
but the [official 7.1.1 support matrix](https://liblfds.org/)
marks ARM64 unsupported, even though partial ARM64 definitions exist in the PAL.
It lists GCC/MSVC rather than Android NDK qualification. The SPSC documentation
grants public-domain/permissive use with named alternative licenses. These facts
do not outweigh the shared-address and target-support gaps for this task.

## libqb qbrb: genuine IPC, a larger integration surface

The public API explicitly documents one writing process and one reading process,
whole variable-size chunks, normal full rejection, and an optional overwrite
mode. `QB_RB_FLAG_NO_SEMAPHORE` disables its waits/notifications. LGPL-2.1-or-later
appears in the source license. [Public contract](https://github.com/ClusterLabs/libqb/blob/002171bbcf4bc4728da56c1538afd9e9d814ecaf/include/qb/qbrb.h).

The shared header holds indexes, paths, reference count, and semaphore storage;
mapping pointers and notifier function pointers are in the local handle. Each
process maps independently. Data uses a double mapping so a wrapped chunk can be
contiguous in local virtual memory: roughly twice the data capacity in virtual
address reservation, not twice the physical data storage. A separate header
mapping includes two `PATH_MAX` arrays. This is genuine relocatable IPC design.
[Structures](https://github.com/ClusterLabs/libqb/blob/002171bbcf4bc4728da56c1538afd9e9d814ecaf/lib/ringbuffer_int.h),
[mapping helper](https://github.com/ClusterLabs/libqb/blob/002171bbcf4bc4728da56c1538afd9e9d814ecaf/lib/unix.c#L211).

Normal `chunk_alloc` checks space and returns failure; `chunk_write` copies and
commits without heap allocation. Commit release-publishes chunk magic; reads
acquire-load it. A configured notifier is then called for every committed chunk.
Native semaphore notification, replacement semaphores, and atomics fallbacks
must be distinguished: the replacement semaphore uses pthread mutexes; the
no-GCC-builtins atomic fallback also uses a lock. `NO_SEMAPHORE` plus working
compiler atomics removes those paths, at the cost of owning wakeup integration.
[Write path](https://github.com/ClusterLabs/libqb/blob/002171bbcf4bc4728da56c1538afd9e9d814ecaf/lib/ringbuffer.c#L410),
[atomic ordering](https://github.com/ClusterLabs/libqb/blob/002171bbcf4bc4728da56c1538afd9e9d814ecaf/lib/atomic_int.h),
[notification selection](https://github.com/ClusterLabs/libqb/blob/002171bbcf4bc4728da56c1538afd9e9d814ecaf/lib/ringbuffer_helper.c#L263),
[replacement semaphore](https://github.com/ClusterLabs/libqb/blob/002171bbcf4bc4728da56c1538afd9e9d814ecaf/lib/rpl_sem.c).

Android rejection cannot simply be blamed on missing `shm_open`: this version
uses ordinary file open plus `mmap`, with `/dev/shm`/configured socket-directory
paths and support for explicit paths. The actual mismatch is its public
name/path-based creation of header/data files rather than attachment to a
product-supplied shared-memory FD; the latter remains a candidate here. Its backend also selects
POSIX process-shared or System V semaphores, or none. No Android/Bionic CI or
acceptance was found in the inspected build/docs. A port would need to settle
paths/permissions, double mapping, backend configuration, and FD ownership.
[Open/setup](https://github.com/ClusterLabs/libqb/blob/002171bbcf4bc4728da56c1538afd9e9d814ecaf/lib/ringbuffer.c#L124),
[file paths](https://github.com/ClusterLabs/libqb/blob/002171bbcf4bc4728da56c1538afd9e9d814ecaf/lib/unix.c#L111).

It is a C library rather than an external broker, but qbrb depends on libqb
mapping, atomics, semaphore, utility, and logging internals. The full Autotools
build includes unrelated IPC/logging/loop facilities; GLib and Check are optional
example/test dependencies, while its configure script checks libxml for the
documentation generator. Do not infer a tiny standalone ring dependency from the
public header alone. [Build/dependency description](https://github.com/ClusterLabs/libqb/blob/002171bbcf4bc4728da56c1538afd9e9d814ecaf/README.markdown),
[configure](https://github.com/ClusterLabs/libqb/blob/002171bbcf4bc4728da56c1538afd9e9d814ecaf/configure.ac).

## Integration conclusions

These are design inferences from the audited primitives:

1. Prefer typed CK if record sizes can be bounded cheaply in fixed slots. Prefer
   auditing Aeron 1.53.2's C SPSC subset if variable-size normal/debug records
   materially reduce reserved memory. Neither preference is a performance claim.
2. Keep queue operations in the same pinned C implementation at both ends through
   a small non-unwinding Rust FFI wrapper first. Rust owns local handle lifetime;
   exported payloads use defined integers/bytes/offsets, never `FlowEntry *`, VPP
   buffer pointers, strings with local backing storage, or shared Rust references.
3. Own the Android/Linux mapping and FD bootstrap separately. Specify initial
   zeroing, mapping bounds, natural atomic alignment, ABI version, capacity,
   generation, peer exit, and teardown before accepting either primitive.
4. Own a bounded notification/sleep protocol separately. Publishing bytes and
   notifying a sleeping reader are different operations. An empty-to-nonempty
   check alone is not a proved wakeup protocol; no inspected primitive supplies
   the required coalesced eventfd/epoll contract.
5. Keep drop-new behavior and owner-local counters on full. One Rust consumer can
   drain several SPSC instances under a bounded fairness policy; that does not
   turn one instance into a multiproducer queue. Do not spin until space appears.

The next evidence boundary is a focused NDK/host integration audit, including the
chosen atomic backend and actual C/Rust ABI, followed by different-address process
tests and lifecycle/wakeup races. Those checks were deliberately not run in this
research task, and no library has been imported into Product.
