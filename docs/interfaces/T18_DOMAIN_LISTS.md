# Domain-list conditions and snapshot ownership

## Representative acceptance — PASS_WITH_EXPLICIT_LIMITS (2026-09-26)

The [T18 evidence record](../testing/2026-09-26_T18_DOMAIN_LISTS.md) binds the
final source and artifacts to independent Linux Root and Pixel Root/controlled-VPN
TLS and QUIC packet checks. Exact and descendant names, label boundaries,
overlapping lists, complete winners, list-only updates, cache invalidation,
counts and endpoint outcomes passed. Host component and real VPP heap checks
cover bounded build, failure, retry and cleanup on x86-64 and Pixel ARM64.

The earlier first nonempty Linux and Pixel submissions remain preserved as
**HOLD**. The VPP API handler had put a 124,760-byte request and 126,856-byte
status on its process stack; moving that scratch state to checked heap allocation
made the real nonempty API and packet tests pass. The original results are under
`build-output/t18-20260926/`.

The calculated full-process overlap budget is still an admission bound, not a
measured RSS peak. A domain-bearing packet deliberately held across retired-bank
reuse has not been separately exercised; S209's protected-bank mechanism and
the T18 source-order contract were checked, while real T18 traffic exercised
repeated publication and cache changes. QUIC evidence covers supported v1
Initial assembly, not a completed handshake or broader version promise.

## Interface and required behavior

SAKAMOTO-269 extends the existing complete rule-management, compiler/matcher,
owner and protected-snapshot seams agreed in the unified rule specification.

Opcode 17 has one byte identifying a list (0..63). It is an ordinary Boolean
leaf. Its availability and whole-rule TLS/QUIC prerequisite are identical to
SNI absence. All memberships are retained; no domain length or action priority
is introduced. The packet-local projection is SNI result plus a 64-bit union
computed using that packet's protected snapshot. Cache guards include both.

A complete configuration carries a list count (including empty lists) and up
to 256 entries in total across all lists. The 256-entry Product binding was
built and queried on Host and Pixel ARM64; full-process peak overlap remains
unmeasured. An entry names one list and exact (0) or
self-and-descendants (1) mode, with an explicit ASCII DNS name length. Canonical A-label input is
accepted; ASCII case and one configuration trailing dot normalize. URL, glob,
Unicode and malformed labels are rejected, never silently stripped. Network
SNI retains its existing producer validation. Import preparation belongs to
the subsequent import task. A reference outside the declared list count is a
basic reference error before saving.

The source file and control ABI are extended as one complete version. Old source
files have empty lists. Save completes before compile; compile failure preserves
new saved/old active identities and old packet results. Domain-only updates
change the snapshot revision/hash without rewriting logical rule identities.

The selected unmodified Valkey rax revision is recorded in third_party/rax.
The Product binding is independently implemented. Build and destruction use
explicit fallible allocation and the captured VPP heap, with checked
allocate/copy/free growth and matching allocation-size/free operations. No
worker allocation, mutable published tree, secondary process or backend choice
is introduced. Each complete bank owns its tree; a retired bank is destroyed
only after its protected readers have left. Teardown destroys both trees before
their allocator heap can disappear.

Required acceptance uses the existing management save/apply/query boundary
with actual packet decisions, independent complete-winner/cache comparisons and protected
publication lifecycle. Component failure recovery does not imply recovery from
unrelated fatal allocations elsewhere in VPP or the Product compiler.

The generated VPP API identity is `product_core.api/1.0.0@22e2ac3d`; schema 1
retains the existing complete-operation semantics. The enlarged C structures
are compiled together with matching generated API/artifact identity, not a
binary-compatible extension for an independently old client. Source file V5
appends list count, entry count and fixed-width entries; V1–V4 load empty lists.
Diagnostic request text adds `lists N` and `domain INDEX exact|descendants NAME`.
JNI uses marker -2 with seven header words and 67 words per domain entry;
existing direct/-1 graph requests remain accepted. Replies append two counts
and domain entries after the graph. Rust and Java do not own persistent lists.

Each rax build is bounded to 128 KiB of allocator-reported object payload,
including its fixed value storage and temporary allocate/copy/free overlap.
The calculated two-bank/candidate representation budget is 1,654,196 bytes at
this layout (2 MiB admission ceiling), including three domain build budgets,
source/API/serialization/compiler representations and two owner caches. It
excludes process/thread reservations and allocator metadata; it is not measured
RSS or an all-process memory cap. Actual full-overlap measurement remains
incomplete; ARM64 component allocation peak was measured separately.
One 253-byte query performs at most 128 allocation-free exact rax lookups
(one exact and at most 127 descendant label boundaries).
