# T11 worker-private complete-result cache

`product_l4_policy_match_cached` is the native synchronous compiler/matcher
seam. It borrows the protected immutable view, normalized packet and identity
for the call, returns the ordinary complete Match/NoMatch or matcher error, and
never retains view, packet or Flow pointers. `NULL` cache selects direct
matching. Caller-owned storage is private to one execution owner; diagnostics
require that owner or the existing control/CLI worker barrier.

Each compiled application bucket carries the union of dependencies for **all**
its whole rules. The initial summary conservatively guards every current static
packet/platform value and availability flag, plus CT state/availability and
flow direction/availability when any applicable rule uses either dynamic leaf.
This deliberately over-guards irrelevant static fields. It does not derive
invalidation from the previous winner. UID and its availability select the
application view; current endpoints and device direction remain directional.
PRE, POST and ALL are distinct complete queries, with no partial state shared.

The canonical guard also contains generation, revision, snapshot hash and the
current Flow incarnation. PRE has no Flow lookup and uses incarnation zero;
POST uses the instance returned by that packet's owner-local observation, or
zero when no instance exists. CT values are guarded directly rather than using
a version detached from its Flow. No slot index, bidirectional hash or pointer
is accepted as instance identity. Runtime restart clears owner storage after
drain; same-slot reuse within a runtime gets a new incarnation.

A hit copies the entire result: evaluation, logical rule, full Rank, reason,
effective mode, declared and actual action, verdict and NoMatch reason. It then
uses the unchanged graph attribution/accounting path. Effective-view candidate
count is retained; leaf/key/subtable work is zero on a hit. `subject_probes`
includes the dependency lookup on hits and adds it to normal lookup work on
misses. Errors are not cached. Guard mismatch or a hash collision performs a
normal complete match, then replaces the slot. No query is truncated.

The initial active capacity is **128 entries per worker**, with 128 fixed backing
entries. A zero-initialized capacity field selects that default; native callers
may choose 1..128 before admission. This is an engineering/testing seam, not a
saved rule-format field or user setting. The canonical guard is 104 bytes, each
entry 168 bytes and each owner cache 21,536 bytes on the tested x86-64/ARM64
layouts. Both workers' 43,072 bytes are charged to management representation
peak (911,756 bytes under the existing 1 MiB bound). Process RSS is separate.
`show product flows` reports capacity, occupancy, storage, hits, misses and
replacements per worker under its existing barrier.

Publication only changes the immutable snapshot. It does not scan/clear caches,
terminate flows, reset CT facts or reset cumulative counters. A packet retains
its acquired snapshot through both positions and may finish under an older
identity after publication. Cache entries store values rather than bank
addresses, so bank reuse does not create a dangling result.

Later protocol/SNI producers must add their dependency class, value/availability
projection (or an instance-bound fact identity) and cold/hot transition tests at
this same seam before their predicates are cached. T12/T13/T15/T18 retain that
integration responsibility; no future facts or new blocking edges are implied.
See the [dated measurement and acceptance report](../testing/2026-09-25_T11_COMPLETE_RESULT_CACHE.md).
