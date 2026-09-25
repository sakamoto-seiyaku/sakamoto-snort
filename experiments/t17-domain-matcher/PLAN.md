# T17 fixed comparison contract

Written before candidate execution, 2026-09-26. This is experiment code, not
Product source or a multi-backend Product design. Decision belongs to
SAKAMOTO-268; T18 remains blocked until the user's recorded selection.

Question: which small C dependency best fits complete domain membership on the
current Android ARM64 endpoint, including building and replacing dictionaries?
Compare libdatrie 665edc5ec1639a81df004d4f92f07a73d5b96aba (public cursor),
Valkey rax 05a9c29c62538519d870d6512978f80ac58a758f (public exact lookups),
and current pinned VPP 9258530f3804a152578ce11cc7c8a1e9eab88ed0 string hash.
Knot QP is optional, only if these fail or evidence motivates another candidate.

Input is a bounded ASCII hostname (1–253 bytes, labels 1–63, letters/digits/
hyphens, no initial/final hyphen); A-labels are already converted by import.
Configuration can remove one final dot; this benchmark's query adapter rejects
trailing dots to model strict SNI input. Fold ASCII case. Reject URLs, wildcards,
empty labels, non-ASCII, embedded NUL and overlength input. These are experiment
adapter rules within the specified hostname subset, not new import syntax.
Each canonical name stores separate exact and descendant list-membership masks.
Return the union of *all* applicable memberships; full-name lookup includes both
modes, proper ancestors include descendants only. No winner/action is selected.
The fixed payload uses 64 list bits per mode. More lists require new measurement.

Common deterministic synthetic workloads: 1,000 / 10,000 / 100,000 entries;
shared suffix, high entropy, and deep/long labels. All carry the same payload.
Each workload mixes full hits, descendant hits, misses, case variants, boundary
near-misses, and overlapping ancestors/list memberships. Python independently
computes expectations using label arrays and set membership. A small adversarial
fixture covers invalid input and exact/descendant separation. No real browsing
data or claim that synthetic frequency represents population traffic.

Single builder, immutable shared tree, single querying thread; no concurrent
mutation, IPC, wakeups or policy cache. Preallocate reusable libdatrie cursor.
Each process builds two simultaneous dictionaries to measure replacement peak,
then frees the old one before queries. Source input/payload memory remains live
and is reported as part of process RSS. Candidate code and library allocation
footprints are reported separately when APIs allow; do not compare serialized
size with resident memory. Record process RSS/HWM at stages and getrusage peak.
Query measurements include normalization, complete ancestor aggregation and
per-query timing overhead, with median/p95/p99 plus batched throughput. Repeat
three fresh processes per workload/platform; rotate candidate order on Android.

Bound runs to 120 seconds each, 256 MiB VPP arena and 100,000 entries; retain
timeout/compile/semantic failures. No guessed SLO or default winner. Correctness
and no query allocation are prerequisites; interpret query tails, build time,
resident/replacement peak, binary/dependency/adapter cost together. Device power,
concurrent multi-worker scaling and full Product integration are unmeasured.
Beyond this envelope T18/later consumers must supplement measurements and
reassess rather than inherit unconditional approval.
