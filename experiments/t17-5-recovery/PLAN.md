# T17.5 pre-run recovery experiment

Written before native execution, 2026-09-26. Authority: SAKAMOTO-287 and the
user's latest KISS instruction. No Product integration or backend selection.

Question: can ordinary index allocation fail and return while the old immutable
snapshot remains usable, without rewriting VPP hash/vec or reserving resources?

Compare (1) unchanged pinned Valkey rax with an explicit recoverable VPP allocator
quartet and (2) a separately built immutable sorted-key representation. The
second route is source/design comparison, not a promised second implementation.
Existing VPP hash is the rejected baseline unless a small correct recovery route
exists. No IPC, process isolation, panic interception or reserve-based solution.

The rax adapter calls `clib_mem_alloc_or_null`, guarded `clib_mem_free`, and
`clib_mem_size`; realloc allocates, copies min(old usable size, requested size),
then frees only after success. This intentionally avoids both intercepted libc
allocation symbols and VPP's fatal realloc. Upstream rax is byte-identical to
T17's pin. No custom ancestor traversal.

Use T17 canonical entries and independent Python-oracle query TSVs unchanged.
Exact and descendant masks union at complete label boundaries; normalize case;
invalid names remain invalid. Old snapshot uses original masks; new snapshot
rotates every membership bit left by one, an independently checked changed
configuration preserving OR semantics. Each snapshot owns its copied entry
payloads and rax nodes. Inputs and queries coexist during builds.

Host and physical ARM64: all three 100k representative distributions and the
127-label/253-byte/all-membership edge workload. Three normal cost repetitions
per distribution. Small shared workload: inject failure at every allocation
ordinal from a successful new build, including snapshot/payload/tree/root,
insert/growth; also continuous failures and explicit pre-publication rejection.
For each, saved version advances first, active pointer/version/results must stay
unchanged, partially built allocations must return to the old live-byte/count
baseline, and a final successful retry must publish changed results. There is
no conversion/load step in this route; source copy allocation is covered.

After initial small-workload runs established recovery, extend the pre-registered
fault sample to the three 100k distributions at allocation ordinals 1–5, 50, 500,
midpoint and last, continuous failure from ordinal 5 and pre-publication rejection.
This measures large partial-build cleanup without an unnecessarily quadratic
exhaustive sweep. Retain the earlier results separately; do not relabel them.

Separate real exhaustion probe: a deliberately small experimental VPP heap,
old snapshot established, attempt a larger ordinary build until _or_null fails,
verify cleanup/old result, then retry a fitting changed snapshot. The small heap
is a fault trigger, never a capacity-based recovery guarantee. Also retain a
native intercepted-realloc probe as a negative control if useful.

Measure build/cleanup duration, batch complete-domain lookup and p50/p95/p99,
RSS and process peak, exact adapter live allocations/usable bytes and simultaneous
old/new peaks (including transient realloc copies). Timed queries allocate zero
through the adapter; source-audit raxFind. Single thread, no wakeup or concurrent
packet claims. Model saved/active ordering only, not real file durability or
Product worker publication. Kernel OOM kills, heap corruption, unavailable VPP
control plane and allocator bugs are outside normal allocation-failure recovery.

Retain consumed-source closure, pinned archive verification, compiler commands,
binary/library/workload hashes, fresh process/run identity, raw output and failed
probes. Android only repo dev/adb, serial operations, nonce-owned deployments,
timeout plus remote exit check before proceeding. Preserve accepted T17 inputs.
Independent Standards/Spec reviews precede final recommendation. User selection
remains required before Done or T18.
