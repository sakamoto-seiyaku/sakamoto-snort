# T20 observation IPC experiment

Pre-registration: 2026-09-26, before benchmark execution. Task SAKAMOTO-271;
parent SAKAMOTO-251, specification §10 and ADR-0009. This is disposable transport
evidence, not product code or the E01 complete observation pipeline.

Question: which reusable C queue can carry bounded, lossy observation records
from one C producer process to one Rust consumer process on Linux and Android
ARM64, with acceptable measured mobile resource and notification tradeoffs?

Candidates: VPP `svm_msg_q` at the product pin
`9258530f3804a152578ce11cc7c8a1e9eab88ed0` with existing target profile; Aeron
1.53.2 C SPSC subset at `664f58e705f850dfb926f6293707b204ba804726`.
No third implementation unless both prove unsuitable. No product backend or
framework selection is implicit in completing the experiment.

## Common contract

One owner, two separately allocated channels (normal/debug), one Rust consumer.
Each record is a pointer-free, little-endian test envelope with version, length,
generation, monotonic sequence, production timestamp, observation identity,
cumulative counters, and attribution segments. Shapes are 128-byte cumulative,
512-byte attribution, and 2048-byte combined END/tail/attribution records in
70/20/10 distribution. These are representative intervals, not a frozen future
product ABI. Deterministic content checks cover every byte; sequence gaps are
allowed only when producer admission failed. Rust copies/validates before release.

The producer attempts each record once. Full/invalid admission returns immediately
and increments independently readable shared counters. No ACK, retry, replay or
durability guarantee. Each channel has its own capacity and loss ledger.
Fresh generations use fresh mappings; old generations are rejected, not repaired
in place. Processes map at independently selected addresses. The experiment may
inherit setup FDs across fork/exec; product FD negotiation and app identity are
explicit subsequent integration requirements.

Compare nominal 256 KiB data capacity per channel. Aeron uses a 262144-byte byte
ring plus its trailer. VPP uses explicit size classes (128/512/2048 bytes),
with 512/128/64 slots respectively, reserved for the mixture, with
descriptor/header overhead reported separately. These counts were fixed after
the initial build/smoke check (which used 1024/128/32) and before comparative
measurements; smoke numbers are not comparative evidence.
Capacity is compared both in actual bytes and accepted record counts; equal
nominal memory does not imply equal saturation behavior.

## Workload and measurement

Run the same compiled C/Rust code on Linux and ARM64. Matrix includes mixed
continuous bursts, isolated records, batches 1/32/128, idle intervals, forced
consumer pause, no consumer, channel-isolation pressure and fresh-generation
restart. Include invalid size/generation and corrupt-record negative checks.
Use bounded runs and external timeouts so missing notifications fail visibly.
Retain all failed attempts and do not replace them with later passing output.

Record wall/process CPU, producer attempt-time distribution, end-to-end delivery
latency p50/p95/p99/max, offered/accepted/dropped/consumed, record bytes, wake
waits/notifications, context switches, RSS and exact shared allocation. Report
notification strategy explicitly: VPP native eventfd transitions versus Aeron
batch notification; both nonblocking eventfds, sleep only after draining and
rechecking authoritative state. Idle CPU/wakeups are separate from throughput.
Three repetitions of comparative workloads, alternating candidate order, without
claiming statistical population or battery-energy qualification.

Correctness gates: no corrupted, duplicate or reordered accepted records; no
unexplained loss in drain-to-completion runs; no producer wait for consumer;
independent normal/debug failure accounting; clean exit and generation rejection.
There is no invented numerical performance threshold. Recommendation weighs
measured costs, reusable dependency surface, failure semantics and integration
work. Device scope is a native transport experiment, not APK/Doze qualification.

Source, compiler/target, library artifact hashes, options, run IDs and environment
must accompany raw results. An independent verifier checks the producer/consumer
ledgers and negative evidence. T21/E01 must remeasure if actual record sizes,
production rate, owners, topology or runtime profile exceed this envelope.
User result review and explicit direction are mandatory before T20 Done/T21.

## Refinement before the final comparative run

The first full matrix is retained as `*-matrix-a`. Before final `*-matrix-b`,
Aeron notifications are suppressed for batches with no accepted record; rejected
attempts cannot create useful consumer work. The final matrix adds a consumer
exit inside its borrowed-record callback (before slot reclamation), followed by
fresh-generation runs, and records producer idle CPU separately. Neither queue
algorithm, data capacity nor workload distribution changes. This is a protocol
refinement, not a changed acceptance threshold. Native VPP transition notification
and explicit Aeron batch notification remain distinct measured integration choices.

Final timing instrumentation records both the queue-call interval and the full
export attempt including any batch notification (excluding pacing sleep). This
avoids comparing VPP's in-call notification against Aeron's queue call alone.
Consumer latency ends after independent Rust content validation; CPU/RSS include
the common generator, validator and timing arrays. They are not pure library
cost or a model of the future storage pipeline. Source-specific final runs replace
earlier runs only as the comparison reference, never as retained evidence.

## User-authorized third-candidate extension — 2026-09-26

After reviewing the two-candidate result, the user explicitly requested:
“20这里要求继续实行 3种 比较补充上”. This supersedes the earlier condition
that a hand-written ring would be evaluated only if both reuse candidates failed.
This section is registered now, before implementing/running the third candidate;
it was not part of the initial two-candidate registration. No direction is selected.

Add one independent C SPSC variable-byte ring, with 262144 data bytes, an 8-byte
record header, 8-byte alignment, a padding marker at the end, and separate
cache-line-aligned 64-bit head/tail positions. Producer copy precedes a release
tail publication; consumer acquire-loads tail, borrows records, and release-stores
head only after callbacks finish. Producer acquire-loads head before reusing
space. No overwrite, allocation, lock, retry loop or consumer wait in admission.
This code is written for the current contract, not imported from an old daemon,
the retained packet POCs, or an upstream queue implementation.

The existing record shapes, distribution, channel capacities, process setup,
CPU/latency accounting, failure cases and lifecycle contract remain unchanged.
Minimal and Aeron use the same successful-batch eventfd policy; VPP retains its
native transition policy. All three use the same changed harness and are rerun
on Host and Android ARM64, with three repetitions rotating candidate order so
each candidate goes first once. No prior measurements are substituted into the
new primary comparison; the complete prior evidence is snapshotted separately.

Additional correctness cases, outside the primary performance comparison:

- Primitive tests: exact full capacity and no mutation on rejected writes;
  1/7/8/9/127/128/129/511/512/513/2047/2048-byte boundaries; invalid 0/2049-byte
  lengths; padding wrap and UINT64 counter wrap; held callback preventing reuse;
  malformed published header rejection; deterministic FIFO/model stress over
  repeated physical wraps. Run the same primitive binary on Host and ARM64 and
  a Host ASan/UBSan build.
- Cross-process boundary workload: 20000 records, batch32, 1ms requested pacing,
  cyclic lengths 128/129/255/256/511/512/513/1023/1024/2047/2048 bytes. Each candidate
  must deliver all records and pass the independent Rust byte/field checks.
- Notification-window workload: 10000 records, batch1, 100us requested pacing.
  The consumer marks a test-only phase after its empty check, delays 200us, then
  enters poll. Producer never waits for that phase. A separate counter records
  successful publications observed before the consumer leaves that pre-poll
  phase; require positive coverage and no timeout/loss for every candidate.
  This delay is test instrumentation, not a proposed Product sleep policy.

The final matrix is 15 workloads × 3 candidates × 3 repetitions = 135 runs per
platform. Retain raw failures and the original two-candidate results, independently
verify the complete matrix and artifacts, repeat the two-axis review, and return
a three-way recommendation with maintenance costs and contrary measurements.
User result review/selection remains mandatory before Done or T21.
