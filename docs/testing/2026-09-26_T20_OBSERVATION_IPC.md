# T20 observation IPC comparison

[SAKAMOTO-271](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/7d77e5d6-cf66-49f2-ae7b-bec9a12b85ff)
compares reusable C queues for bounded, lossy VPP-to-Rust observation export.
Both candidates pass the measured transport contract. **Recommendation for user
review: Aeron 1.53.2 C SPSC subset**, principally for variable-byte capacity and
explicit batch notification. VPP `svm_msg_q` remains a viable, already-shipped
alternative with lower paced delivery latency in this experiment. There is no
universal CPU winner. T20 remains In Progress until the user reviews these results
and explicitly selects a direction; this report does not select a Product backend.

## Scope and reproducibility

The [pre-registration](../../experiments/t20-observation-ipc/PLAN.md) fixed the
question, candidates, common envelope and judgment criteria before comparison.
The [experiment README](../../experiments/t20-observation-ipc/README.md) gives
the C/Rust seam and build/run/verify commands. No Product source or APK changed.
The existing IPC research supplied the shortlist and API constraints; it was not
relabelled as execution evidence.

- VPP pin: `9258530f3804a152578ce11cc7c8a1e9eab88ed0`, existing Host and
  Android API31/ARM64 profile, including its Bionic adaptations.
- Aeron 1.53.2: `664f58e705f850dfb926f6293707b204ba804726`, C SPSC primitive
  only, with a small initialization-error hook and dead-section elimination.
  No Media Driver, broker, JVM or custom ring implementation.
- Same native source closure on both targets:
  `b0d7d2e3202700ea1595d51efb0372e80aa734c76720943f0a5a67664c78f3ce`.
  This is SHA-256 of the sorted compact JSON mapping of `ipc.c`, `ipc.h`,
  `producer.c`, `consumer.rs` and `query.c` to their individual hashes.
- Final Host build manifest: `host-c/build.json`, SHA-256
  `20f4d323b974d6dcdf692296f8305cf069a08ec196cd0b887e11e8c16159455b`.
- Final ARM64 build manifest: `android-c/build.json`, SHA-256
  `c1f1800ddf91ae4bc6a9b4caeaf89fe688c244cb5e18bc1ed02046a53bb16c31`.

All local paths above are below `build-output/t20-20260926/`. Build manifests
retain source snapshots, compiler versions/commands, headers, VPP stage/profile
identities and library/executable hashes. Final runs are `host-matrix-c/` and
`pixel-matrix-d/`. The latter reads back SHA-256 for all eight deployed runtime
files before execution. Each run records its generation, settings, process exits,
raw stdout/stderr and independent counter-query result. The verifier and summaries
retain their own identities; `acceptance-index.json` indexes the final evidence.

## Measured contract

One independent C producer process, one Rust consumer process and two separate
normal/debug queues; one thread per endpoint. Shared data capacity is 256 KiB
per channel. VPP has 512 × 128-byte, 128 × 512-byte and 64 × 2048-byte slots,
with 704 descriptors. Aeron has a 262144-byte ring plus its trailer. Shared
requested mapping size, including both channels and the experimental control
header, is 540032 bytes for VPP and 529920 for Aeron; physical mappings are
page-rounded. These are experimental capacities, not Product defaults.

The 128/512/2048-byte synthetic records occur in a 70/20/10 mixture. Their header
contains generation, sequence, cumulative counters, observation identity and
cumulative/attribution/combined-END shape; the remaining context/attribution
bytes are deterministic sentinels. This models record sizes and copying, not the
future semantic encoding or Rust accounting/storage implementation. Three
repetitions alternate candidate order. Batches are 1, 32 and 128; paced batches
sleep a requested 1 ms, sparse records 20 ms, while unpaced bursts offer 200000
records. Actual wall time/rate is retained rather than assuming perfect timers.

VPP uses nonblocking combined allocation/publication and native eventfd
transitions. Aeron sends one eventfd notification per batch containing accepted
records. Normal/debug capacity and loss ledgers are independent, while both
channels share the consumer notification source. Rust drains, rechecks and sleeps;
the 5-second wait timeout is a failure, not a periodic recovery mechanism.

Both final matrices contain **78 runs**, including expected corruption exit 6
and consumer-death exit 42. Per platform, 4,764,666 valid record offers plus one
invalid-length offer per run are accounted for. Independent validation confirms:

- Different producer/consumer mapping addresses, complete byte validation,
  strict accepted-record ordering and matching count/sum/xor/byte ledgers in
  drain-to-completion runs. No unexplained accepted-record loss or wake timeout.
- Queue full, a 700 ms consumer pause, absent/exited consumer, and a consumer
  exiting inside its first borrowed-record callback before releasing the slot.
  The producer finishes all 100000 offers without waiting for the consumer.
- With the consumer absent, Aeron admits 656 records / 256768 payload bytes and
  rejects 99344; VPP admits 704 / 262144 and rejects 99296. VPP's final admitted
  shape distribution differs because its classes fill independently; record
  count alone is not equal useful capacity. Failure counters are independently
  readable by a third process, without consuming or exporting another record.
- Debug pressure leaves all 320 offered normal records delivered without normal
  loss. Debug accepted-but-unread records remain deliberately unconsumed.
- Every run uses a fresh mapping/generation; wrong-generation attachments and
  independent queries reject. After consumer-death cases, fresh producer and
  consumer processes complete the restart workload. Old unread records are
  discarded with their generation, not repaired or replayed.
- The verifier rejects eight altered witnesses: process exit, stale acceptance,
  missing consumer output, corruption, notification failure, identical mappings,
  unexplained loss and inconsistent independent counters. It also requires the
  complete matrix, exact envelope, unique generations and deployed artifact proof.

Accepted-but-unconsumed records in stopped/crashed generations are not guaranteed
delivery. This is intentionally lossy transport, not an ACK or durable channel.

## Android measurements

Pixel ARM64, Android shell UID/SELinux domain, API31 binaries, 4 KiB pages, USB
powered. Environment, battery/thermal snapshots and process lists are retained.
This is process idle on the available phone, not forced Doze, app-identity,
screen-off, energy or supported-device qualification. No wakelock is introduced.

Numbers below are medians of three repetitions. CPU is process CPU milliseconds;
`P/C` means producer/consumer. Delivery latency ends **after Rust byte validation**.
Export p99 includes the queue call and any notification, but excludes pacing
sleep and record construction. Full repetition ranges are in `pixel-summary.json`.

| Workload | Candidate | P/C CPU ms | Export p99 µs | Delivery p99 µs | Consumer wait calls |
| --- | --- | ---: | ---: | ---: | ---: |
| 32000 records, batch 32 | Aeron | 234 / 274 | 57.6 | 983.6 | 1000 |
| same | VPP | 269 / 323 | 59.0 | 572.0 | 1108 |
| 128000 records, batch 128 | Aeron | 596 / 479 | 15.7 | 1718.1 | 999 |
| same | VPP | 503 / 422 | 32.9 | 1092.0 | 2461 |
| 1000 records, batch 1 | Aeron | 71 / 104 | 223.1 | 637.2 | 998 |
| same | VPP | 88 / 104 | 173.8 | 601.2 | 998 |
| 100 sparse records | Aeron | 14.3 / 18.8 | 364.5 | 824.9 | 101 |
| same | VPP | 13.2 / 20.1 | 341.3 | 754.4 | 101 |
| 200000 unpaced offers | Aeron | 120 / 116 | 0.814 | 1363.3 | 67 |
| same | VPP | 134 / 129 | 1.058 | 2425.7 | 1055 |

Paced workloads have zero loss. In the unpaced burst, Aeron admits a median
160073 records (range 144472–166745), versus VPP 108819 (54906–128845); the rest
are counted admission failures. These are overload observations with different
actual producer rates and considerable scheduling variation, not a universal
throughput ranking. VPP's native transitions notify earlier within a batch;
Aeron deliberately waits until its batch boundary. The measured latency/cost
tradeoff therefore includes notification policy, not just the ring algorithm.

At batch 32, notification-inclusive export p99 ranges overlap:
Aeron 56.9–60.1 µs, VPP 58.4–61.6 µs. Looking only at the much smaller Aeron
queue-call time would omit its out-of-call notification and give a misleading
producer-cost comparison. At batch 128 Aeron has fewer wait calls and a lower
export p99, but **higher median total CPU and delivery latency**. No unmeasured
performance threshold or claim of a blanket CPU win is used in the recommendation.

During the 3-second idle interval followed by one record, producer idle CPU is
0.061 ms Aeron / 0.056 ms VPP. Consumer CPU over about 3.18 seconds including the
one-record delivery is 0.758 / 0.748 ms. Each consumer makes one blocking wait
with no timeout; aggregated eventfd values include work and completion signals.
This supports absence of permanent polling in the measured protocol, not a
battery-life claim. With no consumer, 100000 offers finish in median 88.9 / 84.5
ms, with export p99 0.651 / 0.692 µs. The observed maximum is scheduling-sensitive;
nonblocking means no consumer wait, not a hard real-time upper bound.

At batch 32, standalone producer/consumer current RSS medians are 3876/4444 KiB
for Aeron and 4460/4924 KiB for VPP. The native programs include the common
generator, validator and timing arrays; shared pages must not be counted twice.
VPP's experimental private allocator reserves 16 MiB per endpoint. Android
`VmSize` is roughly 10 GiB for both because of runtime address reservations, so
it is not interpretable as physical queue memory or a useful marginal ranking.

The actual ARM64 ELF text/data/bss totals are about 371 KiB for either pair of
programs; VPP additionally loads `libsvm` (~103 KiB) and `libvppinfra` (~456 KiB).
These are ELF section sizes, not RSS. **Those VPP libraries already ship with the
Product and participate in its VAPI closure**, so the standalone difference is
not an incremental APK-size or Product-RSS estimate. Aeron adds a separately
pinned subset; VPP avoids that new dependency.

Host uses the same source and contract. At batch 32 its median export p99 is
17.2 µs Aeron / 17.7 µs VPP, delivery p99 59.0 / 36.6 µs. Host data is retained
separately and is not substituted for ARM64 evidence.

## Recommendation and integration conditions

Recommend **Aeron C SPSC subset** for the user to select if flexible record sizes
and explicit export batching are the preferred tradeoff. Its byte ring avoids
reserving and tuning size classes while the observation layout is evolving;
the measured overload/batch behavior is useful evidence for that direction.
The recommendation is conditional on the measured one-producer/one-consumer,
128–2048-byte envelope and a bounded flush of partial batches. It is not based
on a claim that Aeron is always faster or more energy-efficient.

Choose **VPP `svm_msg_q`** instead if avoiding a new dependency and retaining its
earlier native notification are more valuable. It passes the same contract,
holds slightly more of this saturation workload and has lower paced delivery
tails here. Its size-class reservation, native notification behavior and same
VPP/libc ABI on both endpoints must remain explicit. No minimum custom ring is
justified while both reuse candidates are suitable.

For either choice, T21 must implement fresh Product code using the selected
dependency and validated contract, not copy this POC. Product work still includes
FD/bootstrap negotiation and identity, mapping permissions, owner/channel lifetime,
safe quiescence before FD/unmap teardown, partial-batch scheduling and actual
record serialization. This experiment uses a generation-private file mapping
and inherited setup eventfd; it does not qualify Product memfd/SCM_RIGHTS or APK
SELinux integration. Notification FD ownership must prevent invalid/closed FD
use; VPP's native error logging is not a new failure-recovery protocol.

T21 and **E01 / SAKAMOTO-274** must compare actual producer sizes/rhythm and
complete collection/storage costs against this envelope. More owners, different
record sizes/distribution, app identity, notification policy or runtime profile
require additional measurements before extending the selection claim. E01 remains
the separate mandatory user review gate for the actual observation pipeline.

## Validation and retained limits

Both final matrices pass the independent verifier, including deliberate failure
cases. C/Rust builds use warnings as errors for experiment code. Python syntax
checks and the experiment catalog's five tests pass. The unchanged Product Debug
suite covers all 50 CTest cases: 49 initially pass, while its Unix-socket lifecycle
test is sandbox-denied; that exact test passes with socket permission (including
21 Rust tests). A separate attempted Release test build is retained: existing
assert-only test variables fail under `-DNDEBUG`; no Product source was changed
to disguise that profile mismatch.

Earlier build failures are retained: upstream VPP header warnings required a
system include path, Aeron's unused correlation-id function initially introduced
an ARM64 atomic link dependency before section elimination, and a conditional
benchmark variable triggered Clang's unused warning. The first adb attempt was
sandbox-denied and was rerun through the same wrapper with permission. Earlier
matrices remain exploratory references; final comparison uses only the final
instrumented source and installed-hash runs. A verifier variable-shadowing error
was corrected before any final PASS or summary was emitted.

Independent Standards and Spec review is recorded in
[the review report](../reviews/2026-09-26_T20_CODE_REVIEW.md). Final device cleanup
removes only the experiment's fresh directory and verifies no owned process
remains. Product/VPN state was not changed. The 34 entering dirty paths remain
preserved; the catalog's prior bytes are checked after removing only T20's new
classification entry. User review/selection and subsequent Product integration
remain outside this experiment's completed execution evidence.
