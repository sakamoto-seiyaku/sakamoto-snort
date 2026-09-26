# E02 SQLite observation storage and matched pipeline results

Campaign: 2026-09-26–27. Task: SAKAMOTO-288. SQLite with bounded Rust-side
merging and batch transactions replaces the provisional JSON snapshot. The
matched measurements substantially reduce retained-history write amplification
and consumer CPU. First-open migration costs more than opening the old snapshot;
durable visibility now follows the explicitly accepted batching boundary.
This is a scoped implementation result, not a numerical performance gate,
electrical-energy result or release qualification.

## Implemented boundary

The [E02 contract](../interfaces/E02_SQLITE_OBSERVATION.md) supersedes T22's
storage implementation. VPP configuration ownership, packet accounting and
the selected `svm_msg_q` wire/layout are unchanged. One Rust live aggregate
includes pending contributions; a bounded dirty-key set identifies SQLite
upserts. Baselines, lifecycle, minutes and metadata advance in one transaction.
Successful commit clears dirty state without adding counts again. The ordinary
API separates live totals, committed totals, pending rows, pending maintenance
and errors. No second aggregation engine, backend selector or UI is added.

Defaults are a one-second monotonic deadline or 2,048 dirty rows, at most 4,096
dirty keys, bundled rusqlite 0.38.0, WAL, `synchronous=FULL`, zero busy timeout
and a Rust-owned checkpoint after every successful batch. The idle queue wait
uses the next deadline. Slow/error/full storage can delay the Rust consumer and
lose explicitly marked observation evidence, but VPP never waits for SQLite.
Uncommitted crash loss is accepted; committed data remains atomic and deduplicated.
The engine settings follow [SQLite's WAL durability semantics](https://sqlite.org/wal.html)
and [PRAGMA contracts](https://sqlite.org/pragma.html).

The import transaction validates the legacy schema, identities and minute/total
conservation, verifies the imported row count/metadata and database integrity,
then commits its migration marker. The original JSON remains intact. A failed
or interrupted import retries that original instead of initializing empty history.

## Comparison identity and scope

The [plan](2026-09-26_E02_SQLITE_PLAN.md), [E01 report](2026-09-26_E01_PIPELINE_RESULTS.md)
and retained raw evidence define the comparison. E01 was not rerun or rewritten.
The compared implementation is **SQLite plus accepted batching**, not an isolated
SQLite-versus-JSON encoding test: E01 fsynced every drained batch, while E02 may
lose its current uncommitted tail. Already committed durability is not weakened.

| Evidence | Source closure |
| --- | --- |
| E01 Linux full matrix | `b17f4dda32a176f7feab96a24973b930fbfe3d57ac02861780aeb7e7ee877f01` |
| E01 pressure and controlled Android | `9e2dc538b4b9ae3e57bd04b51508930553d40783cb1161d888696906c4e5a42b` |
| E02 matched Linux/Android experiment | `e18b74bc7f27a3ae9815d012029e5c47dcda0d693729ed1d8f12108067231fe7` |
| E02 final Product, without experiment overlay | `5f0e31d428b24f10e788a08979003ed5348b91a75795bd6016c4f4f88ed57722` |

E02 retains growth 32 packets/65,536 bytes, producer refresh 1 second, drain 128
records per channel, two owners and the 332,544-byte mapping. The same E01
packet generator supplies 64-byte UDP payloads and 92-byte IPv4 packets. Host
pressure uses low/burst/sustained, 1,276 echo requests plus a final freshness
probe. Android uses the full idle/low/burst/sustained/128-active/128-short/192-pause
workload, with 2,108 requests. Host full load retains the 1,024-flow parked phase.
Synthetic historical baselines have zero contributions and are not a real
attribution/history upper bound.

Primary cost figures below sum closed normal-phase windows, excluding deliberate
pause/recovery. Each SQLite window ends after a normal API query reports no
pending commit or checkpoint work. Direct resource timestamps must follow that
query. Metrics also retain continuous first-normal-send through last-normal-settled
windows, including intervening controls. Freshness probes and startup have
separate evidence. Shutdown commits the conservative termination-gap marker;
that lifecycle metadata write is outside the normal-traffic cost table.

## Matched Host pressure

MB is decimal bytes/1,000,000. CPU counters have 10 ms resolution; values near
zero, and process/thread snapshots sampled at slightly different instants, do
not support fine-grained CPU rankings. All four SQLite cases committed and
checkpointed eight normal batches. All 1,277 echoes returned, and each final
store accounts for 2,554 actual packets with exact directional bytes.

| Seed baselines | E01 consumer CPU ms | E02 consumer CPU ms | E01 process writes MB | E02 process writes MB | E02 store elapsed ms |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 10 | 0 | 0.34 | 0.164 | 36.03 |
| 1,000 | 120 | 10 | 37.68 | 0.197 | 38.06 |
| 10,000 | 790 | 20 | 332.98 | 0.328 | 40.46 |
| 60,000 | 2,800 | 10 | 902.96 | 0.328 | 39.27 |

Startup includes one-time migration of the synthetic JSON and warm filesystem
cache conditions. It is not a cold-start benchmark. SQLite's initial process
writes were 0.106/0.643/5.403/31.863 MB, respectively; these are separate from
the normal-phase writes above. The startup cost is retained, not hidden as
deferred benchmark work.

| Seeds | E01 ready ms | E02 ready ms | E01 HWM KiB | E02 HWM KiB | E02 database MB | Peak sampled owned workspace MB |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 31.80 | 43.06 | 5,732 | 7,480 | 0.008 | 0.041 |
| 1,000 | 32.22 | 51.57 | 7,060 | 8,200 | 0.545 | 1.047 |
| 10,000 | 76.02 | 113.13 | 22,104 | 16,844 | 5.308 | 10.030 |
| 60,000 | 288.14 | 440.91 | 79,996 | 63,428 | 31.769 | 60.015 |

Workspace includes the retained predecessor and observed database/log/shared-memory
files. Between-sample WAL peaks are not claimed to be zero. The implementation
reserves a conservative envelope: 64 MiB database including indexes, a legacy
input bounded at 64 MiB, and WAL/maintenance headroom within 256 MiB. Disabling
cache spill and refusing another write transaction when a required 16 MiB WAL
checkpoint cannot complete bounds maintenance growth. Live row caps and the
4,096 dirty-key cap independently bound Rust state; saturation exposes an error
and incomplete coverage without deleting active baselines.

These are admission/workspace guards, not the completed product retention
policy. Existing T27 / SAKAMOTO-279 owns the 48-hour/30-day/180-day rollups and
ordered quota reclamation. E02 retains first-END 24-hour expiry and does not
claim that filling a 256 MiB production history has been qualified.

## Physical Pixel 6a controlled VPN

The runtime remains the controlled validation profile with
`protectionRunning=false`. Normal phases send 1,916 requests; the complete run
also includes the parked phase. RuntimeService process accounting includes Java,
JNI and diagnostics; the consumer thread is reported separately.

| Starting history | E01 consumer CPU ms | E02 consumer CPU ms | E01 RuntimeService CPU ms | E02 RuntimeService CPU ms | E01 writes MB | E02 writes MB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Empty | 1,730–2,080 | 380 | 2,420–2,810 | 1,050 | 52.46–60.06 | 3.076 |
| 10,000 synthetic baselines | 7,890 | 470 | 8,560 | 1,150 | 771.785 | 3.592 |

The empty/10k runs committed and checkpointed 27/26 normal batches. Store elapsed
time was 319.07/343.95 ms. Final database sizes were 249,856/5,566,464 bytes;
peak sampled workspace was 282,624/10,287,708 bytes, including the 10k predecessor.
Process HWM was 166,344/176,504 KiB, compared with E01's approximately
165,600/181,436 KiB. These single-run observations do not establish a universal
memory advantage or a confidence interval. Whole-runtime readiness polling was
4.54/4.18 seconds and includes VPP/Android lifecycle work; it does not isolate
SQLite startup, and E01 did not retain the same phone readiness measure.

The 10k run returned all 2,108 echoes and stored all 4,216 actual Flow packets,
with no queue loss. Empty history returned 2,107 echoes and stored all 4,215
actual Flow packets. Its one missing reply is present at Host egress and absent
from both device ingress and TUN captures, with zero capture loss; this bounds
the missing packet between those capture points, not inside the observation
store. `pixel-0-network-loss.json` retains its exact payload evidence.

Minute conservation is exact, but placement is approximate. The 10k normal
phases have L1 packet-count difference 42 against exact capture minutes: 21
packets moved across a boundary under last-activity coalescing. Empty history
has L1 zero in this run. Neither result promises exact per-packet timestamps.

## Freshness, pressure and recovery

The separate 20-pair phone tail experiment brackets each normal API query with
device monotonic time. Live visibility is bounded at **344.6–866.6 ms** after the
last send; committed visibility at **1,284.1–1,718.7 ms**. RPC and polling overhead
remain included. These are one-tail intervals, not packet-latency percentiles.
Host pressure probes see live totals at about 1.01 seconds and committed totals
at about 2.01–2.03 seconds, consistent with separate producer and store deadlines.

The full Host parked-consumer run forwards all 3,069 echoes while consumption
is stopped. Final basic count is 6,138, retained contributions 5,174 and failed
record publications 1,435. Missing contributions remain an explicit gap;
publication loss is not a lost-network-packet count. Normal pre-pause store
cost was 30 ms consumer CPU and 1.262 MB process writes. No queue enlargement,
ACK/replay or forced counter reconciliation was introduced.

The 1k Host fault run holds a real competing SQLite write transaction during
burst. API live totals advance while committed totals remain at the prior
boundary and the error is visible. VPP continues forwarding. After release,
committed state reaches all 2,554 contributions without recounting, and the
coverage gap remains visible. Deterministic tests additionally exercise actual
SQLite FULL, transaction abort after baseline writes, bounded dirty saturation,
two failed checkpoints followed by idle recovery, and unsigned counter overflow.

A real child-process exit loses only the uncommitted tail; another test sends
SIGKILL during a legacy import after observing its rollback journal. Reopening
recovers the original history and transaction invariants. These are process and
engine-boundary tests, not a physical power-removal qualification.

Android Root has a separate 20-pair known-flow functional result, with exact
directional packets/bytes, raw SQLite and normal API identity. It is not pooled
into controlled-VPN cost results or used to upgrade E01's strict Root A/B/C HOLD.
The current Root round happened to have zero additional observed Flow packets;
that does not remove the known mixed-UID scope of Root INPUT hooks.

## Real history migration and final device state

The final Product APK is `7f4990ca7bc08f54652fe85ebe4ebea2650f5eba707e44c38820d2ecd04ef42e`,
without the experiment overlay. The installed APK and every native library
match its build manifest. Existing history SHA-256
`75a715a4ce1fd64679631baca1c0d398de3186bf95dad5cdcfa6beabbb9091c4`
matches E01's accepted restoration exactly.

Generations 1622 and 1623 use two actually replaced RuntimeService processes.
SQLite preserves every old baseline, recent lifecycle, minute, counter and
activity bound, including **[318,318] packets and [19152,19152] bytes**. The old
JSON remains byte-identical. Conservative termination gaps advance 2→3→4;
the second start reads SQLite rather than importing the old gap count again.
The final database is 16,384 bytes. Runtime is stopped, KernelSU grant remains
valid, and no VPP/tcpdump process, active owned queue, NFQUEUE rule or owned TUN
remains. The final installed application is the SQLite Product build, not the
old JSON APK or an experimental build.

## Verification and review

Evidence lives under `build-output/e02-20260926/`; `evidence-index.json` seals its
inventory and links the unchanged E01 baseline. Entry points are the existing
E01 builders/collectors with explicit `--sqlite`, `verify_e01.py`,
`e01_metrics.py`, `e02-pixel-migration.py` and `verify_e02_migration.py`.
All collectors retain applied configuration, profile/generation, source/artifact
identity, actual captures, API responses, database files and cleanup.

Independent semantic mutations are rejected: 14 for each Host campaign, 13 for
each full phone campaign, 16 for phone freshness, eight for Root's bounded
functional scope and seven for real-history migration. They cover packets,
directions, bytes, generations, raw-store identity, durability/pending claims,
source identity and resource windows that omit deferred work.

Host CTest passes 50/50; ordinary Rust passes 37 tests, with two additional real
C→Rust process tests. Product C transport passes ASan/UBSan/leak checks; pinned
shared VPP libraries are not sanitizer-instrumented. Fresh ARM64 transport and
handshake executables also pass on the actual device in root context.

An early Host compiler-fixture failure applied generated-VAPI flags to the new
third-party SQLite build. The fixture now checks Product-owned C only; the full
suite passes after the fix. The first ARM scratch upload failed because its
directory was root-owned; that retained setup failure was corrected before a
fresh successful run. Neither is relabelled as a Product runtime failure.

Core review found a repeated-checkpoint failure that could strand idle maintenance.
The fix tracks maintenance independently and its regression fails twice, releases
the reader, then proves deadline-driven recovery with no new records and cleared
errors. Final independent [Standards and Spec review](2026-09-26_E02_SQLITE_REVIEW.md)
reports zero remaining findings.
All 34 pre-existing dirty files are preserved. No electrical power, Doze, thermal
steady-state, complete attribution/retention, arbitrary-history or public-release
claim follows from this scoped acceptance.
