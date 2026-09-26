# T20 observation IPC comparison

Disposable C producer / Rust consumer experiment for
[SAKAMOTO-271](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/7d77e5d6-cf66-49f2-ae7b-bec9a12b85ff).
Read the [pre-registration](PLAN.md) and
[measured comparison](../../docs/testing/2026-09-26_T20_OBSERVATION_IPC.md).
The user selection gate lives in Plane. This directory is not Product source,
an ABI to import, a runtime fallback, or the E01 complete observation pipeline.

## Reproduce

Prerequisites: the exact Aeron 1.53.2 checkout, Rust with the Android ARM64 target,
NDK 29/API31, and the existing pinned VPP Host/Android stages named by `build.py`.
The script asserts the Aeron revision and clean checkout. VPP stage properties,
headers, profile inputs and used library hashes are retained in each build record.
Upstream source is Apache-2.0; retain its notices when packaging any selected
dependency. No upstream source is copied into Product by this experiment.

```sh
rtk proxy python3 experiments/t20-observation-ipc/build.py --target host \
  --aeron /tmp/sakamoto-ipc-aeron --output /tmp/t20-host-new
rtk proxy python3 experiments/t20-observation-ipc/build.py --target android \
  --aeron /tmp/sakamoto-ipc-aeron --output /tmp/t20-android-new
rtk proxy python3 experiments/t20-observation-ipc/run.py --target host \
  --build /tmp/t20-host-new --output /tmp/t20-host-runs-new
rtk proxy python3 experiments/t20-observation-ipc/run.py --target android \
  --build /tmp/t20-android-new --output /tmp/t20-pixel-runs-new
rtk proxy python3 experiments/t20-observation-ipc/verify.py \
  /tmp/t20-host-runs-new --build /tmp/t20-host-new
rtk proxy python3 experiments/t20-observation-ipc/verify.py \
  /tmp/t20-pixel-runs-new --build /tmp/t20-android-new
```

The device runner uses only `dev/adb`, chooses the retained T19 Pixel selector,
inherits the existing ADB server configuration, runs serially in a fresh private
directory, hashes the installed executables/libraries and verifies cleanup.
It does not install/start an APK, start VPP, change Root/VPN state or restart adb.
Every matrix run has an external timeout. New output directories are required.
The exploratory `--smoke` mode is not accepted by the final full-matrix verifier.

## Tested seam

`ipc.h` is an opaque C facade used by both programs. Queue layout and atomics stay
inside the C library, so Rust does not duplicate VPP or Aeron internal structs.
The C executable creates a generation-private shared file and nonblocking eventfd,
then fork/execs a real Rust executable. Rust remaps the file independently; the
eventfd is inherited for this experiment. `query` is a third, independent process
which reads admission/loss counters after producer completion. It never consumes
records or relies on successfully exporting a counter record.

The little-endian test envelope uses 64 bytes for version/length, generation,
sequence, timestamp, synthetic observation identity, cumulative byte/packet
counters, shape and channel. Remaining bytes are deterministic attribution/context
sentinels. The 128/512/2048-byte records model cumulative, attribution and combined
END/tail forms; they are not a serialized future Product FlowEntry. Rust verifies
all fields and every sentinel byte before the queue releases the record. The
independent Python verifier checks the offered/admitted/dropped partitions,
consumer counts/sums/xors/bytes, exact workload, fresh generations, process exits,
installed hashes and negative witnesses.

VPP uses `lock_and_alloc_msg_w_ring(..., noblock=1)` then
`add_and_unlock`, one private queue per channel, and a nonblocking eventfd.
The smallest fitting size class is selected without fallback to another class.
Consumer dequeue and release remain ordered. The unsafe convenience `add(nowait)`
path identified by earlier research is not used. Aeron uses only `spsc_rb_write`
and `spsc_rb_read`, plus a batch notification if at least one record was admitted.
Its unused correlation-id path is removed by function-section garbage collection;
there is no Media Driver, JVM, broker or custom ring algorithm.

Both consumers drain bounded batches and recheck authoritative work before
blocking in `poll`. Eventfd retention covers publication before the wait; a
5-second timeout is a failure, not a polling rescue. The done flag is acquired,
then the queues are drained again before exit. Consumer death deliberately leaves
unreleased records in the old generation; a fresh generation replaces the whole
mapping. No in-place repair, ACK or replay is attempted.

## Evidence

Final native artifacts: `build-output/t20-20260926/{host-c,android-c}/build.json`.
Final measured runs: `host-matrix-c/` and `pixel-matrix-d/`, each 78 runs with
three repetitions. Summaries retain min/median/max and every repetition in
`host-summary.json` and `pixel-summary.json`. Raw failures, earlier instrumentation,
smoke and intermediate matrices remain alongside them with their own identities.
The final verifier deliberately rejects incomplete or pre-final matrices.

The final comparison includes queue-call timing and export timing including
notification. Producer CPU also includes synthetic record construction; consumer
CPU/latency include byte validation and timing storage. RSS is per process, so
adding it would double-count shared pages. The Android virtual-address reservation
is not physical RAM. These limits matter when comparing against a future Product
producer and observation store.
