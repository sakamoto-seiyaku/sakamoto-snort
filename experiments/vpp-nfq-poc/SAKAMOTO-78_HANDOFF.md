# SAKAMOTO-78 handoff — startup-fixed lane-local NFQUEUE reserve

Status: implementation and host acceptance complete; Plane remains **In
Progress** pending integration/product decisions.

S78 adds the smallest real reserve vertical slice to the S73-S77 VPP-native
NFQUEUE probe. Normal ingress can be held at a fixed capacity. When that
capacity is exhausted, each of the four native lanes takes only from its own
startup-fixed reserve entries allocated with `vlib_buffer_alloc` from the
existing VPP pool. Every reserve entry has the same patched contiguous VPP
buffer envelope as normal ingress (`9000` bytes). There is no scratch store,
dynamic reserve growth, cross-lane borrowing, blocking wait, or packet copy.

The reserve completion seam recovers only the original NFQUEUE packet ID from
the already-received span, writes the lane/generation identity, performs one
native `NFQUEUE_LIVE_ACCEPT`, and immediately returns that same VPP buffer on
the origin lane. It does not call the shared envelope parser, callback parser,
worker graph, flow, or policy path. A reserve exhaustion uses one fixed
per-lane loss slot when available; it records bounded degraded health and an
explicit infrastructure loss. If the packet identity cannot be recovered,
the loss is recorded as unmaterialized and no Policy Verdict or delivery
success is claimed.
The positive-capacity host case arms exhaustion only after a real normal VPP
allocation has reached the configured peak, proving the transition without
pre-exhausting the pool.

## Pinned artifact

The host runtime uses the source-owned S73 build lineage:

* VPP revision `9258530f3804a152578ce11cc7c8a1e9eab88ed0` from
  `https://github.com/FDio/vpp.git`.
* `bufferDataSize=9000`.
* Provenance patch SHA-256
  `439ac1c67a76d5bac61aa964f114505884a3eee3254691675362a2601e0a0bc9`.
* Regular-memfd fallback patch SHA-256
  `1ddd591c271860887c8d7576dec1a2d6d1b649dbe1038172fffcf7b76f432afe`.
* Installed `nfqueue_live_poc_plugin.so` SHA-256
  `4dfcd56e9ef95cdd5c29f4aa6870adb899247ab0e9e16e45f817eb834f9f8546`.

Full build provenance is in
`work/vpp-s73-install-9258530f3804a152578ce11cc7c8a1e9eab88ed0/s73-provenance.properties`.
The build was tagged with `SAKAMOTO_POC_TICKET=SAKAMOTO-78`.

## Verification

From `experiments/vpp-nfq-poc`:

```sh
SAKAMOTO_POC_TICKET=SAKAMOTO-78 JOBS=12 \
  PYTHONPATH="$PWD/work/s73-python-venv/lib/python3.13/site-packages" \
  ./scripts/build-nfqueue-live-poc.sh
./scripts/test-nfqueue-live-poc-s78-reserve.sh
rtk unshare -Urn env S78_REGULAR_MEMFD=1 S78_STRESS_COUNT=64 \
  S78_MATRIX_DIR=/tmp/sakamoto-s78-matrix-faultfix2 \
  ./scripts/run-nfqueue-live-poc-s78-matrix.sh
rtk unshare -Urn env S78_FAULT=reserve-receive-fault S78_REGULAR_MEMFD=1 \
  S78_EVIDENCE_DIR=/tmp/sakamoto-s78-recvfault \
  ./scripts/run-nfqueue-live-poc-s78.sh
```

The matrix starts a fresh VPP process and separate netlink topology for each
case. The positive exhaustion case uses `normal-capacity=1` with
`arm-normal-capacity-exhaustion-after-fill`; the direct and stress cases are
zero-capacity controls. The evidence directory is
`/tmp/sakamoto-s78-matrix-faultfix2`. The runner verifies that the copied
plugin hash equals the pinned `pluginSha256` in the provenance properties.

| Case | Datagrams | Normal capacity/peak/exhaustions | Reserve cap/startup/peak | Direct obligations/completions/direct returns | Reserve exhaustion/loss/degraded | Native returns | Outcomes | Outstanding/residue |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `reserve_direct` | 5 | 0 / 0 / 5 | 8 / 32 / 2 | 5 / 5 / 5 | 0 / 0 / 0 | 5 | 5 succeeded | 0 / 0 |
| `reserve_exhaustion` | 11 | 1 / 1 / 36 | 2 / 8 / 2 | 8 / 8 / 8 | 28 / 28 / 28 | 11 | 11 succeeded | 0 / 0 |
| `reserve_stress` (`S78_STRESS_COUNT=64`) | 11 | 0 / 0 / 133 | 2 / 8 / 2 | 8 / 8 / 8 | 125 / 125 / 125 | 11 | 11 succeeded | 0 / 0 |

The reserve-native-return total includes reserve entries returned after a
nonblocking receive found no datagram; `reserve-direct-native-returns` counts
only the direct ACCEPT branch. This keeps immediate direct completion distinct
from ordinary reserve checkout/return accounting. All cases reported
`reserve-startup-failures=0`, `reserve-inflight-peak=1`,
`dynamic-reserve-growth=0`, `cross-lane-reserve-borrows=0`,
`reserve-blocking-waits=0`, parser/flow/policy/delivery counters `0`, packet
copies `0`, scratch buffers `0`, full-packet memcpy `0`, and per-packet heap
objects `0`.

The positive exhaustion case recorded two identity-recoverable loss
materializations and 26 unmaterialized losses. The stress case recorded three
and 122 respectively. Only successful native `NF_DROP` outcomes are counted
in `reserve-loss-native-drops` (two and three); failed-definite and unknown
outcomes have separate bounded counters and do not fabricate delivery or
policy evidence. The aggregate and every lane satisfy the exact partition
`reserve-losses = reserve-loss-materializations + reserve-loss-unmaterialized`.
A zero-time netlink readiness check prevents an EAGAIN callback from
consuming a reserve entry speculatively.

The correction slice also makes startup partial-allocation release idempotent
by transferring each index to a sentinel before freeing it. It records
non-transient receive faults as degraded health, returns the acquired VPP
buffer exactly once, removes the faulted lane from the file event loop, and
yields the callback without a persistent re-entry loop. Missing packet
identity is counted only as unmaterialized loss/materialization failure; it
does not increment the materialization partition.

The deterministic/static check prints:

```text
startup partial allocation: owned=3 frees=3 repeated-release=1
fault accounting: loss-materialized=3 loss-unmaterialized=1 identity-misses=1 loss-drops=1 failed=1 unknown=1 receive-faults=1 callback-yields=1 disables=1 buffer-returns=1 degraded=2
capacity: normal-peak=3/3 normal-exhaustions=4 reserve-startup=8 reserve-peak=2/2 reserve-inflight-peak=1 reserve-exhaustions=4 losses=4 direct-attempts=8 outcomes=8 native-returns=11 outstanding=0 residue=0 copies=0
S78 deterministic reserve ledger: PASS
```

Raw host evidence is retained at:

* `/tmp/sakamoto-s78-matrix-faultfix2/reserve_direct/`
* `/tmp/sakamoto-s78-matrix-faultfix2/reserve_exhaustion/`
* `/tmp/sakamoto-s78-matrix-faultfix2/reserve_stress/`
* `/tmp/sakamoto-s78-recvfault/` (post-acquisition non-transient receive-fault injection)

Each directory contains `run.log`, `show-before-disable.txt`,
`show-after-disable.txt`, generated startup configuration, and cleanup logs.
The disable/teardown checks leave zero reserve outstanding and zero global
obligation residue.

The targeted live receive-fault case completed two reserve obligations and
three native returns, with `reserve-receive-faults=1`,
`reserve-native-buffer-returns=3`, `degraded-health=1`, and one affected lane
disabled; outstanding and residue were both zero. The corrected plugin hash
was `4dfcd56e9ef95cdd5c29f4aa6870adb899247ab0e9e16e45f817eb834f9f8546` in
both the copied artifact and the pinned provenance record.

Post-build S73-S77 checks: S75 passed 17 obligations/verdicts/native returns;
S76 stress passed 257 obligations/verdicts/native returns with 257 credits,
129 proof records, and 129 remote records; S77 normal passed 33 live
obligations/verdicts/native returns; S77 failed-definite passed 34 with
33 successful and one failed native outcome; S77 outcome-unknown passed 32
with 31 successful and one unknown native outcome. All left zero residue.
S73/S74 static and envelope regressions pass; their existing live wrapper
single-worker owner-mismatch limitation remains documented above.

## Android proportional check

`./dev/adb devices -l`, `./dev/adb shell id`, and
`./dev/adb shell getprop ro.product.model` resolve Pixel 6a serial
`28201JEGR0XPAJ` through the repository wrapper. The shell preflight succeeds;
no S78 Android live PASS is claimed because the existing rooted Android VPP
artifact/SVM startup path has not been rerun for this correction slice. The
prior S77 attempt stopped before NFQUEUE reserve exercise with:

```text
svm_region_map(mmap open): Permission denied
SIGSEGV while creating /data/local/tmp/vpp-nfq-s77/shm
```

This is the same writable-SVM backing-path / permission failure recorded by
S77; host/netns acceptance above is the authoritative result until an Android
SVM path is made writable.

## Scope boundary and accounting

This is a bounded POC reserve seam, not a production allocator or a promise
that reserve loss implies downstream delivery behavior. Normal S73-S77
ownership, handoff, provenance, and exactly-once completion accounting remain
unchanged; the S73/S74 live wrapper still has its historical single-worker
`owner-mismatches` acceptance mismatch, while S75, S76, and all S77 live modes
pass. Reserve counters expose startup reservations, normal/reserve peak
occupancy, reserve in-flight peak, direct obligations/completions/native
returns, reserve exhaustion/loss/degraded-health outcomes, native returns,
outstanding obligations, and final residue so a reserve loss cannot be hidden
inside a policy verdict or delivery-success metric.

The correction commit containing this handoff is on top of `1690e43`,
preserving the earlier S78 vertical-slice and runtime fault-matrix commits.
