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
  `3aba6098f37fb2dfccdfa37a06c4295f274b594e1fd2cc213495f72de54142d6`.

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
rtk unshare -Urn env S78_REGULAR_MEMFD=1 S78_STRESS_COUNT=16 \
  S78_MATRIX_DIR=/tmp/sakamoto-s78-matrix-final \
  ./scripts/run-nfqueue-live-poc-s78-matrix.sh
```

The matrix starts a fresh VPP process and separate netlink topology for each
case. The evidence directory is `/tmp/sakamoto-s78-matrix-final`.

| Case | Datagrams | Normal capacity/exhaustions | Reserve cap/startup/peak | Direct obligations/completions/direct returns | Reserve exhaustion/loss/degraded | Native returns | Outcomes | Outstanding/residue |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `reserve_direct` | 5 | 0 / 10 | 8 / 32 / 4 | 5 / 5 / 5 | 0 / 0 / 0 | 10 | 5 succeeded | 0 / 0 |
| `reserve_exhaustion` | 7 | 0 / 22 | 2 / 8 / 2 | 4 / 4 / 4 | 14 / 7 / 7 | 11 | 7 succeeded | 0 / 0 |
| `reserve_stress` (`S78_STRESS_COUNT=16`) | 7 | 0 / 70 | 2 / 8 / 2 | 4 / 4 / 4 | 62 / 31 / 31 | 11 | 7 succeeded | 0 / 0 |

The reserve-native-return total includes reserve entries returned after a
nonblocking receive found no datagram; `reserve-direct-native-returns` counts
only the direct ACCEPT branch. This keeps immediate direct completion distinct
from ordinary reserve checkout/return accounting. All cases reported
`reserve-startup-failures=0`, `reserve-inflight-peak=1`,
`dynamic-reserve-growth=0`, `cross-lane-reserve-borrows=0`,
`reserve-blocking-waits=0`, parser/flow/policy/delivery counters `0`, packet
copies `0`, scratch buffers `0`, full-packet memcpy `0`, and per-packet heap
objects `0`.

The exhaustion case recorded three identity-recoverable loss materializations
and four unmaterialized losses. The stress case recorded three and twenty-eight
respectively. Only recoverable loss identities issue the explicit native
infrastructure `NF_DROP`; neither case fabricates policy or delivery evidence.

The deterministic/static check prints:

```text
capacity: normal-peak=3/3 normal-exhaustions=4 reserve-startup=8 reserve-peak=2/2 reserve-inflight-peak=1 reserve-exhaustions=4 losses=4 direct-attempts=8 outcomes=8 native-returns=11 outstanding=0 residue=0 copies=0
S78 deterministic reserve ledger: PASS
```

Raw host evidence is retained at:

* `/tmp/sakamoto-s78-matrix-final/reserve_direct/`
* `/tmp/sakamoto-s78-matrix-final/reserve_exhaustion/`
* `/tmp/sakamoto-s78-matrix-final/reserve_stress/`

Each directory contains `run.log`, `show-before-disable.txt`,
`show-after-disable.txt`, generated startup configuration, and cleanup logs.
The disable/teardown checks leave zero reserve outstanding and zero global
obligation residue.

## Android proportional check

`./dev/adb devices -l` resolves Pixel 6a serial `28201JEGR0XPAJ` and the
repository wrapper remains the only Android transport used. A proportional
device preflight reaches the device, but the existing VPP Android startup
blocker occurs before NFQUEUE reserve exercise:

```text
svm_region_map(mmap open): Permission denied
SIGSEGV while creating /data/local/tmp/vpp-nfq-s77/shm
```

No Android S78 PASS is claimed. This is the same writable-SVM backing-path /
permission failure recorded by S77; host/netns acceptance above is the
authoritative result until an Android SVM path is made writable.

## Scope boundary and accounting

This is a bounded POC reserve seam, not a production allocator or a promise
that reserve loss implies downstream delivery behavior. Normal S73-S77
ownership, handoff, provenance, and exactly-once completion accounting remain
unchanged. Reserve counters expose startup reservations, normal/reserve peak
occupancy, reserve in-flight peak, direct obligations/completions/native
returns, reserve exhaustion/loss/degraded-health outcomes, native returns,
outstanding obligations, and final residue so a reserve loss cannot be hidden
inside a policy verdict or delivery-success metric.
