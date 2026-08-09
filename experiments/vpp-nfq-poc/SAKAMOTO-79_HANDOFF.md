# SAKAMOTO-79 handoff — ordered NFQUEUE generation teardown

Status: implementation, deterministic checks, pinned host build, and the
six-case host/netns matrix pass. Plane remains **In Progress** until the
integration owner accepts the POC boundary.

S79 makes teardown an observable state machine in the existing native
`nfqueue_live_poc` plugin. Enable records `ENABLE`; disable first records
`QUIESCE` and removes ingress readers, then records `DRAIN` and drains the
bounded ingress/completion/origin rings while the completion event channel is
still open. Only after obligations are settled does it record
`CLOSE_COMPLETION`, close the event channel, record `CLOSE_CHANNELS`, release
the lane reserves and NFQUEUE handles/sockets, and record `FINISH` to reach
`COMPLETE`. A forced deadline inserts `DRAIN_DEADLINE` before the same close
sequence. A process death is classified separately as
`PROCESS_TERMINATED`; it is never reported as a clean finish.

The completion path remains identity-completable and unevaluated: a valid
packet ID, queue generation, origin lane, and live lane can produce exactly
one terminal `NF_ACCEPT` while draining or at the deadline. Missing or stale
identity is counted as an explicit unknown/unrecoverable outcome, not guessed,
retried, or silently discarded. Old-generation, stale, duplicate, closed-
channel, and late frames are isolated and counted. Completion debt and credits
must settle to zero before channels close. The show command exposes ordered
events, ring depths, resource fds/handles/queues/lanes, completion frames,
obligation/debt/credit residue, late-frame classification, and no-replay
counters.

## Pinned artifact and provenance

The host runner uses the source-owned S73 build lineage:

* VPP revision `9258530f3804a152578ce11cc7c8a1e9eab88ed0` from
  `https://github.com/FDio/vpp.git`.
* `bufferDataSize=9000`.
* Provenance patch SHA-256
  `439ac1c67a76d5bac61aa964f114505884a3eee3254691675362a2601e0a0bc9`.
* Regular-memfd fallback patch SHA-256
  `1ddd591c271860887c8d7576dec1a2d6d1b649dbe1038172fffcf7b76f432afe`.
* Installed `nfqueue_live_poc_plugin.so` SHA-256
  `870e862feeedcf3343805fe220a6a7a0453e86c75793dddafb47aa3b6ac1fcaa`.

The complete generated record is retained at
`work/vpp-s73-install-9258530f3804a152578ce11cc7c8a1e9eab88ed0/s73-provenance.properties`.
The runner copies the artifact from the provenance-bound `lib/vpp_plugins`
directory and rejects a hash mismatch before starting VPP.

## Reproduce

From `experiments/vpp-nfq-poc`:

```sh
SAKAMOTO_POC_TICKET=SAKAMOTO-79 JOBS=12 \
  ./scripts/build-nfqueue-live-poc.sh
./scripts/test-nfqueue-live-poc-s79-runner.sh
rtk unshare -Urn env S79_MATRIX_DIR=/tmp/sakamoto-s79-matrix \
  ./scripts/run-nfqueue-live-poc-s79-matrix.sh
```

The deterministic gate compiles the state model with `-std=c11 -Wall -Wextra
-Werror -O2`, checks the source/runner wiring, and verifies clean residue and
explicit process-failure classification for obligations, buffers, completion
frames, credits, debt, sockets, queues, hooks, and logs.

The live runner owns one disposable namespace, topology, VPP process, runtime,
and evidence directory per case. Its cases are:

| Case | Evidence | Result |
| --- | --- | --- |
| `queue-disable` | `queue-disable/` | stale/duplicate isolation; ordered clean close |
| `clean-stop` | `clean-stop/` | clean stop and process exit |
| `drain-deadline` | `drain-deadline/` | real traffic plus bounded forced deadline |
| `process-termination` | `process-termination/` | SIGKILL with explicit pre-cleanup resource classification |
| `fresh-restart` | `fresh-restart/` | clean stop, new process, generation reset to 1 |
| `multiple-generations` | `multiple-generations/` | three in-process rounds, generations 1/2/3 |

The accepted matrix evidence from the final host run is under
`/tmp/sakamoto-s79-matrix-final/`. Every clean round reported the exact
transition sequence (with `DRAIN_DEADLINE` in the deadline case), zero
outstanding obligations/ring depth/debt/held credits, matched raised/settled
debt and acquired/released credits, `netlink-fd=-1`, `completion-fd=-1`,
`queue-open=0`, `handle-open=0`, and `enabled-lanes=0`. The runner partitions
completion frames into physical attempts, stale frames, and duplicate frames;
physical attempts partition into succeeded/failed-definite/unknown outcomes,
so duplicate or stale input cannot create a second verdict.

The process-death ledger intentionally records:

```text
obligations=EXPLICITLY_CLASSIFIED_PROCESS_FAILURE
buffers=EXPLICITLY_CLASSIFIED_PROCESS_FAILURE
completion-frames=EXPLICITLY_CLASSIFIED_PROCESS_FAILURE
credits=EXPLICITLY_CLASSIFIED_PROCESS_FAILURE
debt=EXPLICITLY_CLASSIFIED_PROCESS_FAILURE
socket=EXPLICITLY_CLOSED_BY_PROCESS_DEATH
queue=EXPLICITLY_CLOSED_BY_PROCESS_DEATH
hooks=PRESENT_BEFORE_SUPERVISOR_CLEANUP
logs=CAPTURED
```

The supervisor then removes the topology and verifies no NFQUEUE firewall
hook remains. No process-death obligation is silently converted into a clean
zero.

## Android proportional check

The required repository wrapper was used for the device preflight:
`./dev/adb devices -l`, `./dev/adb shell id`, and
`./dev/adb shell getprop ro.product.model` resolved Pixel 6a serial
`28201JEGR0XPAJ` (Android 16). No S79 Android VPP/NFQUEUE PASS is claimed:
the device has no active VPP/NFQUEUE process, and the existing Android VPP
SVM backing-path permission failure remains the blocker recorded by S77/S78.
The host/netns matrix is therefore the authoritative S79 live acceptance.

## Scope and preservation

S79 changes only the teardown seam, its state-model/static gate, and the
runner/config/handoff above. S73-S78 identity, envelope, worker ownership,
exactly-once outcome, reserve, handoff, and provenance contracts remain
unchanged. Generated VPP build trees and raw `/tmp` evidence are not committed;
the pinned provenance record and this handoff identify the exact artifact used.
