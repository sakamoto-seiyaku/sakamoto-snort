# SAKAMOTO-77 handoff — exactly-once NFQUEUE outcomes

Status: implementation and host acceptance complete; Plane remains **In Progress** pending the next integration decision.

S77 closes each live-buffer obligation with one physical verdict operation. The completion frame preserves the original queue generation, packet ID, origin lane, immutable policy verdict, and terminal intent. Duplicate frames are counted and ignored; stale-generation frames are counted and ignored. There is no retry, alternate-lane re-entry, policy re-evaluation, replacement payload, or verdict rewrite. Completion debt is raised at handoff and settled exactly once with native buffer return.

The evidence separates operation attempts from native backend knowledge: `physical-verdict-attempts` counts one attempt for each completion identity, `native-verdict-calls` counts calls that reached `nfq_set_verdict`, `verdict-definite-rejections` counts an operation rejected before that native call, and `verdict-ambiguous-results` counts an explicitly injected path that withholds a trustworthy operation/result observation. A forced definite-failure injection is therefore one operation attempt and one pre-backend rejection; the ambiguity injection is one operation attempt with no native call and no invented return; neither is retried as another operation. On the normal path, NFQUEUE has no separate ACK: the `nfq_set_verdict(..., NF_ACCEPT/NF_DROP, ...)` call is the NFQ-defined terminal operation, and its return classifies Adapter Completion without making an end-to-end delivery claim.

Outcome classification is explicit:

* `SUCCEEDED`: the one NFQ terminal operation returned a nonnegative result. This records successful completion of the Adapter operation only; it does not prove later network delivery, downstream traffic success, or a separate receiver ACK.
* `FAILED_DEFINITE`: the operation was rejected before the native backend call, or the one native call returned a negative/native error. Both are terminal definite failures; neither is retried.
* `OUTCOME_UNKNOWN`: an explicitly injected genuinely ambiguous operation path produced no trustworthy terminal result. The seam withholds the native operation/result observation, increments `verdict-ambiguous-results`, and does not call `nfq_set_verdict`; it is not assigned after observing an ordinary nonnegative return and is never reported as success or definite failure or retried.

## Pinned artifact

The real host/netns runtime uses the source-owned S73 build lineage:

* VPP revision `9258530f3804a152578ce11cc7c8a1e9eab88ed0` from `https://github.com/FDio/vpp.git`.
* `bufferDataSize=9000`.
* Provenance patch SHA-256 `439ac1c67a76d5bac61aa964f114505884a3eee3254691675362a2601e0a0bc9`.
* Regular-memfd fallback patch SHA-256 `1ddd591c271860887c8d7576dec1a2d6d1b649dbe1038172fffcf7b76f432afe`.
* Installed `nfqueue_live_poc_plugin.so` SHA-256 `51ffda8b4c78a311ac52c35c67cb17a569c978ec49ef053e6abe359a171f0f2e`.
* Full provenance is in `work/vpp-s73-install-9258530f3804a152578ce11cc7c8a1e9eab88ed0/s73-provenance.properties`.

## Verification

From `experiments/vpp-nfq-poc`:

```sh
./scripts/test-nfqueue-live-poc-s77-outcome.sh
./scripts/test-nfqueue-live-poc-s77-static.sh
rtk unshare -Urn env S77_FAULT=normal S77_OWNER_MODE=remote S77_REGULAR_MEMFD=1 \
  S77_RUNTIME_ROOT=/tmp/sakamoto-vpp-nfqueue-s77-matrix-normal-resume \
  S77_NETNS_STATE=/tmp/sakamoto-nfqueue-s77-state-normal-resume \
  S77_EVIDENCE_DIR=/tmp/sakamoto-s77-evidence-matrix-normal-resume \
  ./scripts/run-nfqueue-live-poc-s77.sh
rtk unshare -Urn env S77_FAULT=failed-definite S77_OWNER_MODE=remote S77_REGULAR_MEMFD=1 \
  S77_RUNTIME_ROOT=/tmp/sakamoto-vpp-nfqueue-s77-matrix-failed-resume \
  S77_NETNS_STATE=/tmp/sakamoto-nfqueue-s77-state-failed-resume \
  S77_EVIDENCE_DIR=/tmp/sakamoto-s77-evidence-matrix-failed-resume \
  ./scripts/run-nfqueue-live-poc-s77.sh
rtk unshare -Urn env S77_FAULT=outcome-unknown S77_OWNER_MODE=remote S77_REGULAR_MEMFD=1 \
  S77_RUNTIME_ROOT=/tmp/sakamoto-vpp-nfqueue-s77-matrix-unknown-resume \
  S77_NETNS_STATE=/tmp/sakamoto-nfqueue-s77-state-unknown-resume \
  S77_EVIDENCE_DIR=/tmp/sakamoto-s77-evidence-matrix-unknown-resume \
  ./scripts/run-nfqueue-live-poc-s77.sh
rtk unshare -Urn env S76_OWNER_MODE=remote S76_REGULAR_MEMFD=1 S76_STRESS=1 \
  S76_STRESS_COUNT=64 S76_NETNS_STATE=/tmp/sakamoto-nfqueue-s76-state-s77-resume-stress \
  S76_EVIDENCE_DIR=/tmp/sakamoto-s76-evidence-s77-resume-stress \
  ./scripts/run-nfqueue-live-poc-s76.sh
```

Observed host/netns results:

| Case | Physical attempts | Native calls | Definite rejects | Ambiguous results | Succeeded | Failed definite | Unknown | Duplicate | Stale generation | Debt/outstanding | Result |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| normal | 33 | 33 | 0 | 0 | 33 | 0 | 0 | 1 | 1 | 0 / 0 | PASS |
| failed-definite | 34 | 33 | 1 | 0 | 33 | 1 | 0 | 0 | 0 | 0 / 0 | PASS |
| outcome-unknown (explicit ambiguity injection) | 34 | 33 | 0 | 1 | 33 | 0 | 1 | 0 | 0 | 0 / 0 | PASS |

All three runs reported zero verdict-identity mismatches, packet copies, completion debt, and outstanding obligations, with zero retry/re-entry/policy-reevaluation/replacement/rewrite counters. Native buffer returns matched the physical attempts (33 normal, 34 failed-definite, 34 unknown). Each row partitions physical attempts into native calls, definite rejections, and ambiguous-result injections. The normal run's final verdict identity matched `queue-generation=1`, `packet-id=9`; the fault runs preserved their original terminal/policy intent in the deterministic ledger.

The 64-ping remote-owner stress run reported 257 obligations/verdicts/native returns, completion credits `257/257`, identity proof `257/257`, remote handoffs `257/257`, and zero residue obligations.

The runner also accepts a custom `S77_RUNTIME_ROOT`. The normal custom-root evidence at `/tmp/sakamoto-s77-evidence-custom-root-resume` contains generated `startup.conf` paths under `/tmp/sakamoto-vpp-nfqueue-s77-custom-root-resume` (runtime, log, CLI, statseg, and plugin path), with no hard-coded default root.

Raw host evidence:

* `/tmp/sakamoto-s77-evidence-matrix-normal-resume/run.log`, `show-before-disable.txt`, `show-after-disable.txt`
* `/tmp/sakamoto-s77-evidence-matrix-failed-resume/run.log`, `show-before-disable.txt`, `show-after-disable.txt`
* `/tmp/sakamoto-s77-evidence-matrix-unknown-resume/run.log`, `show-before-disable.txt`, `show-after-disable.txt`
* `/tmp/sakamoto-s77-evidence-custom-root-resume/run.log`, `show-before-disable.txt`, `show-after-disable.txt`
* `/tmp/sakamoto-s76-evidence-s77-resume-stress/run.log`, `show-before-disable.txt`, `show-after-disable.txt`

## Android proportional check

`./dev/adb devices -l` resolved Pixel 6a serial `28201JEGR0XPAJ`. The Android VPP core and `nfqueue_live_poc_plugin.so` cross-build completed with `VPP_PLUGINS=nfqueue_live_poc`; the corrected staged stripped plugin was hashed `f261a5de7f4faa817c72941e71ccbcf07121091da4bc435c260efe5ab6466e18` and pushed using only the repository `./dev/adb` helper. The device runner is `scripts/android-run-nfqueue-live-s77.sh`.

The runner's latest attempt reached `show version` but then lost the CLI connection during `nfqueue-live-poc enable-dual`; the direct reproduction captured `svm_region_map(mmap open): Permission denied` followed by `SIGSEGV` while VPP tried to create `/data/local/tmp/vpp-nfq-s77/shm` under the device's `ksu` root context. This is an Android SVM backing-path/permission blocker before NFQUEUE capability can be exercised, not an S77 outcome-ledger failure. The result directory is `results/sakamoto-77-android-live-20260809-235130`; cleanup left no VPP process, NFQUEUE queue lines, or NFQUEUE firewall hooks. No Android PASS is claimed; the host/netns runtime is the authoritative S77 acceptance until a writable Android SVM path is available.
