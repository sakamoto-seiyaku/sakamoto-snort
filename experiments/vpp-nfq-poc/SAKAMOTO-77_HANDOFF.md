# SAKAMOTO-77 handoff — exactly-once NFQUEUE outcomes

Status: implementation and host acceptance complete; Plane remains **In Progress** pending the next integration decision.

S77 closes each live-buffer obligation with one physical verdict operation. The completion frame preserves the original queue generation, packet ID, origin lane, immutable policy verdict, and terminal intent. Duplicate frames are counted and ignored; stale-generation frames are counted and ignored. There is no retry, alternate-lane re-entry, policy re-evaluation, replacement payload, or verdict rewrite. Completion debt is raised at handoff and settled exactly once with native buffer return.

The evidence separates operation attempts from native backend calls: `physical-verdict-attempts` counts one attempt for each completion identity, `native-verdict-calls` counts calls that reached `nfq_set_verdict`, and `verdict-definite-rejections` counts an operation rejected before that native call. A forced definite-failure injection is therefore one operation attempt and one pre-backend rejection; it is not a native call and is never retried as another operation.

Outcome classification is explicit:

* `SUCCEEDED`: the one native call returned success.
* `FAILED_DEFINITE`: the operation was rejected before the native backend call, or the one native call returned an error. Both are terminal definite failures; neither is retried.
* `OUTCOME_UNKNOWN`: the one native call was issued, but local code cannot prove receiver acceptance; it is never reported as success and is never retried.

## Pinned artifact

The real host/netns runtime uses the source-owned S73 build lineage:

* VPP revision `9258530f3804a152578ce11cc7c8a1e9eab88ed0` from `https://github.com/FDio/vpp.git`.
* `bufferDataSize=9000`.
* Provenance patch SHA-256 `439ac1c67a76d5bac61aa964f114505884a3eee3254691675362a2601e0a0bc9`.
* Regular-memfd fallback patch SHA-256 `1ddd591c271860887c8d7576dec1a2d6d1b649dbe1038172fffcf7b76f432afe`.
* Installed `nfqueue_live_poc_plugin.so` SHA-256 `a0d03ae61d7c960380e84b297b8cd5fea415671ebb8d816a13ae1909a2208c63`.
* Full provenance is in `work/vpp-s73-install-9258530f3804a152578ce11cc7c8a1e9eab88ed0/s73-provenance.properties`.

## Verification

From `experiments/vpp-nfq-poc`:

```sh
./scripts/test-nfqueue-live-poc-s77-outcome.sh
./scripts/test-nfqueue-live-poc-s77-static.sh
rtk unshare -Urn env S77_FAULT=normal S77_OWNER_MODE=remote S77_REGULAR_MEMFD=1 \
  S77_RUNTIME_ROOT=/tmp/sakamoto-vpp-nfqueue-s77-matrix-normal-2 \
  S77_NETNS_STATE=/tmp/sakamoto-nfqueue-s77-state-normal-2 \
  S77_EVIDENCE_DIR=/tmp/sakamoto-s77-evidence-matrix-normal-2 \
  ./scripts/run-nfqueue-live-poc-s77.sh
rtk unshare -Urn env S77_FAULT=failed-definite S77_OWNER_MODE=remote S77_REGULAR_MEMFD=1 \
  S77_RUNTIME_ROOT=/tmp/sakamoto-vpp-nfqueue-s77-matrix-failed-2 \
  S77_NETNS_STATE=/tmp/sakamoto-nfqueue-s77-state-failed-2 \
  S77_EVIDENCE_DIR=/tmp/sakamoto-s77-evidence-matrix-failed-2 \
  ./scripts/run-nfqueue-live-poc-s77.sh
rtk unshare -Urn env S77_FAULT=outcome-unknown S77_OWNER_MODE=remote S77_REGULAR_MEMFD=1 \
  S77_RUNTIME_ROOT=/tmp/sakamoto-vpp-nfqueue-s77-matrix-unknown-2 \
  S77_NETNS_STATE=/tmp/sakamoto-nfqueue-s77-state-unknown-2 \
  S77_EVIDENCE_DIR=/tmp/sakamoto-s77-evidence-matrix-unknown-2 \
  ./scripts/run-nfqueue-live-poc-s77.sh
rtk unshare -Urn env S76_OWNER_MODE=remote S76_REGULAR_MEMFD=1 S76_STRESS=1 \
  S76_STRESS_COUNT=64 S76_NETNS_STATE=/tmp/sakamoto-nfqueue-s76-state-s77-stress-fix-2 \
  S76_EVIDENCE_DIR=/tmp/sakamoto-s76-evidence-s77-stress-fix-2 \
  ./scripts/run-nfqueue-live-poc-s76.sh
```

Observed host/netns results:

| Case | Physical attempts | Native calls | Definite rejects | Succeeded | Failed definite | Unknown | Duplicate | Stale generation | Debt/outstanding | Result |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| normal | 33 | 33 | 0 | 33 | 0 | 0 | 1 | 1 | 0 / 0 | PASS |
| failed-definite | 34 | 33 | 1 | 33 | 1 | 0 | 0 | 0 | 0 / 0 | PASS |
| outcome-unknown | 33 | 33 | 0 | 32 | 0 | 1 | 0 | 0 | 0 / 0 | PASS |

All three runs reported zero verdict-identity mismatches, packet copies, completion debt, and outstanding obligations, with zero retry/re-entry/policy-reevaluation/replacement/rewrite counters. Native buffer returns matched the physical attempts (33 normal, 34 failed-definite, 33 unknown). The normal run's final verdict identity matched `queue-generation=1`, `packet-id=9`; the fault runs preserved their original terminal/policy intent in the deterministic ledger.

The 64-ping remote-owner stress run reported 257 obligations/verdicts/native returns, completion credits `257/257`, identity proof `257/257`, remote handoffs `257/257`, and zero residue obligations.

The runner also accepts a custom `S77_RUNTIME_ROOT`. The normal custom-root evidence at `/tmp/sakamoto-s77-evidence-custom-root` contains generated `startup.conf` paths under `/tmp/sakamoto-vpp-nfqueue-s77-custom-root` (runtime, log, CLI, statseg, and plugin path), with no hard-coded default root.

Raw host evidence:

* `/tmp/sakamoto-s77-evidence-matrix-normal-2/run.log`, `show-before-disable.txt`, `show-after-disable.txt`
* `/tmp/sakamoto-s77-evidence-matrix-failed-2/run.log`, `show-before-disable.txt`, `show-after-disable.txt`
* `/tmp/sakamoto-s77-evidence-matrix-unknown-2/run.log`, `show-before-disable.txt`, `show-after-disable.txt`
* `/tmp/sakamoto-s76-evidence-s77-stress-fix-2/run.log`, `show-before-disable.txt`, `show-after-disable.txt`

## Android proportional check

`./dev/adb devices -l` resolved Pixel 6a serial `28201JEGR0XPAJ`. The Android VPP core and `nfqueue_live_poc_plugin.so` cross-build completed with `VPP_PLUGINS=nfqueue_live_poc`; the corrected staged stripped plugin was hashed `f261a5de7f4faa817c72941e71ccbcf07121091da4bc435c260efe5ab6466e18` and pushed using only the repository `./dev/adb` helper. The device runner is `scripts/android-run-nfqueue-live-s77.sh`.

After the push, the runner reached `show version`, then the device rejected `nfqueue-live-poc enable-dual` and the CLI closed. A direct post-push command captured `nfqueue-live-poc enable-dual: nfq_bind_pf: Operation not permitted` in `/data/local/tmp/vpp-nfq-s77/logs/enable-direct.log`; this is the Android `ksu` root context lacking the NFQUEUE capability, not an S77 outcome-ledger failure. Cleanup left the staged artifact but no VPP process, NFQUEUE queue lines, or NFQUEUE firewall hooks. No Android PASS is claimed; the host/netns runtime is the authoritative S77 acceptance until NFQUEUE capability is available.
