# SAKAMOTO-77 handoff — exactly-once NFQUEUE outcomes

Status: implementation and host acceptance complete; Plane remains **In Progress** pending the next integration decision.

S77 closes each live-buffer obligation with one physical native `nfq_set_verdict` attempt. The completion frame preserves the original queue generation, packet ID, origin lane, immutable policy verdict, and terminal intent. Duplicate frames are counted and ignored; stale-generation frames are counted and ignored. There is no retry, alternate-lane re-entry, policy re-evaluation, replacement payload, or verdict rewrite. Completion debt is raised at handoff and settled exactly once with native buffer return.

Outcome classification is explicit:

* `SUCCEEDED`: the one native call returned success.
* `FAILED_DEFINITE`: the one native call returned an error (or the deterministic one-shot failure seam classified that call as a definite failure).
* `OUTCOME_UNKNOWN`: the one native call was issued, but local code cannot prove receiver acceptance; it is never reported as success and is never retried.

## Pinned artifact

The real host/netns runtime uses the source-owned S73 build lineage:

* VPP revision `9258530f3804a152578ce11cc7c8a1e9eab88ed0` from `https://github.com/FDio/vpp.git`.
* `bufferDataSize=9000`.
* Provenance patch SHA-256 `439ac1c67a76d5bac61aa964f114505884a3eee3254691675362a2601e0a0bc9`.
* Regular-memfd fallback patch SHA-256 `1ddd591c271860887c8d7576dec1a2d6d1b649dbe1038172fffcf7b76f432afe`.
* Installed `nfqueue_live_poc_plugin.so` SHA-256 `138660712cfebf9bc1aebe0460e3b3a5a4ee421782e367cec6c68b41f1efb382`.
* Full provenance is in `work/vpp-s73-install-9258530f3804a152578ce11cc7c8a1e9eab88ed0/s73-provenance.properties`.

## Verification

From `experiments/vpp-nfq-poc`:

```sh
./scripts/test-nfqueue-live-poc-s77-outcome.sh
./scripts/test-nfqueue-live-poc-s77-static.sh
rtk unshare -Urn env S77_FAULT=normal S77_OWNER_MODE=remote S77_REGULAR_MEMFD=1 \
  S77_EVIDENCE_DIR=/tmp/sakamoto-s77-evidence-normal \
  ./scripts/run-nfqueue-live-poc-s77.sh
rtk unshare -Urn env S77_FAULT=failed-definite S77_OWNER_MODE=remote S77_REGULAR_MEMFD=1 \
  S77_EVIDENCE_DIR=/tmp/sakamoto-s77-evidence-failed-definite \
  ./scripts/run-nfqueue-live-poc-s77.sh
rtk unshare -Urn env S77_FAULT=outcome-unknown S77_OWNER_MODE=remote S77_REGULAR_MEMFD=1 \
  S77_EVIDENCE_DIR=/tmp/sakamoto-s77-evidence-outcome-unknown \
  ./scripts/run-nfqueue-live-poc-s77.sh
```

Observed host/netns results:

| Case | Physical attempts | Succeeded | Failed definite | Unknown | Duplicate | Stale generation | Debt/outstanding | Result |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| normal | 33 | 33 | 0 | 0 | 1 | 1 | 0 / 0 | PASS |
| failed-definite | 33 | 32 | 1 | 0 | 0 | 0 | 0 / 0 | PASS |
| outcome-unknown | 33 | 32 | 0 | 1 | 0 | 0 | 0 / 0 | PASS |

All three runs reported `native-buffer-returns=33`, `verdict-identity-mismatches=0`, `packet-copies=0`, and zero retry/re-entry/policy-reevaluation/replacement/rewrite counters. The normal run's final verdict identity matched `queue-generation=1`, `packet-id=9`, and the fault runs preserved their original terminal/policy intent in the deterministic ledger.

Raw host evidence:

* `/tmp/sakamoto-s77-evidence-normal/run.log`, `show-before-disable.txt`, `show-after-disable.txt`
* `/tmp/sakamoto-s77-evidence-failed-definite/run.log`, `show-before-disable.txt`, `show-after-disable.txt`
* `/tmp/sakamoto-s77-evidence-outcome-unknown/run.log`, `show-before-disable.txt`, `show-after-disable.txt`

## Android proportional check

`./dev/adb devices -l` resolved Pixel 6a serial `28201JEGR0XPAJ`. The Android VPP core and `nfqueue_live_poc_plugin.so` cross-build completed with `VPP_PLUGINS=nfqueue_live_poc`; the staged stripped plugin was hashed `adf64b89e1f097ebe33e2a8ce626a0f483d4d93092ca140d21964c30e368f0ac` and pushed using only the repository `./dev/adb` helper. The device runner is `scripts/android-run-nfqueue-live-s77.sh`.

The Android native lane is currently blocked before NFQUEUE enable: this device's `ksu` root context rejects VPP SVM backing-file creation under `/data/local/tmp` (`svm_region_map(mmap open): Permission denied` followed by SIGSEGV). The runner's cleanup completed with `vpp_pids=none`, zero `/proc/net/netfilter/nfnetlink_queue` lines, and zero NFQUEUE firewall hooks. No Android PASS is claimed; the host/netns runtime is the authoritative S77 acceptance until the device SVM mount/path is made writable.

