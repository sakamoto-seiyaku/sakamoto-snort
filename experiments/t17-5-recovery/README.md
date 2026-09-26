# T17.5 recoverable builder experiment

Experimental component evidence for SAKAMOTO-287, not Product source. Read the
[pre-run plan](PLAN.md), [source investigation](../../docs/reviews/2026-09-26_T17_5_RECOVERABLE_DOMAIN_ROUTES.md)
and [results](../../docs/testing/2026-09-26_T17_5_RECOVERABLE_DOMAIN_BUILD.md).
Never import this harness or introduce a Product multi-backend switch.

The unmodified T17 Valkey rax source is compiled against explicit VPP allocation
functions. `allocator.h` only chooses the quartet; `recovery.c` contains its
implementation plus fault accounting, independent snapshot ownership, queries
and the model of saved-before-compile/active-after-success ordering. No disk
save, Product management API, concurrent worker publication or full policy
compiler is exercised. `cost`, `faults`, `targeted` and `exhaustion` are separate
fresh-process modes, not Product options.

Prerequisites are the accepted T17 immutable source archives, generated normal
and edge workloads, and pinned Host/Android VPP stages. Recreate missing T17
inputs with its [replay instructions](../t17-domain-matcher/README.md). Host
uses GCC; Android uses the existing NDK r29/API31 cross compiler. Use fresh paths:

```sh
rtk proxy python3 experiments/t17-5-recovery/build.py build-output/t175-replay/host
rtk proxy python3 experiments/t17-5-recovery/build.py build-output/t175-replay/android --android
rtk proxy python3 experiments/t17-5-recovery/run.py build-output/t175-replay/host build-output/t175-replay/host-runs
rtk proxy python3 experiments/t17-5-recovery/run.py build-output/t175-replay/android build-output/t175-replay/android-runs --android
rtk proxy python3 experiments/t17-5-recovery/verify.py build-output/t175-replay/host build-output/t175-replay/host-runs
rtk proxy python3 experiments/t17-5-recovery/verify.py build-output/t175-replay/android build-output/t175-replay/android-runs
```

Android access is exclusively repo `./dev/adb`, with the private selector read
from the accepted T16 local result and per-process known Linux ADB-client route.
No APK installation, VPN/Root launch or grant change. Every series uses a nonce
directory, remote binary/library/workload hash checks, a remote timeout, process-exit
verification between cases, and owned-directory cleanup. A transport timeout
retains state and stops; inspect/terminate any nonce-owned process through the
same wrapper and verify exit before another measurement.

`build.json`, `source-closure.json`, source snapshots, commands, compiler output,
raw run results and environment records form the local evidence chain. The
verifier recomputes the source closure against retained archives, binds actual
binary/library/workload bytes, recomputes the original oracle with label sets,
and computes changed memberships by independently shifting list identities.
It rejects missing or modified evidence, foreign identity, failed native runs,
wrong results, publication/cleanup failures and Android non-exit. It is not a
proof against a maliciously rewritten binary and fabricated source records.

`--sanitize` builds an ASan/UBSan host executable; run with `--focused` for small
and edge normal/failure cases. LeakSanitizer is disabled as in retained T17
evidence. The prebuilt VPP allocator is not instrumented; its custom heap lacks
ordinary per-allocation ASan redzones. Adapter live count/usable-byte restoration
checks partial-builder cleanup separately, without claiming whole-process leak
freedom or complete memory-safety certification.

The checked-in CSV contains each final normal measurement. `summarize.py` exports
the named accepted Host `host-d-runs` and ARM64 `android-e-runs` records from the local evidence root. Results from
earlier development builds remain local and are not mixed into the final table.
