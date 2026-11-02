# Build and tooling

Read the [compilation cache and artifact-retention constraints](../agents/build-cache.md)
before repeated builds or experiments. Product builders share persistent compiler
intermediates across output directories; unique evidence folders are not caches.

The root CMake project builds C Host semantic/ABI tests. It does not build the
removed C++ daemon or the complete Android VPP artifact.

```sh
cmake -S . -B build-output/host-tests -DCMAKE_BUILD_TYPE=Debug
cmake --build build-output/host-tests --parallel
ctest --test-dir build-output/host-tests --output-on-failure
```

For the real product:

- [Host artifact builder](../../tools/product/build-host-artifact.sh) requires a
  verified pinned VPP stage via `VPP_HOST_STAGE_DIR`; see its input checks.
  `SAKAMOTO_PRODUCT_HOST_EVIDENCE` defaults to `OFF` for the current Product artifact.
  Explicit `ON` is rejected before compilation: the retained legacy Host-only branch
  depends on removed reassembly interfaces;
  see the [refactor verification limits](../maintenance/2026-09-13_KISS_CODE_ORGANIZATION.md).
  Host evidence must stay outside Android production.
- [Android build entry](../../app/android-runtime/scripts/build-debug-apk.sh)
  stages VPP-native Product artifacts; consult the [app build notes](../../app/android-runtime/README.md)
  and the script's current input contract. Do not substitute POC adapter artifacts.
- [Host launch/query/stop helpers](../../tools/product/) bind artifact and generation
  identity. They are not the root CMake fixture.
- All Android operations use [`dev/adb`](../../dev/adb); read [device precautions](../../dev/README.md).

Build outputs belong in `build-output/`. Retain raw data through required
verification, then follow the [retention rules](../agents/build-cache.md).
See [tests](../../tests/README.md) for verification layers and
[current mainline](../current/README.md) for readiness limits.

Completed task outputs can be reduced to compact results and recoverable source
with [the output cleanup helper](../../tools/product/clean-build-output.py).
It previews by default; use `--apply` after the task's verification and lifecycle
cleanup have finished:

```sh
rtk proxy python3 tools/product/clean-build-output.py --root build-output/COMPLETED_TASK --finished
rtk proxy python3 tools/product/clean-build-output.py --root build-output/COMPLETED_TASK --finished --apply
```

`--keep PATH` protects recovery baselines or other current inputs. Compiler caches
and their recorded VPP/source dependencies are protected automatically.
`--keep-raw` leaves the task unchanged. Historical selection uses `--before YYYY-MM-DD`;
review its protected paths and selection before applying it.
The helper stores conclusions and source indexes under `build-output/storage-retained/`,
with shared source contents in `source-objects/`. `--restore-source ARCHIVE --destination NEW_DIR`
materializes the indexed source files. Pruned raw data and historical binaries are
not restored by this command; those runs retain their historical conclusions but
cannot be reverified offline without repeating the experiment.

Product publishers also share identical read-only files under
`build-output/product-published/`. Publication replaces files atomically;
the shared files are separate from mutable compiler outputs. Cleanup removes
publication contents once no output path refers to them.
