# Build and tooling

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
  Host evidence is an explicit build option and must stay outside Android production.
- [Android build entry](../../app/android-runtime/scripts/build-debug-apk.sh)
  stages VPP-native Product artifacts; consult the [app build notes](../../app/android-runtime/README.md)
  and the script's current input contract. Do not substitute POC adapter artifacts.
- [Host launch/query/stop helpers](../../tools/product/) bind artifact and generation
  identity. They are not the root CMake fixture.
- All Android operations use [`dev/adb`](../../dev/adb); read [device precautions](../../dev/README.md).

Build outputs and acceptance witnesses belong in `build-output/`; it contains
irreplaceable raw evidence too, so it is not safe to delete wholesale.
See [tests](../../tests/README.md) for verification layers and
[current mainline](../current/README.md) for readiness limits.
