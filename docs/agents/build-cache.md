# Compilation cache and artifact retention

These are build workflow constraints. They apply before new Root/VPN experiments,
repeated acceptance builds, and local build/test helpers.

## Reuse compilation, isolate publication

- Use the current Android and Host Product builders. Their default compilation
  cache is `build-output/product-build-cache/`, owned and keyed by
  [`build-cache.py`](../../tools/product/build-cache.py). Do not put ordinary
  CMake or Cargo intermediates in a per-run `/tmp`, APK stage, or evidence folder.
- A fresh experiment/output directory isolates published artifacts and raw
  results; it must not force recompiling the unchanged dependency graph. Do not
  set a fresh `CARGO_TARGET_DIR` or CMake `-B` for each run just to isolate results.
  The standalone Host CMake suite uses the stable `build-output/host-tests` tree.
- Cache identities include the checkout, platform/ABI/API, compiler and Rust
  toolchain, verified VPP stage/source identity, and compiler flag environment.
  Android and Host are separate. Do not key compilation by the full Product
  source hash or by the unique distribution path: Ninja and Cargo track source
  changes within the cache. CMake options, including batch/verdict mode, are
  checked every invocation. Changed command options or an altered `CMakeCache`
  force configuration; unchanged builds retain CMake/Ninja's automatic dependency
  checks without rerunning every compiler-capability probe.
- APK Java/DEX compilation has a separate `apk/` cache keyed by Android API,
  Android SDK stub, JDK module image/tools and D8. Within that tree, validate the
  Java source set, build pipeline and compiled-output hashes before reuse.
  Source deletion, changed inputs, missing or modified output must rebuild the
  component. Version-code allocation, manifest packaging and signing still run
  for each APK publication.
- The Android VPP runtime builder uses `android-vpp/` in the same owned cache,
  keyed by the immutable pinned VPP/core/profile patch closure and NDK target.
  It prepares and verifies source separately from its persistent CMake tree.
  Reuse the repository API depfile wrapper and cached configure identity so an
  unchanged repeat does not rebuild API consumers or compiler-capability probes.
- Keep generated VAPI paths stable. Cargo must track changes to owned/VPP/generated
  headers and compiler selections, as well as source files; a cache hit never
  bypasses input validation, VPP closure checks or artifact identity checks.
- Serialize writers to the same compilation cache. Keep atomic Android stage
  publication separate, and strip/copy only distribution files. Do not link a
  mutable compiler output directly into frozen evidence or strip it in place.
- `SAKAMOTO_PRODUCT_BUILD_CACHE_DIR` may select another owned real directory below
  this checkout's `build-output`. Symlink paths, unowned nonempty directories,
  and overlap with a distribution are rejected. Never clear the cache as routine
  build cleanup or delete all of `build-output`.

## Verify reuse before repeating expensive work

After changing build/cache logic, run the real native builder twice against the
same validated inputs and different distribution directories. The repeat must
have zero Rust compilations, zero Ninja build actions, unchanged compiled-file
timestamps and byte-identical native payload. Cache-directory existence or a
fast-looking run alone is not proof. Use:

```sh
rtk proxy python3 tests/host/product_build_cache_test.py
# Supply the validated VPP/NDK environment documented by the Android builder.
rtk proxy python3 tests/android/check_build_cache.py \
  --output build-output/cache-reuse-<unique-check>
rtk proxy python3 tests/android/check_apk_build_cache.py \
  --stage build-output/cache-reuse-<unique-check>/stage-repeat \
  --output build-output/apk-cache-reuse-<unique-check>
```

A deliberate cold-build/cache-isolation test is an exception: state why it needs
an empty cache, give it a bounded output directory, and retain its result. An
ordinary Product test or new benchmark cell does not require a cold dependency
build. Fixture ABI transports use a separate cache identity from Product builds.

## Retain evidence without unbounded copies

- Share installed SDK/NDK and Gradle/toolchain dependencies. Pin their versions;
  do not unpack another complete toolchain under each experiment or `/tmp`.
- Keep one reusable compilation tree per compatible toolchain/target identity.
  Retain final APKs, exact matching symbols, source identities, logs and raw
  results needed by verifiers. Intermediate object trees are not independent
  acceptance evidence.
- Freeze binaries by exact content identity and reuse sealed identical copies
  rather than copying hundreds of MiB of debug executables for every case.
  Deduplicate only verified immutable artifacts; never hard-link a mutable build
  cache to archived witnesses. Preserve artifact paths/bytes and verifier inputs.
  Shared frozen aliases are read-only. Any later replacement must use a new file
  and atomic rename; never make an alias writable and modify its shared inode.
- Control failed-test log growth. Keep the diagnostic result and necessary raw
  evidence; do not allow a recursive sanitizer failure to stream without a bound.
- Before cleanup, distinguish active caches, reproducible intermediates, frozen
  artifacts and raw observations. Check actual allocated blocks/inodes, verify
  exact hashes, retain a cleanup manifest, and measure released space afterward.
  Do not delete other projects' results by matching only their directory names.

The October 21 read-only inventory is in
[`storage-audit-20261021/findings.json`](../../build-output/storage-audit-20261021/findings.json).
It is a dated observation, not permission to delete every listed directory.

The [October 21 cache and storage verification](../testing/2026-10-21_BUILD_CACHE_AND_STORAGE.md)
records actual cold/warm builds, invalidation checks and the lossless cleanup.
