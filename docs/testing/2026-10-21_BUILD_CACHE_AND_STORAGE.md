# Product build cache and storage verification — 2026-10-21

The Product builders now reuse compilation across distribution directories.
Android native staging, Host native assembly and APK Java/DEX reuse passed real
repeat builds. Lossless deduplication of sealed artifacts released **13.43 GiB**,
including 1.07 GiB of duplicate distributions created by this verification.
This verifies the local build workflow; no APK was installed and no new Root/VPN
traffic or performance acceptance was performed.

The implementation follows commit `4d27ebb4`; exact changed-file identities are
retained in the local [source receipt](../../build-output/build-cache-20261021/source-receipt.json).
The [standing build/retention constraints](../agents/build-cache.md) apply to
subsequent experiments.

## Cause and changes

Previously, Android created CMake and Cargo trees under a fresh temporary stage
and removed them on completion. Both observed builds recompiled 49 Rust crates.
Host compilation lived under the distribution directory, which its builder
removed before each assembly. Output isolation therefore destroyed reuse.

Both builders now keep owned, locked compilation trees under
`build-output/product-build-cache/`, keyed by compatible target, toolchain and
verified VPP inputs. Distribution paths and full Product source hashes are not
cache keys. Ninja/Cargo track source changes; changed CMake options reconfigure
the stable tree. JNI also uses Ninja. Copies are stripped for publication while
compiler outputs remain intact. Generated ABI/header and compiler selections
are explicit Cargo build-script dependencies.

Real repeat builds exposed three additional invalidations, all corrected:

- The pinned VPP API generator omitted its main input from the depfile. A wrapper
  runs the official generator unchanged and adds that dependency while retaining
  imports; pinned VPP source is unchanged.
- libprotoident rewrote an identical generated header on every configuration.
  Its generator now preserves the file when its contents are unchanged.
- Repeated explicit Host configuration rewrote an upstream compiler-probe object.
  Identical configure arguments plus an unchanged `CMakeCache.txt` now reuse the
  existing configuration; Ninja still performs its CMake dependency checks.

APK Java/DEX compilation uses a separate toolchain cache. Reuse checks the source
set, build pipeline and compiled-output hashes; a missing/changed result rebuilds
the component. Android's boot class path, compiler-only LambdaMetafactory support
and single-DEX policy remain enforced. Manifest/version packaging and signing
still run per APK.

## Measured reuse

All repeat checks use a different distribution directory with the same validated
inputs. Native checks compare compiled-file sizes/timestamps and payload hashes;
APK checks compare class/DEX timestamps, DEX hash and every packaged native file.

| Build | Initial observation | Qualified repeat | Repeat compilation |
| --- | --- | --- | --- |
| Android native | 227.26 s; 49 Rust crates and 656 native build steps | 0.86 s | 0 Rust, 0 Ninja actions; 757 compiled files unchanged; all 12 native payload hashes identical |
| Host native | 174.95 s; 49 Rust crates and 657 native build steps | 10.21 s | 0 Rust, 0 Ninja actions; compiled timestamps and payload hashes identical |
| APK assembly | 13.60 s including javac/D8 | 2.27 s including packaging/signing | 0 javac/D8; 178 class/DEX files unchanged; identical DEX/native contents |

These are local elapsed observations with already-available pinned VPP/SDK
inputs, not benchmark guarantees. The qualified native repeats follow fixes to
the initial attempt; cold/warm ratios do not represent a controlled performance
experiment. APK hashes differ because version codes advance.

Retained local records:

- [Android final two-build result](../../build-output/build-cache-20261021/android-final/result.json),
  [Host final result](../../build-output/build-cache-20261021/host-final/result.json),
  [APK final result](../../build-output/build-cache-20261021/apk-final/result.json).
  A [post-format Android repeat](../../build-output/build-cache-20261021/android-post-format/result.json)
  rebuilt only the affected Rust crate/JNI link, then returned to 0.85 s with
  zero compilation and the same payload hashes.
- [Deliberate input invalidation](../../build-output/build-cache-20261021/invalidation/result.json):
  scalar/packed mode changes rebuild the plugin without recompiling Rust
  dependencies; modifying a generated VAPI header rebuilds the Rust C bridge and
  JNI link. Header contents and packed mode were restored; the final repeat has
  zero compilation.
- `tests/host/product_build_cache_test.py`: seven checks cover output-independent
  reuse, toolchain/target separation, ownership/path rejection, writer locking,
  real Ninja option/header invalidation, and Java/pipeline/output invalidation.
- Existing real native-stage contract, staged identity contract, VAPI Cargo
  contract, Product VPP contract, JNI contract and Android Process API contract
  pass. Their logs remain under the same evidence directory.

Initial failures are preserved: Host first lacked Python `ply`; the next strict
Host repeat detected the compiler-probe rewrite. The early Android warm run
still performed native work before the depfile/header corrections. These attempts
are diagnostic records, not qualified cache passes.

Reproduce with validated local prerequisites (the SDK/NDK paths are session-local):

```sh
rtk proxy python3 tests/host/product_build_cache_test.py
rtk proxy env PYTHONPATH=/usr/lib/python3/dist-packages \
  SAKAMOTO_VPP_SOURCE_DIR="$PWD/build-output/pinned-vpp-clean" \
  SAKAMOTO_VPP_STAGE_DIR="$PWD/build-output/s220-20260913/android-stage-b" \
  python3 tests/android/check_build_cache.py \
  --output build-output/cache-reuse-<unique-check>
rtk proxy python3 tests/android/check_apk_build_cache.py \
  --stage build-output/cache-reuse-<unique-check>/stage-repeat \
  --output build-output/apk-cache-reuse-<unique-check>
```

Host uses `VPP_HOST_STAGE_DIR=build-output/s220-20260913/host-stage-b` with the
[Host artifact builder](../../tools/product/build-host-artifact.sh). Keep its
toolchain/VPP identity fixed and select separate `PRODUCT_ARTIFACT_DIR`
destinations; retain the build log and compare compiler outputs, not only time.

## Storage result and retention

The [initial inventory](../../build-output/storage-audit-20261021/findings.json)
found 37.8 GiB under this repo's `build-output`, 12.3 GiB of historical POC work,
and 157.4 GiB under `/tmp`. Full-file hash comparisons found about 16.9 GiB of
redundant large-file allocations in the checked scope, excluding existing hard
links. These figures are dated observations, not a deletion list.

Cleanup ran only after both qualified native cache checks passed. It selected
sealed binary/symbol/APK snapshots and historical frozen executable witnesses,
excluding mutable compilation caches, source, unique binaries and raw results.
Each group required matching full SHA-256, mode, owner and group, with no extended
attributes or live process mapping/open file. Every file was rechecked before
atomic replacement with a hard link. Shared aliases were made read-only.

| Result | Historical artifacts | Finalized verification distributions | Total |
| --- | --- | --- | --- |
| Exact-content groups | 65 | 27 | 92 |
| Original paths retained | 469 | 222 | 691 |
| Redundant allocations replaced | 404 | 195 | 599 |
| Allocated blocks released | 12.363 GiB | 1.066 GiB | 14,419,210,240 bytes / 13.429 GiB |
| Measured filesystem available increase | 12.361 GiB | 1.066 GiB | 14,417,756,160 bytes / 13.428 GiB |

The [cleanup result](../../build-output/build-cache-20261021/cleanup-result.json)
and [journal](../../build-output/build-cache-20261021/dedup-journal.jsonl) retain
original metadata, paths, hashes and each replacement. A separate
[postcheck](../../build-output/build-cache-20261021/cleanup-postcheck.json)
rehashed all canonical artifacts and verified every alias still names its
expected read-only inode. Frozen shared aliases must be replaced by a new file
and atomic rename if future work needs different contents.

Once all builds finished, their redundant published distributions were frozen
and deduplicated separately with the same guards. The
[verification cleanup](../../build-output/build-cache-20261021/verification-cleanup-result.json),
[separate journal](../../build-output/build-cache-20261021/verification-dedup-journal.jsonl)
and [combined result](../../build-output/build-cache-20261021/final-storage-result.json)
retain this second phase. It does not link any distribution to a mutable compiler
output. The final local compilation caches occupy about 516 MiB.

Shared Android inputs remain installed once: active NDK 29 is about 2.35 GiB.
The Lineage tree also supplies actual Android SDK/signing inputs and was not
removed. Historical POC trees and unique debug binaries were retained. Native
compilation caches are separate from all frozen hard-link groups.
