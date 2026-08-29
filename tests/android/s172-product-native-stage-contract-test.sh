#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
build_script="$repo_root/app/android-runtime/scripts/build-debug-apk.sh"
pinned_revision="$(tr -d '[:space:]' < "$repo_root/src/product/vpp/pinned-vpp-revision.txt")"
expected_patch_series_count=15
expected_patch_series_sha256=96417ad8655f0c8d39a256aaaaf40d3661c9f8599ae1418450f80b25fd9b91bf

# The test accepts only caller-supplied clean product inputs. The VPP stage is
# the sole source for generated headers, host tools, and runtime libraries; no
# independent include tree or source-tree generator is a product input.
source_input="${SAKAMOTO_S172_VPP_SOURCE_DIR:-}"
input_stage="${SAKAMOTO_S172_VPP_STAGE_DIR:-}"
ndk_root="${SAKAMOTO_S172_ANDROID_NDK_ROOT:-/home/js/.local/share/android-sdk/ndk/29.0.14206865}"
python_path="${SAKAMOTO_S172_VPP_PYTHONPATH:-/home/js/android/lineage/external/ply/ply}"
unset SAKAMOTO_VPP_INCLUDE_DIR SAKAMOTO_VPP_SOURCE_REPO

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/sakamoto-172-native-stage.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT

test -x "$build_script"
grep -Fq 'flock' "$build_script"
grep -Fq 'RENAME_NOREPLACE = 1' "$build_script"
grep -Fq 'RENAME_EXCHANGE = 2' "$build_script"
grep -Fq 'publish_product_stage_atomic fresh' "$build_script"
if grep -Fq 'vpp_source_dir/src/tools/vppapigen' "$build_script" || \
    grep -Fq 'vpp_source_dir/src/vpp-api/vapi' "$build_script"; then
  echo "stage-only still depends on source-tree VPP generators" >&2
  exit 1
fi
if grep -Fq 'rm -rf -- "$product_stage"' "$build_script"; then
  echo "stage-only removes the public product stage before publishing" >&2
  exit 1
fi

[[ -n "$input_stage" ]] || {
  echo "set SAKAMOTO_S172_VPP_STAGE_DIR to a clean arm64 VPP stage" >&2
  exit 2
}
[[ -n "$source_input" ]] || {
  echo "set SAKAMOTO_S172_VPP_SOURCE_DIR to the clean pinned VPP checkout" >&2
  exit 2
}

root_index=0
for root_output in / // /// /./; do
  root_index=$((root_index + 1))
  root_version_state="$work_dir/root-$root_index-version-code"
  if SAKAMOTO_VPP_STAGE_DIR="$input_stage" \
      SAKAMOTO_VPP_SOURCE_DIR="$source_input" \
      SAKAMOTO_ANDROID_PRODUCT_STAGE_DIR="$root_output" \
      SAKAMOTO_ANDROID_VERSION_STATE_FILE="$root_version_state" \
      bash "$build_script" --stage-only >"$work_dir/root-$root_index.log" 2>&1; then
    echo "stage-only accepted filesystem-root output: $root_output" >&2
    exit 1
  fi
  grep -Fq 'filesystem root' "$work_dir/root-$root_index.log" || {
    echo "filesystem-root rejection is not explicit: $root_output" >&2
    exit 1
  }
  [[ ! -e "$root_version_state" ]] || {
    echo "filesystem-root validation happened after a version-state side effect: $root_output" >&2
    exit 1
  }
done

# A raw output leaf that is a symlink must be rejected before canonicalization
# and before version-state, lock, or target-directory side effects. Checking a
# normal directory behind the link catches implementations that inspect only
# the canonical path and then follow the link.
symlink_target="$work_dir/product-stage-target"
symlink_leaf="$work_dir/product-stage-link"
symlink_version_state="$work_dir/symlink-version-code"
symlink_lock="$work_dir/.$(basename -- "$symlink_target").lock"
symlink_leaf_lock="$work_dir/.$(basename -- "$symlink_leaf").lock"
mkdir -p -- "$symlink_target"
printf '%s\n' keep-me >"$symlink_target/keep-me"
ln -s -- "$symlink_target" "$symlink_leaf"
if SAKAMOTO_VPP_STAGE_DIR="$input_stage" \
    SAKAMOTO_VPP_SOURCE_DIR="$source_input" \
    SAKAMOTO_ANDROID_PRODUCT_STAGE_DIR="$symlink_leaf" \
    SAKAMOTO_ANDROID_VERSION_STATE_FILE="$symlink_version_state" \
    bash "$build_script" --stage-only >"$work_dir/symlink-output.log" 2>&1; then
  echo "stage-only accepted a symlink product-stage leaf" >&2
  exit 1
fi
grep -Fq 'symlink' "$work_dir/symlink-output.log" || {
  echo "symlink product-stage rejection is not explicit" >&2
  exit 1
}
[[ -L "$symlink_leaf" ]]
[[ -f "$symlink_target/keep-me" ]]
[[ ! -e "$symlink_target/.sakamoto-android-product-stage" ]]
[[ ! -e "$symlink_version_state" ]]
[[ ! -e "$symlink_lock" ]]
[[ ! -e "$symlink_leaf_lock" ]]

stage_dir="$(realpath -e "$input_stage" 2>/dev/null)" || {
  echo "VPP stage cannot be canonicalized" >&2
  exit 1
}
case "${stage_dir,,}" in
  *experiments*|*poc*)
    echo "VPP stage path is a POC/experiment path" >&2
    exit 1
    ;;
esac
test -x "$stage_dir/bin/vpp"
stage_marker="$stage_dir/.sakamoto-android-vpp-stage"
stage_manifest="$stage_dir/android-vpp-stage.properties"
test -f "$stage_marker"
[[ ! -L "$stage_marker" ]]
grep -Fxq 'sakamoto-android-vpp-stage/v1' "$stage_marker"
test -f "$stage_manifest"
[[ ! -L "$stage_manifest" ]]
grep -Fxq 'schema=sakamoto-android-vpp-stage/v1' "$stage_manifest"
grep -Fxq "revision=$pinned_revision" "$stage_manifest"
grep -Fxq "patchSeriesCount=$expected_patch_series_count" "$stage_manifest"
grep -Fxq "patchSeriesSha256=$expected_patch_series_sha256" "$stage_manifest"
grep -Fxq 'api=31' "$stage_manifest"
grep -Fxq 'abi=arm64-v8a' "$stage_manifest"
grep -Fxq 'binary=bin/vpp' "$stage_manifest"
grep -Fxq 'libraries=lib' "$stage_manifest"
grep -Fxq 'headers=include' "$stage_manifest"
grep -Fxq 'hostTools=host-tools' "$stage_manifest"

vpp_include="$stage_dir/include"
host_tools="$stage_dir/host-tools"
test -d "$vpp_include"
test -x "$host_tools/vppapigen"
test -f "$host_tools/vapi_c_gen.py"
test -f "$host_tools/vapi_cpp_gen.py"
for header in \
  vppinfra/clib.h \
  vlib/vlib.h \
  vlibapi/api.h \
  vlibmemory/api.h \
  vnet/plugin/plugin.h \
  vnet/vnet.h \
  vpp/app/version.h; do
  test -f "$vpp_include/$header"
done
for library in \
  libsvm.so \
  libvapiclient.so \
  libvlib.so \
  libvlibapi.so \
  libvlibmemory.so \
  libvlibmemoryclient.so \
  libvnet.so \
  libvppinfra.so; do
  test -f "$stage_dir/lib/$library"
done
test -f "$ndk_root/build/cmake/android.toolchain.cmake"
test -x "$ndk_root/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang"
test -x "$ndk_root/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar"
source_dir="$(realpath -e "$source_input" 2>/dev/null)"
case "${source_dir,,}" in
  *experiments*|*poc*)
    echo "VPP source path is a POC/experiment path" >&2
    exit 1
    ;;
esac
test "$(git -C "$source_dir" rev-parse HEAD)" = "$pinned_revision"
test -z "$(git -C "$source_dir" status --porcelain)"

while IFS= read -r -d '' link; do
  target="$(readlink -- "$link")"
  [[ "$target" != /* ]]
  resolved="$(realpath -e "$link" 2>/dev/null)"
  case "$resolved" in
    "$stage_dir"/*) ;;
    *)
      echo "VPP stage symlink escapes its stage: $link" >&2
      exit 1
      ;;
  esac
done < <(find "$stage_dir" -type l -print0)

# A corrupt stage must fail before any product build. This proves the marker
# is an ownership boundary rather than an informational label.
invalid_stage="$work_dir/invalid-vpp-stage"
mkdir -p "$invalid_stage/bin"
cp -a -- "$stage_dir/bin/vpp" "$invalid_stage/bin/vpp"
cp -a -- "$stage_manifest" "$invalid_stage/android-vpp-stage.properties"
printf '%s\n' wrong-stage >"$invalid_stage/.sakamoto-android-vpp-stage"
if SAKAMOTO_VPP_STAGE_DIR="$invalid_stage" \
    SAKAMOTO_VPP_SOURCE_DIR="$source_dir" \
    SAKAMOTO_ANDROID_NDK_ROOT="$ndk_root" \
    SAKAMOTO_VPP_PYTHONPATH="$python_path" \
    SAKAMOTO_ANDROID_PRODUCT_STAGE_DIR="$work_dir/invalid-product-stage" \
    SAKAMOTO_ANDROID_VERSION_STATE_FILE="$work_dir/invalid-version-code" \
    bash "$build_script" --stage-only >"$work_dir/invalid-stage.log" 2>&1; then
  echo "stage-only accepted a stage with the wrong ownership marker" >&2
  exit 1
fi
grep -Fq 'owned marker' "$work_dir/invalid-stage.log" || {
  echo "invalid stage rejection did not name the owned marker" >&2
  exit 1
}

unowned_product_stage="$work_dir/unowned-product-stage"
mkdir -p "$unowned_product_stage"
printf '%s\n' user-data >"$unowned_product_stage/keep-me"
if SAKAMOTO_VPP_STAGE_DIR="$stage_dir" \
    SAKAMOTO_VPP_SOURCE_DIR="$source_dir" \
    SAKAMOTO_ANDROID_NDK_ROOT="$ndk_root" \
    SAKAMOTO_VPP_PYTHONPATH="$python_path" \
    SAKAMOTO_ANDROID_PRODUCT_STAGE_DIR="$unowned_product_stage" \
    SAKAMOTO_ANDROID_VERSION_STATE_FILE="$work_dir/unowned-version-code" \
    bash "$build_script" --stage-only >"$work_dir/unowned-product-stage.log" 2>&1; then
  echo "stage-only accepted an unowned product stage" >&2
  exit 1
fi
grep -Fq 'unowned product stage' "$work_dir/unowned-product-stage.log" || {
  echo "unowned product stage rejection did not identify ownership" >&2
  exit 1
}
grep -Fxq user-data "$unowned_product_stage/keep-me"

if SAKAMOTO_VPP_STAGE_DIR="$stage_dir" \
    SAKAMOTO_VPP_SOURCE_DIR="$source_dir" \
    SAKAMOTO_ANDROID_API=30 \
    SAKAMOTO_ANDROID_NDK_ROOT="$ndk_root" \
    SAKAMOTO_VPP_PYTHONPATH="$python_path" \
    SAKAMOTO_ANDROID_PRODUCT_STAGE_DIR="$work_dir/api30-product-stage" \
    SAKAMOTO_ANDROID_VERSION_STATE_FILE="$work_dir/api30-version-code" \
    bash "$build_script" --stage-only >"$work_dir/api30.log" 2>&1; then
  echo "stage-only accepted a non-API31 product build" >&2
  exit 1
fi
grep -Fq 'Android API 31' "$work_dir/api30.log" || {
  echo "non-API31 rejection is not explicit" >&2
  exit 1
}

product_stage="$work_dir/product-stage"
output="$work_dir/stage-output"
export SAKAMOTO_VPP_STAGE_DIR="$input_stage"
export SAKAMOTO_VPP_SOURCE_DIR="$source_dir"
unset SAKAMOTO_VPP_INCLUDE_DIR
export SAKAMOTO_ANDROID_NDK_ROOT="$ndk_root"
export SAKAMOTO_ANDROID_API=31
export SAKAMOTO_VPP_PYTHONPATH="$python_path"
export SAKAMOTO_ANDROID_PRODUCT_STAGE_DIR="$product_stage"
export SAKAMOTO_ANDROID_VERSION_STATE_FILE="$work_dir/version-code"

bash "$build_script" --stage-only > "$output"
grep -Fxq 'mode=stage-only' "$output"
grep -Fxq "productStage=$product_stage" "$output"
grep -Fxq "productCore=$product_stage/lib/arm64-v8a/libsakamoto_product_core.so" "$output"
grep -Fxq "runtimeControl=$product_stage/lib/arm64-v8a/libsakamoto_runtime_control.so" "$output"
grep -Fxq "productPlugin=$product_stage/lib/arm64-v8a/libproduct_core_plugin.so" "$output"

# A second publication exercises the owned-stage exchange path. The old
# public stage remains available until the complete candidate is ready, and
# no hidden candidate may remain after the exchange.
exchange_output="$work_dir/stage-output-exchange"
bash "$build_script" --stage-only > "$exchange_output"
grep -Fxq 'mode=stage-only' "$exchange_output"
if compgen -G "$work_dir/.product-stage.build.*" >/dev/null; then
  echo "product-stage candidate remained after atomic publication" >&2
  exit 1
fi

manifest="$product_stage/product-stage.properties"
native_dir="$product_stage/lib/arm64-v8a"
generated_dir="$product_stage/generated-vapi/vapi"
rust_library="$native_dir/libsakamoto_product_core.so"
jni_library="$native_dir/libsakamoto_runtime_control.so"
plugin="$native_dir/libproduct_core_plugin.so"

test -f "$manifest"
[[ ! -e "$product_stage/.build" ]]
product_marker="$product_stage/.sakamoto-android-product-stage"
test -f "$product_marker"
[[ ! -L "$product_marker" ]]
grep -Fxq 'sakamoto-android-product-stage/v1' "$product_marker"
test -f "$native_dir/libvpp_runtime.so"
test -f "$native_dir/libvapiclient.so"
test -f "$rust_library"
test -f "$jni_library"
test -f "$plugin"
test -f "$generated_dir/product_core.api.vapi.h"
cmp "$stage_dir/bin/vpp" "$native_dir/libvpp_runtime.so"

for library in \
  libsvm.so \
  libvapiclient.so \
  libvlib.so \
  libvlibapi.so \
  libvlibmemory.so \
  libvlibmemoryclient.so \
  libvnet.so \
  libvppinfra.so; do
  [[ -f "$native_dir/$library" || -L "$native_dir/$library" ]]
done

grep -Fxq 'schema=sakamoto-android-product-stage/v1' "$manifest"
grep -Fxq 'abi=arm64-v8a' "$manifest"
grep -Fxq 'vppBinary=lib/arm64-v8a/libvpp_runtime.so' "$manifest"
grep -Fxq 'productCore=lib/arm64-v8a/libsakamoto_product_core.so' "$manifest"
grep -Fxq 'runtimeControl=lib/arm64-v8a/libsakamoto_runtime_control.so' "$manifest"
grep -Fxq 'productPlugin=lib/arm64-v8a/libproduct_core_plugin.so' "$manifest"
grep -Fxq 'generatedVapi=generated-vapi/vapi/product_core.api.vapi.h' "$manifest"
grep -Fxq 'bridgeSource=src/product/native/sakamoto_product_vapi.c' "$manifest"

# Every staged shared object must be a real arm64-v8a ELF. A text placeholder
# or a host object is not consumable by the APK assembler.
while IFS= read -r artifact; do
  artifact_description="$(file -Lb "$artifact")"
  [[ "$artifact_description" == *'ARM aarch64'* ]]
done < <(find "$product_stage" \( -type f -o -type l \) -name '*.so*' -print | sort)

while IFS= read -r -d '' link; do
  target="$(readlink -- "$link")"
  [[ "$target" != /* ]]
  resolved="$(realpath -e "$link" 2>/dev/null)"
  case "$resolved" in
    "$product_stage"/*) ;;
    *)
      echo "product stage symlink escapes its stage: $link" >&2
      exit 1
      ;;
  esac
done < <(find "$product_stage" -type l -print0)

readelf -d "$rust_library" | grep -F 'libvapiclient.so' >/dev/null
readelf -Ws "$rust_library" | grep -F 'vapi_ctx_alloc' >/dev/null
readelf -d "$jni_library" | grep -F 'libsakamoto_product_core.so' >/dev/null
readelf -Ws "$plugin" | grep -F 'product_core_init' >/dev/null

test "$(find "$native_dir" -maxdepth 1 -type f -name '*.so' | wc -l)" -eq 12
poc_paths="$(cd "$product_stage" && find . -mindepth 1 -print)"
forbidden_path=""
while IFS= read -r path; do
  case "${path,,}" in
    *poc*|*nfqueue*|*hev*|*sucre*|*fixture*)
      forbidden_path="$path"
      break
      ;;
  esac
done <<< "$poc_paths"
if [[ -n "$forbidden_path" ]]; then
  echo "retired or POC artifact entered product stage" >&2
  exit 1
fi

echo "sakamoto-172 native product stage contract: PASS"
