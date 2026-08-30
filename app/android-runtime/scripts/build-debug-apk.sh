#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-172 Android product build boundary.
#
# This script owns the Android product input boundary and the native staging
# seam. The stage-only path is the first real product build slice: it compiles
# the pinned VPP plugin and Product Core against production generated VAPI, then
# emits only the arm64-v8a inputs consumed by the APK assembler.

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
pin_file="$repo_root/src/product/vpp/pinned-vpp-revision.txt"
product_source_manifest="$repo_root/src/product/vpp/product-vpp-artifact.properties"
bridge_source="$repo_root/src/product/native/sakamoto_product_vapi.c"
jni_source="$repo_root/app/android-runtime/src/main/native/sakamoto_product_core_jni.c"
plugin_build_name="product_core_plugin.so"
plugin_name="libproduct_core_plugin.so"
expected_vpp_patch_series_count=15
expected_vpp_patch_series_sha256=96417ad8655f0c8d39a256aaaaf40d3661c9f8599ae1418450f80b25fd9b91bf
default_stage_dir="$repo_root/build-output/android-vpp-runtime/stage"
default_version_state="$repo_root/build-output/android-vpp-runtime/version-code"
product_stage_cleanup_dir=""
apk_cleanup_dir=""

usage() {
  cat >&2 <<'EOF'
usage: build-debug-apk.sh [--dry-run|--stage-only|--apk-only]

Required production VAPI inputs:
  SAKAMOTO_PRODUCT_VAPI_INCLUDE_DIR
  SAKAMOTO_PRODUCT_VAPI_GENERATED_DIR

Optional inputs:
  SAKAMOTO_VPP_STAGE_DIR
  SAKAMOTO_VPP_SOURCE_DIR
  SAKAMOTO_ANDROID_NDK_ROOT
  SAKAMOTO_ANDROID_API
  SAKAMOTO_VPP_PYTHONPATH
  SAKAMOTO_ANDROID_PRODUCT_STAGE_DIR
  SAKAMOTO_ANDROID_VERSION_STATE_FILE
  SAKAMOTO_PRODUCT_PLUGIN

--stage-only requires SAKAMOTO_VPP_STAGE_DIR and SAKAMOTO_VPP_SOURCE_DIR.
The clean stage supplies the generated headers, host tools, and runtime
libraries; the default experiment stage is never selected by that mode.

--apk-only requires an explicit, previously built product stage in
SAKAMOTO_ANDROID_PRODUCT_STAGE_DIR. It consumes that stage without rebuilding
VPP, Product Core, or the product plugin.
EOF
}

die() {
  echo "Android product build: $*" >&2
  exit 2
}

mode=build
case "${1:-}" in
  "") ;;
  --dry-run)
    mode=dry-run
    shift
    ;;
  --stage-only)
    mode=stage-only
    shift
    ;;
  --apk-only)
    mode=apk-only
    shift
    ;;
  --help|-h)
    usage
    exit 0
    ;;
  *)
    usage
    die "unknown option: $1"
    ;;
esac
[[ "$#" -eq 0 ]] || die "unexpected arguments: $*"

[[ -f "$pin_file" ]] || die "pinned VPP revision file is missing"
expected_revision="$(tr -d '[:space:]' < "$pin_file")"
[[ "$expected_revision" =~ ^[[:xdigit:]]{40}$ ]] || \
  die "pinned VPP revision is not a 40-character commit"

[[ -f "$bridge_source" ]] || die "production generated-VAPI bridge source is missing"
[[ -f "$jni_source" ]] || die "Product Core JNI bridge source is missing"

# Both directories are required as a pair for the APK-build boundary. In
# particular, an absent generated directory must not cause a fallback to a
# non-production ABI. Stage-only generates these headers from the pinned VPP
# API and validates them after the plugin build instead.
vapi_include_dir="${SAKAMOTO_PRODUCT_VAPI_INCLUDE_DIR:-}"
vapi_generated_dir="${SAKAMOTO_PRODUCT_VAPI_GENERATED_DIR:-}"
if [[ "$mode" != stage-only && "$mode" != apk-only ]]; then
  if [[ -z "$vapi_include_dir" || -z "$vapi_generated_dir" ]]; then
    die "generated VAPI inputs are required: set SAKAMOTO_PRODUCT_VAPI_INCLUDE_DIR and SAKAMOTO_PRODUCT_VAPI_GENERATED_DIR"
  fi
  [[ -d "$vapi_include_dir" ]] || \
    die "generated VAPI include directory is missing: $vapi_include_dir"
  [[ -d "$vapi_generated_dir" ]] || \
    die "generated VAPI directory is missing: $vapi_generated_dir"

  generated_vapi_header="$vapi_generated_dir/product_core.api.vapi.h"
  if [[ ! -f "$generated_vapi_header" ]]; then
    generated_vapi_header="$vapi_generated_dir/vapi/product_core.api.vapi.h"
  fi
  [[ -f "$generated_vapi_header" ]] || \
    die "generated VAPI product_core.api.vapi.h is missing"

  require_vapi_header() {
    local name="$1"
    if [[ ! -f "$vapi_include_dir/$name" &&
          ! -f "$vapi_include_dir/vapi/$name" &&
          ! -f "$vapi_generated_dir/$name" &&
          ! -f "$vapi_generated_dir/vapi/$name" ]]; then
      die "generated VAPI header is missing: $name"
    fi
  }
  require_vapi_header memclnt.api.vapi.h
  require_vapi_header vlib.api.vapi.h
fi

stage_dir="${SAKAMOTO_VPP_STAGE_DIR:-$default_stage_dir}"
if [[ "$mode" == stage-only && -z "${SAKAMOTO_VPP_STAGE_DIR:-}" ]]; then
  die "stage-only requires an explicit clean arm64 VPP stage in SAKAMOTO_VPP_STAGE_DIR"
fi
if [[ "$mode" != apk-only ]]; then
  [[ -d "$stage_dir" ]] || die "VPP stage directory is missing: $stage_dir"
  vpp_binary="$stage_dir/bin/vpp"
  [[ -f "$vpp_binary" && -x "$vpp_binary" ]] || \
    die "VPP stage does not contain an executable bin/vpp: $vpp_binary"
fi

stage_only_product_stage_input=""
if [[ "$mode" == stage-only || "$mode" == apk-only ]]; then
  if [[ "$mode" == apk-only && -z "${SAKAMOTO_ANDROID_PRODUCT_STAGE_DIR:-}" ]]; then
    die "apk-only requires an explicit product stage in SAKAMOTO_ANDROID_PRODUCT_STAGE_DIR"
  fi
  raw_product_stage_input="${SAKAMOTO_ANDROID_PRODUCT_STAGE_DIR:-$repo_root/build-output/android-product-stage}"
  raw_product_stage_leaf="$raw_product_stage_input"
  while [[ "$raw_product_stage_leaf" != "/" &&
            "$raw_product_stage_leaf" == */ ]]; do
    raw_product_stage_leaf="${raw_product_stage_leaf%/}"
  done
  [[ ! -L "$raw_product_stage_leaf" ]] || \
    die "refusing to use a symlink as the product stage output"
  stage_only_product_stage_input="$(realpath -m -- "$raw_product_stage_input" 2>/dev/null)" || \
    die "product stage directory cannot be canonicalized: $raw_product_stage_input"
  [[ "$stage_only_product_stage_input" != "/" ]] || \
    die "product stage directory cannot be the filesystem root"
fi

version_state_file="${SAKAMOTO_ANDROID_VERSION_STATE_FILE:-$default_version_state}"
version_state_dir="$(dirname -- "$version_state_file")"
mkdir -p -- "$version_state_dir"

if [[ -n "${SAKAMOTO_ANDROID_VERSION_CODE:-}" ]]; then
  version_code="$SAKAMOTO_ANDROID_VERSION_CODE"
  [[ "$version_code" =~ ^[1-9][0-9]*$ ]] || \
    die "SAKAMOTO_ANDROID_VERSION_CODE must be a positive integer"
else
  previous_version=0
  if [[ -f "$version_state_file" ]]; then
    previous_version="$(tr -d '[:space:]' < "$version_state_file")"
    [[ "$previous_version" =~ ^[0-9]+$ ]] || \
      die "version state file is invalid: $version_state_file"
  fi
  # Seconds since epoch gives a new debug version even when a prior build was
  # produced on the same day; the state file handles same-second rebuilds.
  epoch_version="$(date +%s)"
  version_code=$((epoch_version > previous_version ? epoch_version : previous_version + 1))
fi
printf '%s\n' "$version_code" > "$version_state_file"

export SAKAMOTO_PRODUCT_VAPI_REQUIRED=1

build_native_stage() {
  local vpp_source_dir="${SAKAMOTO_VPP_SOURCE_DIR:-}"
  local ndk_root="${SAKAMOTO_ANDROID_NDK_ROOT:-/home/js/.local/share/android-sdk/ndk/29.0.14206865}"
  local android_api="${SAKAMOTO_ANDROID_API:-31}"
  local python_path="${SAKAMOTO_VPP_PYTHONPATH:-}"
  local product_stage_input="$stage_only_product_stage_input"
  local product_stage
  local android_target="aarch64-linux-android"
  local ndk_host="linux-x86_64"
  local ndk_bin="$ndk_root/toolchains/llvm/prebuilt/$ndk_host/bin"
  local android_clang="$ndk_bin/${android_target}${android_api}-clang"
  local llvm_ar="$ndk_bin/llvm-ar"
  local llvm_readelf="$ndk_bin/llvm-readelf"
  local toolchain_file="$ndk_root/build/cmake/android.toolchain.cmake"
  local vpp_apigen
  local vapi_c_gen
  local vapi_cpp_gen
  local stage_include_dir
  local stage_host_tools
  local stage_manifest
  local stage_marker
  local stage_path
  local stage_symlink_target
  local stage_symlink_resolved
  local forbidden_stage_path
  local product_stage_parent
  local product_stage_name
  local product_stage_candidate
  local product_stage_lock
  local product_stage_lock_fd
  local python_bin
  local flock_bin
  local build_root
  local plugin_build
  local plugin_install
  local plugin_source
  local generated_vapi_header
  local cargo_target_dir
  local rust_library
  local jni_library
  local android_sysroot
  local native_dir
  local generated_dir
  local marker
  local runtime_library
  local runtime_artifact
  local runtime_name
  local -a runtime_matches
  local source_head
  local source_status
  local vpp_patch_series_count
  local vpp_patch_series_sha256
  local product_artifact_id
  local product_api_identity
  local product_abi_version
  local product_api_version
  local vpp_binary_sha256
  local generated_api_json
  local generated_api_crc
  local product_api_crc
  local artifact_description
  local rust_dynamic
  local jni_dynamic
  local plugin_symbols
  local -a cmake_args

  [[ -f "$product_source_manifest" ]] || \
    die "product artifact source manifest is missing"
  product_manifest_value() {
    local key="$1"
    awk -F= -v key="$key" '$1 == key { print substr($0, index($0, "=") + 1); exit }' \
      "$product_source_manifest"
  }
  product_artifact_id="$(product_manifest_value artifact.id)"
  product_api_identity="$(product_manifest_value product.api.identity)"
  product_abi_version="$(product_manifest_value product.abi.version)"
  product_api_version="$(product_manifest_value product.api.version)"
  [[ "$product_artifact_id" =~ ^[^[:space:]=]+$ ]] || \
    die "source product artifact identity has an invalid format"
  [[ "$product_api_identity" =~ ^[^[:space:]=]+$ ]] || \
    die "source product API identity has an invalid format"
  [[ "$product_abi_version" == 1 && "$product_api_version" == 1 ]] || \
    die "source product ABI/API versions must be 1"

  [[ -n "$vpp_source_dir" ]] || \
    die "stage-only requires SAKAMOTO_VPP_SOURCE_DIR at the pinned revision"
  [[ -d "$vpp_source_dir" ]] || \
    die "VPP source directory is missing: $vpp_source_dir"
  stage_dir="$(realpath -e "$stage_dir" 2>/dev/null)" || \
    die "VPP stage directory cannot be canonicalized: $stage_dir"
  case "${stage_dir,,}" in
    *experiments*|*poc*) die "stage-only refuses experiment/POC VPP inputs" ;;
  esac
  stage_marker="$stage_dir/.sakamoto-android-vpp-stage"
  stage_manifest="$stage_dir/android-vpp-stage.properties"
  [[ -f "$stage_marker" && ! -L "$stage_marker" ]] || \
    die "VPP stage is missing its owned marker"
  [[ "$(<"$stage_marker")" == "sakamoto-android-vpp-stage/v1" ]] || \
    die "VPP stage has an invalid owned marker"
  [[ -f "$stage_manifest" && ! -L "$stage_manifest" ]] || \
    die "VPP stage manifest is missing"
  require_stage_manifest_line() {
    local expected_line="$1"
    grep -Fxq "$expected_line" "$stage_manifest" || \
      die "VPP stage manifest is missing: $expected_line"
  }
  require_stage_manifest_line "schema=sakamoto-android-vpp-stage/v1"
  require_stage_manifest_line "revision=$expected_revision"
  require_stage_manifest_line "api=31"
  require_stage_manifest_line "abi=arm64-v8a"
  require_stage_manifest_line "binary=bin/vpp"
  require_stage_manifest_line "libraries=lib"
  require_stage_manifest_line "headers=include"
  require_stage_manifest_line "hostTools=host-tools"
  vpp_patch_series_count="$(sed -n 's/^patchSeriesCount=//p' "$stage_manifest")"
  vpp_patch_series_sha256="$(sed -n 's/^patchSeriesSha256=//p' "$stage_manifest")"
  [[ "$vpp_patch_series_count" =~ ^[1-9][0-9]*$ ]] || \
    die "VPP stage manifest has an invalid patch series count"
  [[ "$vpp_patch_series_sha256" =~ ^[[:xdigit:]]{64}$ ]] || \
    die "VPP stage manifest has an invalid patch series hash"
  [[ "$vpp_patch_series_count" == "$expected_vpp_patch_series_count" ]] || \
    die "VPP stage manifest has an unexpected patch series count"
  [[ "$vpp_patch_series_sha256" == "$expected_vpp_patch_series_sha256" ]] || \
    die "VPP stage manifest has an unexpected patch series hash"
  while IFS= read -r -d '' stage_path; do
    case "${stage_path,,}" in
      *poc*|*experiment*|*fixture*|*nfqueue*|*hev*|*sucre*)
        forbidden_stage_path="$stage_path"
        die "stage-only refuses POC/experiment artifact: $forbidden_stage_path"
        ;;
    esac
  done < <(cd "$stage_dir" && find . -mindepth 1 -print0)
  while IFS= read -r -d '' stage_path; do
    stage_symlink_target="$(readlink -- "$stage_path")" || \
      die "cannot read VPP stage symlink: $stage_path"
    [[ "$stage_symlink_target" != /* ]] || \
      die "VPP stage has an absolute symlink: $stage_path"
    stage_symlink_resolved="$(realpath -e "$stage_path" 2>/dev/null)" || \
      die "VPP stage has a dangling symlink: $stage_path"
    case "$stage_symlink_resolved" in
      "$stage_dir"/*) ;;
      *) die "VPP stage symlink escapes its stage: $stage_path" ;;
    esac
  done < <(find "$stage_dir" -type l -print0)
  stage_include_dir="$stage_dir/include"
  stage_host_tools="$stage_dir/host-tools"
  [[ -d "$stage_include_dir" ]] || die "VPP stage include directory is missing"
  [[ -x "$stage_host_tools/vppapigen" ]] || \
    die "VPP stage host tool vppapigen is missing"
  [[ -f "$stage_host_tools/vapi_c_gen.py" &&
     -f "$stage_host_tools/vapi_cpp_gen.py" ]] || \
    die "VPP stage VAPI generators are missing"
  for header in \
    vppinfra/clib.h \
    vlib/vlib.h \
    vlibapi/api.h \
    vlibmemory/api.h \
    vnet/plugin/plugin.h \
    vnet/vnet.h \
    vpp/app/version.h; do
    [[ -f "$stage_include_dir/$header" ]] || \
      die "VPP stage include is missing: $header"
  done
  for runtime_library in \
    libsvm.so \
    libvapiclient.so \
    libvlib.so \
    libvlibapi.so \
    libvlibmemory.so \
    libvlibmemoryclient.so \
    libvnet.so \
    libvppinfra.so; do
    [[ -f "$stage_dir/lib/$runtime_library" ||
       -L "$stage_dir/lib/$runtime_library" ]] || \
      die "VPP stage runtime library is missing: $runtime_library"
  done
  vpp_source_dir="$(realpath -e "$vpp_source_dir" 2>/dev/null)" || \
    die "VPP source directory cannot be canonicalized"
  case "${vpp_source_dir,,}" in
    *experiments*|*poc*) die "stage-only refuses experiment/POC VPP inputs" ;;
  esac
  [[ -d "$ndk_root" ]] || die "Android NDK directory is missing: $ndk_root"
  [[ "$android_api" == "31" ]] || \
    die "only Android API 31 is supported by the product stage"

  if ! command -v git >/dev/null 2>&1; then
    die "git is required to audit the pinned VPP checkout"
  fi
  if ! source_head="$(git -C "$vpp_source_dir" rev-parse HEAD 2>/dev/null)"; then
    die "VPP source directory is not a Git checkout: $vpp_source_dir"
  fi
  [[ "$source_head" == "$expected_revision" ]] || \
    die "VPP source checkout is not at pinned revision $expected_revision"
  source_status="$(git -C "$vpp_source_dir" status --porcelain 2>/dev/null)" || \
    die "cannot inspect VPP source checkout status: $vpp_source_dir"
  [[ -z "$source_status" ]] || \
    die "VPP source checkout must be clean: $vpp_source_dir"

  [[ -f "$vpp_source_dir/src/cmake/VPPConfig.cmake" ]] || \
    die "pinned VPP CMake integration is missing"
  vpp_apigen="$stage_host_tools/vppapigen"
  vapi_c_gen="$stage_host_tools/vapi_c_gen.py"
  vapi_cpp_gen="$stage_host_tools/vapi_cpp_gen.py"

  [[ -f "$toolchain_file" ]] || \
    die "Android NDK CMake toolchain is missing: $toolchain_file"
  [[ -x "$android_clang" ]] || \
    die "Android arm64 clang is missing: $android_clang"
  [[ -x "$llvm_ar" ]] || die "Android LLVM archiver is missing: $llvm_ar"
  [[ -x "$llvm_readelf" ]] || die "Android LLVM readelf is missing: $llvm_readelf"
  for tool in cmake ninja cargo file readelf; do
    command -v "$tool" >/dev/null 2>&1 || die "required build tool is missing: $tool"
  done

  [[ -f "$stage_dir/lib/libvapiclient.so" ]] || \
    die "VPP stage is missing the VAPI client library"
  if ! compgen -G "$stage_dir/lib/*.so" >/dev/null; then
    die "VPP stage has no core shared libraries"
  fi

  [[ "$product_stage_input" != "/" ]] || \
    die "product stage directory cannot be the filesystem root"
  product_stage_name="$(basename -- "$product_stage_input")"
  [[ -n "$product_stage_name" && "$product_stage_name" != "." &&
     "$product_stage_name" != ".." ]] || \
    die "product stage directory name is invalid"
  product_stage_parent_input="$(dirname -- "$product_stage_input")"
  mkdir -p -- "$product_stage_parent_input"
  product_stage_parent="$(realpath -e "$product_stage_parent_input" 2>/dev/null)" || \
    die "product stage parent cannot be canonicalized"
  if [[ -L "$product_stage_input" ]]; then
    die "refusing to use a symlink as the product stage output"
  fi
  product_stage="$product_stage_parent/$product_stage_name"
  case "${product_stage,,}" in
    *experiments*|*poc*) die "stage-only refuses experiment/POC product output" ;;
  esac
  product_stage_lock="$product_stage_parent/.${product_stage_name}.lock"
  [[ ! -L "$product_stage_lock" ]] || \
    die "product stage lock path is a symlink"
  python_bin="$(command -v python3 2>/dev/null || true)"
  flock_bin="$(command -v flock 2>/dev/null || true)"
  [[ -n "$python_bin" && -x "$python_bin" ]] || \
    die "host Python3 is required for atomic product stage publication"
  [[ -n "$flock_bin" && -x "$flock_bin" ]] || \
    die "host flock is required for atomic product stage publication"
  exec {product_stage_lock_fd}>"$product_stage_lock" || \
    die "cannot open product stage lock"
  "$flock_bin" -x "$product_stage_lock_fd" || \
    die "cannot acquire product stage lock"

  assert_owned_product_stage() {
    local existing_marker="$product_stage/.sakamoto-android-product-stage"
    [[ -d "$product_stage" && ! -L "$product_stage" ]] || \
      die "refusing to overwrite an unowned product stage: $product_stage"
    [[ -f "$existing_marker" && ! -L "$existing_marker" ]] || \
      die "refusing to overwrite an unowned product stage: $product_stage"
    [[ "$(<"$existing_marker")" == "sakamoto-android-product-stage/v1" ]] || \
      die "refusing to overwrite an unowned product stage: $product_stage"
  }
  if [[ -e "$product_stage" || -L "$product_stage" ]]; then
    assert_owned_product_stage
  fi
  product_stage_candidate="$(mktemp -d "$product_stage_parent/.${product_stage_name}.build.XXXXXX")"
  product_stage_cleanup_dir="$product_stage_candidate"
  cleanup_product_stage() {
    if [[ -n "$product_stage_cleanup_dir" &&
          -e "$product_stage_cleanup_dir" ]]; then
      rm -rf -- "$product_stage_cleanup_dir"
    fi
  }
  trap cleanup_product_stage EXIT
  build_root="$product_stage_candidate/.build"
  plugin_build="$build_root/product-plugin-build"
  plugin_install="$build_root/product-plugin-install"

  if [[ -n "$python_path" ]]; then
    export PYTHONPATH="$python_path${PYTHONPATH:+:$PYTHONPATH}"
  fi
  cmake_args=(
    -S "$repo_root/src/product/vpp"
    -B "$plugin_build"
    -G Ninja
    -DCMAKE_BUILD_TYPE=Release
    "-DCMAKE_TOOLCHAIN_FILE=$toolchain_file"
    -DANDROID_ABI=arm64-v8a
    "-DANDROID_PLATFORM=android-$android_api"
    "-DVPP_SOURCE_DIR=$vpp_source_dir"
    "-DVPP_INCLUDE_DIR=$stage_include_dir"
    "-DVPP_APIGEN=$vpp_apigen"
    "-DVPP_VAPI_C_GEN=$vapi_c_gen"
    "-DVPP_VAPI_CPP_GEN=$vapi_cpp_gen"
    "-DVPP_LIBRARY_DIR=$stage_dir/lib"
    -DCMAKE_INSTALL_LIBDIR=lib
    "-DCMAKE_INSTALL_PREFIX=$plugin_install"
  )
  cmake "${cmake_args[@]}"
  # VPP_LIBRARY_DIR is the exact runtime library input directory, not the
  # temporary CMake install destination. Build the plugin in place so the
  # clean input stage is never mutated by an install rule.
  cmake --build "$plugin_build" --target product_core_plugin \
    --parallel "${SAKAMOTO_ANDROID_BUILD_JOBS:-2}"
  plugin_source="$plugin_build/lib/vpp_plugins/$plugin_build_name"
  [[ -f "$plugin_source" ]] || \
    die "production VPP plugin was not built: $plugin_source"
  generated_vapi_header="$plugin_build/CMakeFiles/vpp-api/vapi/product_core.api.vapi.h"
  [[ -f "$generated_vapi_header" ]] || \
    die "production generated VAPI header was not produced"
  generated_api_json="$plugin_build/product_core.api.json"
  [[ -f "$generated_api_json" && ! -L "$generated_api_json" ]] || \
    die "production generated product_core.api.json was not produced"
  product_api_crc="$(product_manifest_value product.api.crc)"
  [[ "$product_api_crc" =~ ^[[:xdigit:]]{8}$ ]] || \
    die "source product API CRC has an invalid format"
  generated_api_crc="$(grep -Eio '"vl_api_version"[[:space:]]*:[[:space:]]*"0x?[0-9a-f]{8}"' \
    "$generated_api_json" | sed -E 's/.*0x?([0-9a-f]{8}).*/\1/I' | head -n 1)"
  [[ "$generated_api_crc" =~ ^[[:xdigit:]]{8}$ ]] || \
    die "generated product API CRC is missing"
  [[ "${generated_api_crc,,}" == "${product_api_crc,,}" ]] || \
    die "generated API CRC does not match product identity"
  [[ "${product_api_identity##*@}" == "${generated_api_crc,,}" ]] || \
    die "generated API CRC does not match product identity"

  export CC_aarch64_linux_android="$android_clang"
  export AR_aarch64_linux_android="$llvm_ar"
  export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$android_clang"
  export SAKAMOTO_PRODUCT_VAPI_INCLUDE_DIR="$stage_include_dir"
  export SAKAMOTO_PRODUCT_VAPI_GENERATED_DIR="$plugin_build/CMakeFiles/vpp-api"
  export SAKAMOTO_PRODUCT_VAPI_LIBRARY_DIR="$stage_dir/lib"
  export SAKAMOTO_PRODUCT_VAPI_REQUIRED=1
  export CARGO_TARGET_DIR="$build_root/cargo-target"
  cargo build --release -p sakamoto-product-core --lib --target "$android_target"
  cargo_target_dir="$build_root/cargo-target"
  rust_library="$cargo_target_dir/$android_target/release/libsakamoto_product_core.so"
  [[ -f "$rust_library" ]] || die "Android Product Core artifact was not produced"

  native_dir="$product_stage_candidate/lib/arm64-v8a"
  generated_dir="$product_stage_candidate/generated-vapi/vapi"
  mkdir -p -- "$native_dir" "$generated_dir"
  install -m 0755 "$vpp_binary" "$native_dir/libvpp_runtime.so"
  vpp_binary_sha256="$(sha256sum "$native_dir/libvpp_runtime.so" | awk '{print $1}')"
  [[ "$vpp_binary_sha256" =~ ^[[:xdigit:]]{64}$ ]] || \
    die "installed Product Core VPP executable hash is invalid"
  for runtime_library in \
    libsvm.so \
    libvapiclient.so \
    libvlib.so \
    libvlibapi.so \
    libvlibmemory.so \
    libvlibmemoryclient.so \
    libvnet.so \
    libvppinfra.so; do
    runtime_matches=("$stage_dir/lib/${runtime_library}"*)
    [[ -e "${runtime_matches[0]}" || -L "${runtime_matches[0]}" ]] || \
      die "VPP stage runtime library family is missing: $runtime_library"
    for runtime_artifact in "${runtime_matches[@]}"; do
      [[ -e "$runtime_artifact" || -L "$runtime_artifact" ]] || continue
      runtime_name="$(basename -- "$runtime_artifact")"
      if [[ -L "$runtime_artifact" ]]; then
        # Keep the SONAME symlink and its versioned target together. Android's
        # dynamic linker resolves the NEEDED name recorded by the VPP objects.
        cp -a -- "$runtime_artifact" "$native_dir/$runtime_name"
      else
        install -m 0755 "$runtime_artifact" "$native_dir/$runtime_name"
      fi
    done
    [[ -e "$native_dir/$runtime_library" || -L "$native_dir/$runtime_library" ]] || \
      die "product stage omitted VPP runtime library: $runtime_library"
  done
  install -m 0755 "$rust_library" "$native_dir/libsakamoto_product_core.so"
  android_sysroot="$ndk_root/toolchains/llvm/prebuilt/$ndk_host/sysroot/usr/include"
  jni_library="$native_dir/libsakamoto_runtime_control.so"
  "$android_clang" \
    -std=c11 -Wall -Wextra -Werror -fPIC -shared \
    -I "$android_sysroot" \
    -I "$repo_root/src/product/include" \
    "$jni_source" \
    -L "$native_dir" -Wl,--no-as-needed \
    -Wl,-soname,libsakamoto_runtime_control.so \
    -lsakamoto_product_core -o "$jni_library"
  [[ -f "$jni_library" ]] || die "Product Core JNI library was not produced"
  # Android PackageManager recognizes only lib/<abi>/lib*.so as native
  # payload. Keep the production plugin bytes unchanged while using the
  # linker-prefixed installed name required by that packaging boundary.
  install -m 0755 "$plugin_source" "$native_dir/$plugin_name"
  install -m 0644 "$generated_vapi_header" "$generated_dir/product_core.api.vapi.h"

  for artifact in \
    "$native_dir/libvpp_runtime.so" \
    "$native_dir/libsakamoto_product_core.so" \
    "$native_dir/$plugin_name"; do
    artifact_description="$(file -Lb "$artifact")"
    [[ "$artifact_description" == *'ARM aarch64'* ]] || \
      die "staged artifact is not an arm64-v8a ELF: $artifact"
  done
  for artifact in "$native_dir"/*.so*; do
    [[ -e "$artifact" || -L "$artifact" ]] || continue
    artifact_description="$($llvm_readelf -h "$artifact" 2>/dev/null)" || \
      die "cannot inspect staged ELF: $artifact"
    [[ "$artifact_description" == *AArch64* ]] || \
      die "staged artifact is not an AArch64 ELF: $artifact"
  done
  rust_dynamic="$($llvm_readelf -d "$rust_library" 2>/dev/null)" || \
    die "cannot inspect Product Core dynamic dependencies"
  [[ "$rust_dynamic" == *'libvapiclient.so'* ]] || \
    die "Product Core does not link the staged libvapiclient.so"
  jni_dynamic="$($llvm_readelf -d "$jni_library" 2>/dev/null)" || \
    die "cannot inspect Product Core JNI dynamic dependencies"
  [[ "$jni_dynamic" == *'libsakamoto_product_core.so'* ]] || \
    die "Product Core JNI bridge does not link libsakamoto_product_core.so"
  plugin_symbols="$($llvm_readelf -Ws "$native_dir/$plugin_name" 2>/dev/null)" || \
    die "cannot inspect product plugin symbols"
  [[ "$plugin_symbols" == *product_core_init* ]] || \
    die "product plugin init symbol is missing"
  validate_product_stage_symlinks() {
    local root="$1"
    local link target resolved
    while IFS= read -r -d '' link; do
      target="$(readlink -- "$link")" || \
        die "cannot read product stage symlink: $link"
      [[ "$target" != /* ]] || \
        die "product stage has an absolute symlink: $link"
      resolved="$(realpath -e "$link" 2>/dev/null)" || \
        die "product stage has a dangling symlink: $link"
      case "$resolved" in
        "$root"/*) ;;
        *) die "product stage symlink escapes its stage: $link" ;;
      esac
    done < <(find "$root" -type l -print0)
  }
  validate_product_stage_symlinks "$product_stage_candidate"
  forbidden_stage_path=""
  while IFS= read -r -d '' stage_path; do
    case "${stage_path,,}" in
      *poc*|*experiment*|*fixture*|*nfqueue*|*hev*|*sucre*)
        forbidden_stage_path="$stage_path"
        die "retired or POC artifact entered product stage: $forbidden_stage_path"
        ;;
    esac
  done < <(cd "$product_stage_candidate" && find . -mindepth 1 -print0)
  rm -rf -- "$build_root"
  marker="$product_stage_candidate/.sakamoto-android-product-stage"
  printf '%s\n' 'sakamoto-android-product-stage/v1' >"$marker"
  cat >"$product_stage_candidate/product-stage.properties" <<EOF
schema=sakamoto-android-product-stage/v1
abi=arm64-v8a
androidApi=$android_api
vppRevision=$expected_revision
artifactId=$product_artifact_id
apiIdentity=$product_api_identity
abiVersion=$product_abi_version
apiVersion=$product_api_version
vppBinarySha256=$vpp_binary_sha256
vppPatchSeriesCount=$vpp_patch_series_count
vppPatchSeriesSha256=$vpp_patch_series_sha256
vppBinary=lib/arm64-v8a/libvpp_runtime.so
productCore=lib/arm64-v8a/libsakamoto_product_core.so
runtimeControl=lib/arm64-v8a/libsakamoto_runtime_control.so
productPlugin=lib/arm64-v8a/$plugin_name
generatedVapi=generated-vapi/vapi/product_core.api.vapi.h
bridgeSource=src/product/native/sakamoto_product_vapi.c
EOF

  publish_product_stage_atomic() {
    local operation="$1"
    local target="$2"
    local candidate="$3"
    "$python_bin" - "$operation" "$target" "$candidate" <<'PY'
import ctypes
import os
import sys

AT_FDCWD = -100
RENAME_NOREPLACE = 1
RENAME_EXCHANGE = 2
operation = sys.argv[1]
target_path = os.fsencode(sys.argv[2])
candidate_path = os.fsencode(sys.argv[3])
flags_by_operation = {
    "fresh": RENAME_NOREPLACE,
    "exchange": RENAME_EXCHANGE,
}
try:
    flags = flags_by_operation[operation]
except KeyError:
    print(f"unknown product stage operation: {operation}", file=sys.stderr)
    raise SystemExit(2)

try:
    renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
except AttributeError:
    print("host libc does not provide renameat2", file=sys.stderr)
    raise SystemExit(1)

renameat2.argtypes = [
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_int,
    ctypes.c_char_p,
    ctypes.c_uint,
]
renameat2.restype = ctypes.c_int
if renameat2(
    AT_FDCWD,
    candidate_path,
    AT_FDCWD,
    target_path,
    flags,
) != 0:
    error_number = ctypes.get_errno()
    raise OSError(error_number, os.strerror(error_number))
PY
  }

  # Revalidate the exact ownership marker while holding the publisher lock,
  # then publish without removing an existing public stage first.
  if [[ -e "$product_stage" || -L "$product_stage" ]]; then
    assert_owned_product_stage
    if ! publish_product_stage_atomic exchange "$product_stage" "$product_stage_candidate"; then
      die "atomic product stage exchange is unavailable"
    fi
    old_product_stage="$product_stage_candidate"
    product_stage_cleanup_dir=""
    rm -rf -- "$old_product_stage"
  else
    if ! publish_product_stage_atomic fresh "$product_stage" "$product_stage_candidate"; then
      die "atomic product stage publication failed; output appeared during build or atomic no-replace is unavailable"
    fi
    product_stage_cleanup_dir=""
  fi

  echo "mode=stage-only"
  echo "productStage=$product_stage"
  echo "versionCode=$version_code"
  echo "vppRevision=$expected_revision"
  echo "productCore=$product_stage/lib/arm64-v8a/libsakamoto_product_core.so"
  echo "runtimeControl=$product_stage/lib/arm64-v8a/libsakamoto_runtime_control.so"
  echo "productPlugin=$product_stage/lib/arm64-v8a/$plugin_name"
}

build_apk_only() {
  local product_stage_input="$stage_only_product_stage_input"
  local product_stage
  local product_marker
  local product_manifest
  local vpp_patch_series_count
  local vpp_patch_series_sha256
  local native_dir
  local plugin_source
  local stage_path
  local symlink_target
  local symlink_resolved
  local forbidden_path
  local android_api=31
  local target_api=36
  local android_jar="${SAKAMOTO_ANDROID_ANDROID_JAR:-/home/js/android/lineage/prebuilts/sdk/36/public/android.jar}"
  local aapt2="${SAKAMOTO_ANDROID_AAPT2:-/home/js/android/lineage/prebuilts/sdk/tools/linux/bin/aapt2}"
  local d8="${SAKAMOTO_ANDROID_D8:-/home/js/android/lineage/prebuilts/sdk/tools/linux/bin/d8}"
  local zipalign="${SAKAMOTO_ANDROID_ZIPALIGN:-/home/js/android/lineage/prebuilts/sdk/tools/linux/bin/zipalign}"
  local apksigner_jar="${SAKAMOTO_ANDROID_APKSIGNER_JAR:-/home/js/android/lineage/prebuilts/sdk/tools/linux/lib/apksigner.jar}"
  local d8_jar="${SAKAMOTO_ANDROID_D8_JAR:-}"
  local debug_key="${SAKAMOTO_ANDROID_DEBUG_KEY:-/home/js/android/lineage/build/make/target/product/security/testkey.pk8}"
  local debug_cert="${SAKAMOTO_ANDROID_DEBUG_CERT:-/home/js/android/lineage/build/make/target/product/security/testkey.x509.pem}"
  local ndk_root="${SAKAMOTO_ANDROID_NDK_ROOT:-/home/js/.local/share/android-sdk/ndk/29.0.14206865}"
  local llvm_readelf="$ndk_root/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-readelf"
  local java_bin
  local java_launcher
  local javac_bin
  local java_home
  local jimage_bin
  local jar_bin
  local tool_path
  local zip_bin
  local apk_output_input="${SAKAMOTO_ANDROID_APK_OUTPUT_DIR:-$repo_root/app/android-runtime/build/outputs}"
  local apk_output_dir
  local apk_output_path
  local apk_build_dir
  local java_source_dir="$repo_root/app/android-runtime/src/main/java"
  local classes_dir
  local dex_dir
  local payload_root
  local payload_assets
  local payload_lib
  local unsigned_apk
  local aligned_apk
  local signed_apk
  local artifact
  local elf_header
  local jni_dynamic
  local native_library
  local javac_log
  local javac_support_dir
  local javac_support_jar
  local javac_classpath
  local -a java_sources
  local -a class_files
  local -a d8_outputs
  local -a d8_command
  local product_artifact_id
  local product_api_identity
  local product_abi_version
  local product_api_version
  local vpp_binary_sha256

  [[ -n "$product_stage_input" ]] || \
    die "apk-only requires an explicit product stage"
  product_stage="$(realpath -e -- "$product_stage_input" 2>/dev/null)" || \
    die "product stage directory cannot be canonicalized: $product_stage_input"
  [[ -d "$product_stage" && ! -L "$product_stage" ]] || \
    die "product stage directory is not a real directory: $product_stage"
  case "${product_stage,,}" in
    *experiments*|*poc*) die "apk-only refuses experiment/POC product stage" ;;
  esac

  product_marker="$product_stage/.sakamoto-android-product-stage"
  product_manifest="$product_stage/product-stage.properties"
  [[ -f "$product_marker" && ! -L "$product_marker" ]] || \
    die "product stage is missing its owned marker"
  [[ "$(<"$product_marker")" == "sakamoto-android-product-stage/v1" ]] || \
    die "product stage has an invalid owned marker"
  [[ -f "$product_manifest" && ! -L "$product_manifest" ]] || \
    die "product stage manifest is missing"
  require_product_manifest_line() {
    local expected_line="$1"
    grep -Fxq "$expected_line" "$product_manifest" || \
      die "product stage manifest is missing: $expected_line"
  }
  require_product_manifest_line "schema=sakamoto-android-product-stage/v1"
  require_product_manifest_line "abi=arm64-v8a"
  require_product_manifest_line "androidApi=$android_api"
  require_product_manifest_line "vppRevision=$expected_revision"
  product_manifest_value() {
    local key="$1"
    awk -F= -v key="$key" '$1 == key { print substr($0, index($0, "=") + 1); exit }' \
      "$product_source_manifest"
  }
  product_artifact_id="$(product_manifest_value artifact.id)"
  product_api_identity="$(product_manifest_value product.api.identity)"
  product_abi_version="$(product_manifest_value product.abi.version)"
  product_api_version="$(product_manifest_value product.api.version)"
  [[ "$product_artifact_id" =~ ^[^[:space:]=]+$ ]] || \
    die "source product artifact identity has an invalid format"
  [[ "$product_api_identity" =~ ^[^[:space:]=]+$ ]] || \
    die "source product API identity has an invalid format"
  [[ "$product_abi_version" == 1 && "$product_api_version" == 1 ]] || \
    die "source product ABI/API versions must be 1"
  require_product_manifest_line "artifactId=$product_artifact_id"
  require_product_manifest_line "apiIdentity=$product_api_identity"
  require_product_manifest_line "abiVersion=$product_abi_version"
  require_product_manifest_line "apiVersion=$product_api_version"
  vpp_binary_sha256="$(sed -n 's/^vppBinarySha256=//p' "$product_manifest")"
  [[ "$vpp_binary_sha256" =~ ^[[:xdigit:]]{64}$ ]] || \
    die "product stage manifest has an invalid VPP executable hash"
  vpp_patch_series_count="$(sed -n 's/^vppPatchSeriesCount=//p' "$product_manifest")"
  vpp_patch_series_sha256="$(sed -n 's/^vppPatchSeriesSha256=//p' "$product_manifest")"
  [[ "$vpp_patch_series_count" =~ ^[1-9][0-9]*$ ]] || \
    die "product stage manifest has an invalid VPP patch series count"
  [[ "$vpp_patch_series_sha256" =~ ^[[:xdigit:]]{64}$ ]] || \
    die "product stage manifest has an invalid VPP patch series hash"
  [[ "$vpp_patch_series_count" == "$expected_vpp_patch_series_count" ]] || \
    die "product stage manifest has an unexpected VPP patch series count"
  [[ "$vpp_patch_series_sha256" == "$expected_vpp_patch_series_sha256" ]] || \
    die "product stage manifest has an unexpected VPP patch series hash"
  require_product_manifest_line "vppBinary=lib/arm64-v8a/libvpp_runtime.so"
  require_product_manifest_line "productCore=lib/arm64-v8a/libsakamoto_product_core.so"
  require_product_manifest_line "runtimeControl=lib/arm64-v8a/libsakamoto_runtime_control.so"
  require_product_manifest_line "productPlugin=lib/arm64-v8a/$plugin_name"
  require_product_manifest_line "generatedVapi=generated-vapi/vapi/product_core.api.vapi.h"
  require_product_manifest_line "bridgeSource=src/product/native/sakamoto_product_vapi.c"

  while IFS= read -r -d '' stage_path; do
    case "${stage_path,,}" in
      *poc*|*experiment*|*fixture*|*nfqueue*|*hev*|*sucre*|*snortd*|*removed-cxx*)
        forbidden_path="$stage_path"
        die "apk-only refuses retired/POC product artifact: $forbidden_path"
        ;;
    esac
  done < <(cd "$product_stage" && find . -mindepth 1 -print0)
  while IFS= read -r -d '' stage_path; do
    symlink_target="$(readlink -- "$stage_path")" || \
      die "cannot read product stage symlink: $stage_path"
    [[ "$symlink_target" != /* ]] || \
      die "product stage has an absolute symlink: $stage_path"
    symlink_resolved="$(realpath -e -- "$stage_path" 2>/dev/null)" || \
      die "product stage has a dangling symlink: $stage_path"
    case "$symlink_resolved" in
      "$product_stage"/*) ;;
      *) die "product stage symlink escapes its stage: $stage_path" ;;
    esac
  done < <(find "$product_stage" -type l -print0)

  native_dir="$product_stage/lib/arm64-v8a"
  for native_library in \
    libvpp_runtime.so \
    libsakamoto_product_core.so \
    libsakamoto_runtime_control.so \
    libsvm.so \
    libvapiclient.so \
    libvlib.so \
    libvlibapi.so \
    libvlibmemory.so \
    libvlibmemoryclient.so \
    libvnet.so \
    libvppinfra.so \
    "$plugin_name"; do
    [[ -f "$native_dir/$native_library" && ! -L "$native_dir/$native_library" ]] || \
      die "product stage native library is missing or not a regular file: $native_library"
  done
  plugin_source="$native_dir/$plugin_name"
  [[ -f "$plugin_source" && ! -L "$plugin_source" ]] || \
    die "product stage plugin is missing or not a regular file"
  if [[ "$(sha256sum "$native_dir/libvpp_runtime.so" | awk '{print $1}')" \
      != "$vpp_binary_sha256" ]]; then
    die "product_artifact_hash_mismatch: VPP executable does not match product stage"
  fi

  [[ -f "$android_jar" ]] || die "Android SDK android.jar is missing: $android_jar"
  [[ -x "$aapt2" ]] || die "Android aapt2 is missing: $aapt2"
  [[ -x "$d8" ]] || die "Android d8 is missing: $d8"
  [[ -x "$zipalign" ]] || die "Android zipalign is missing: $zipalign"
  [[ -f "$apksigner_jar" ]] || die "Android apksigner is missing: $apksigner_jar"
  [[ -f "$debug_key" && -f "$debug_cert" ]] || \
    die "Android debug signing key or certificate is missing"
  [[ -x "$llvm_readelf" ]] || die "Android LLVM readelf is missing: $llvm_readelf"
  # Resolve every JDK tool from the java.home reported by one selected Java.
  # Mixing PATH entries can silently pair different JDK releases and make the
  # compiler/API-surface check non-reproducible.
  java_launcher="$(command -v java 2>/dev/null || true)"
  zip_bin="$(command -v zip 2>/dev/null || true)"
  [[ -n "$java_launcher" && -x "$java_launcher" ]] || die "Java runtime is missing from PATH"
  java_launcher="$(realpath -e -- "$java_launcher" 2>/dev/null)" || \
    die "Java runtime path cannot be resolved: $java_launcher"
  java_home="$($java_launcher -XshowSettings:properties -version 2>&1 \
    | sed -n 's/^[[:space:]]*java.home = //p' | head -n 1)"
  [[ -n "$java_home" ]] || die "selected Java did not report java.home"
  java_home="$(realpath -e -- "$java_home" 2>/dev/null)" || \
    die "reported java.home cannot be resolved: $java_home"
  java_bin="$java_home/bin/java"
  javac_bin="$java_home/bin/javac"
  jimage_bin="$java_home/bin/jimage"
  jar_bin="$java_home/bin/jar"
  [[ "$(realpath -e -- "$java_bin" 2>/dev/null)" == "$java_launcher" ]] || \
    die "selected Java is not from reported java.home: $java_home"
  for tool_path in "$java_bin" "$javac_bin" "$jimage_bin" "$jar_bin"; do
    [[ -x "$tool_path" ]] || \
      die "JDK tool is missing from java.home (PATH lookup disabled): $tool_path"
  done
  [[ -n "$zip_bin" && -x "$zip_bin" ]] || die "zip is required to package native libraries"
  if [[ -z "$d8_jar" ]]; then
    d8_jar="${d8%/bin/d8}/lib/d8.jar"
  fi
  elf_header="$($llvm_readelf -h "$plugin_source" 2>/dev/null)" || \
    die "cannot inspect product stage plugin ELF"
  [[ "$elf_header" == *AArch64* ]] || \
    die "product stage plugin is not AArch64"
  [[ "$($llvm_readelf -Ws "$plugin_source" 2>/dev/null)" == *product_core_init* ]] || \
    die "product stage plugin init symbol is missing"
  jni_dynamic="$($llvm_readelf -d "$native_dir/libsakamoto_runtime_control.so" 2>/dev/null)" || \
    die "cannot inspect Product Core JNI dynamic dependencies"
  [[ "$jni_dynamic" == *'libsakamoto_product_core.so'* ]] || \
    die "Product Core JNI bridge does not link libsakamoto_product_core.so"

  apk_output_dir="$(realpath -m -- "$apk_output_input" 2>/dev/null)" || \
    die "APK output directory cannot be canonicalized: $apk_output_input"
  [[ "$apk_output_dir" != "/" ]] || \
    die "APK output directory cannot be the filesystem root"
  mkdir -p -- "$apk_output_dir"
  apk_output_dir="$(realpath -e -- "$apk_output_dir" 2>/dev/null)" || \
    die "APK output directory cannot be resolved: $apk_output_input"
  apk_output_path="$apk_output_dir/sakamoto-runtime-debug.apk"
  apk_build_dir="$(mktemp -d "$apk_output_dir/.sakamoto-runtime-debug.build.XXXXXX")"
  apk_cleanup_dir="$apk_build_dir"
  cleanup_apk_build() {
    if [[ -n "$apk_cleanup_dir" && -e "$apk_cleanup_dir" ]]; then
      rm -rf -- "$apk_cleanup_dir"
    fi
  }
  trap cleanup_apk_build EXIT

  payload_root="$apk_build_dir/payload"
  payload_assets="$payload_root/assets"
  payload_lib="$payload_root/lib/arm64-v8a"
  classes_dir="$apk_build_dir/classes"
  dex_dir="$apk_build_dir/dex"
  mkdir -p -- "$payload_assets" "$payload_lib" "$classes_dir" "$dex_dir"
  install -m 0644 "$product_manifest" "$payload_assets/product-stage.properties"

  mapfile -t java_sources < <(find "$java_source_dir" -type f -name '*.java' -print | sort)
  ((${#java_sources[@]} > 0)) || die "Android Java source tree is empty"
  [[ -f "$java_home/lib/modules" ]] || \
    die "JDK module image is missing from java.home: $java_home/lib/modules"
  javac_support_dir="$apk_build_dir/javac-support"
  javac_support_jar="$apk_build_dir/javac-support.jar"
  mkdir -p "$javac_support_dir"
  # Android's platform stub omits LambdaMetafactory.metafactory, which javac
  # needs solely to lower Java-8 lambdas.  Add that compiler-only signature
  # from this JDK's module image on the ordinary compiler class path while
  # keeping every Android API class, including java.lang.Process, on the sole
  # Android boot class path. The support class is never packaged.
  "$jimage_bin" extract --dir="$javac_support_dir" \
    --include "glob:**/java/lang/invoke/LambdaMetafactory.class" \
    "$java_home/lib/modules" >/dev/null || \
    die "cannot extract the javac LambdaMetafactory support class"
  [[ -f "$javac_support_dir/java.base/java/lang/invoke/LambdaMetafactory.class" ]] || \
    die "javac LambdaMetafactory support class was not extracted"
  "$jar_bin" cf "$javac_support_jar" -C "$javac_support_dir/java.base" \
    java/lang/invoke/LambdaMetafactory.class || \
    die "cannot package the javac LambdaMetafactory support class"
  javac_classpath="$android_jar:$javac_support_jar"
  javac_log="$apk_build_dir/javac.verbose.log"
  # -source/-target select Java language/class-file compatibility only.  The
  # boot class path must explicitly point at Android's platform stub or JDK17
  # java.base can leak host-only methods into the generated class files. The
  # verbose log is diagnostic evidence only; its format is not a build gate.
  if ! "$javac_bin" -encoding UTF-8 -Xlint:-options -source 8 -target 8 \
      -bootclasspath "$android_jar" -classpath "$javac_classpath" \
      -verbose -d "$classes_dir" "${java_sources[@]}" >"$javac_log" 2>&1; then
    sed -n '1,160p' "$javac_log" >&2
    die "Android Java compilation failed; see $javac_log"
  fi
  mapfile -t class_files < <(find "$classes_dir" -type f -name '*.class' -print | sort)
  ((${#class_files[@]} > 0)) || die "Android Java compilation produced no classes"

  if [[ -f "$d8_jar" ]]; then
    d8_command=("$java_bin" -cp "$d8_jar" com.android.tools.r8.D8)
  else
    d8_command=("$d8")
  fi
  "${d8_command[@]}" --lib "$android_jar" --min-api "$android_api" \
    --output "$dex_dir" "${class_files[@]}"
  mapfile -t d8_outputs < <(find "$dex_dir" -mindepth 1 -maxdepth 1 -print | sort)
  if ((${#d8_outputs[@]} != 1)) || [[ "${d8_outputs[0]:-}" != "$dex_dir/classes.dex" ]]; then
    printf 'D8 output must contain only classes.dex; found:\n' >&2
    printf '  %s\n' "${d8_outputs[@]:-<none>}" >&2
    die "D8 produced unexpected classes*.dex output"
  fi

  "$aapt2" link -o "$apk_build_dir/unsigned.apk" \
    --manifest "$repo_root/app/android-runtime/src/main/AndroidManifest.xml" \
    -I "$android_jar" \
    --min-sdk-version "$android_api" \
    --target-sdk-version "$target_api" \
    --version-code "$version_code" \
    --version-name debug \
    -A "$payload_assets"
  unsigned_apk="$apk_build_dir/unsigned-with-libs.apk"
  cp -a -- "$apk_build_dir/unsigned.apk" "$unsigned_apk"
  cp -a -- "$dex_dir/classes.dex" "$apk_build_dir/classes.dex"
  (
    cd "$apk_build_dir"
    "$zip_bin" -q -0 "$unsigned_apk" classes.dex
  )
  for native_library in \
    libvpp_runtime.so \
    libsakamoto_product_core.so \
    libsakamoto_runtime_control.so \
    libsvm.so \
    libvapiclient.so \
    libvlib.so \
    libvlibapi.so \
    libvlibmemory.so \
    libvlibmemoryclient.so \
    libvnet.so \
    libvppinfra.so \
    "$plugin_name"; do
    install -m 0644 "$native_dir/$native_library" "$payload_lib/$native_library"
    artifact="$native_dir/$native_library"
    elf_header="$($llvm_readelf -h "$artifact" 2>/dev/null)" || \
      die "cannot inspect product stage native ELF: $native_library"
    [[ "$elf_header" == *AArch64* ]] || \
      die "product stage native library is not AArch64: $native_library"
  done
  (
    cd "$payload_root"
    "$zip_bin" -q -0 -r "$unsigned_apk" lib
  )

  aligned_apk="$apk_build_dir/aligned.apk"
  "$zipalign" -f -p 4 "$unsigned_apk" "$aligned_apk"
  signed_apk="$apk_build_dir/signed.apk"
  "$java_bin" -jar "$apksigner_jar" sign \
    --key "$debug_key" --cert "$debug_cert" --out "$signed_apk" "$aligned_apk"
  "$java_bin" -jar "$apksigner_jar" verify --verbose --print-certs "$signed_apk" \
    >/dev/null
  mv -fT -- "$signed_apk" "$apk_output_path"
  [[ -f "$apk_output_path" ]] || die "APK atomic publication did not produce an output"
  rm -rf -- "$apk_build_dir"
  apk_cleanup_dir=""

  echo "mode=apk-only"
  echo "apk=$apk_output_path"
  echo "versionCode=$version_code"
  echo "productStage=$product_stage"
}

if [[ "$mode" == stage-only ]]; then
  build_native_stage
  exit 0
fi

if [[ "$mode" == apk-only ]]; then
  build_apk_only
  exit 0
fi

if [[ "$mode" == dry-run ]]; then
  echo "mode=dry-run"
  echo "vppRevision=$expected_revision"
  echo "stageDir=$stage_dir"
  echo "generatedVapiIncludeDir=$vapi_include_dir"
  echo "generatedVapiSource=$generated_vapi_header"
  echo "generatedVapiRequired=$SAKAMOTO_PRODUCT_VAPI_REQUIRED"
  echo "bridgeSource=$bridge_source"
  echo "pluginName=$plugin_name"
  echo "versionCode=$version_code"
  exit 0
fi

product_plugin="${SAKAMOTO_PRODUCT_PLUGIN:-$repo_root/build-output/product-vpp-android/lib/vpp_plugins/$plugin_build_name}"
[[ -f "$product_plugin" ]] || \
  die "production VPP plugin is missing: $product_plugin"
[[ "$(basename -- "$product_plugin")" == "$plugin_build_name" ]] || \
  die "production VPP plugin must be named $plugin_build_name before Android native packaging"

echo "Android product APK assembly is not enabled until the generated-VAPI JNI bridge and product plugin staging slice is present." >&2
echo "validated versionCode=$version_code vppRevision=$expected_revision plugin=$plugin_name" >&2
exit 2
