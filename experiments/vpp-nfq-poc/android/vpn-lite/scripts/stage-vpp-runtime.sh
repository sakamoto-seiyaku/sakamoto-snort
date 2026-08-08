#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
app_dir="$(cd -- "$script_dir/.." && pwd)"
poc_dir="$(cd -- "$app_dir/../.." && pwd)"
repo_root="$(cd -- "$poc_dir/../.." && pwd)"

runtime_root="${VPP_RUNTIME_BUILD_ROOT:-$repo_root/build-output/android-vpp-runtime}"
build_dir="$runtime_root/build"
stage_dir="${VPP_RUNTIME_STAGE_DIR:-$runtime_root/stage}"
vpp_dir="${VPP_SOURCE_TREE:-$poc_dir/work/vpp}"
vpp_source="$vpp_dir/src"
product_path="/usr/bin:/bin:${PATH}"

if [[ ! -f "$vpp_source/CMakeLists.txt" ]]; then
  echo "error: VPP source tree is unavailable: $vpp_source" >&2
  echo "fetch the pinned VPP source before building the product runtime" >&2
  exit 1
fi

stage_needs_refresh=0
for artifact in \
  "$stage_dir/bin/vpp" \
  "$stage_dir/bin/vppctl"; do
  [[ -f "$artifact" ]] || stage_needs_refresh=1
done
for pair in \
  "$build_dir/bin/vpp:$stage_dir/bin/vpp" \
  "$build_dir/bin/vppctl:$stage_dir/bin/vppctl"; do
  source_artifact="${pair%%:*}"
  staged_artifact="${pair#*:}"
  if [[ -f "$source_artifact" && ( ! -f "$staged_artifact" || "$source_artifact" -nt "$staged_artifact" ) ]]; then
    stage_needs_refresh=1
  fi
done

if [[ "${VPP_RUNTIME_REBUILD:-0}" == 1 || "$stage_needs_refresh" == 1 ]]; then
  PATH="$product_path" VPP_DIR="$vpp_dir" "$poc_dir/scripts/apply-vpp-android-overlay.sh"
  PATH="$product_path" VPP_DIR="$vpp_dir" \
    BUILD_DIR="$build_dir" \
    VPP_CMAKE_BUILD_TYPE=release \
    VPP_USE_LTO=OFF \
    VPP_PLUGINS="" \
    VPP_EXTRA_CMAKE_ARGS="-DPython3_EXECUTABLE=/usr/bin/python3 -DVPP_MARCH_VARIANT_OCTEONTX2=OFF -DVPP_MARCH_VARIANT_THUNDERX2T99=OFF -DVPP_MARCH_VARIANT_CORTEXA72=OFF -DVPP_MARCH_VARIANT_NEOVERSEN1=OFF -DVPP_MARCH_VARIANT_NEOVERSEV2=OFF -DSAKAMOTO_VPP_NO_IPSEC=ON -DSAKAMOTO_VPP_ANDROID_IDLE_PROFILE=ON" \
    "$poc_dir/scripts/android-configure-vpp-probe.sh"
  PATH="$product_path" VPP_DIR="$vpp_dir" BUILD_DIR="$build_dir" TARGET=vpp \
    "$poc_dir/scripts/android-build-vpp-probe.sh"
  PATH="$product_path" VPP_DIR="$vpp_dir" BUILD_DIR="$build_dir" TARGET=vppctl \
    "$poc_dir/scripts/android-build-vpp-probe.sh"
  PATH="$product_path" VPP_DIR="$vpp_dir" BUILD_DIR="$build_dir" STAGE_DIR="$stage_dir" \
    "$poc_dir/scripts/android-stage-vpp-core.sh"
  printf '%s\n' "$build_dir" >"$stage_dir/runtime/vapi-build-dir"
fi

printf '%s\n' "$stage_dir"
