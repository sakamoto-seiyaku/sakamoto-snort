#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
app_dir="$(cd -- "$script_dir/.." && pwd)"
poc_dir="$(cd -- "$app_dir/../.." && pwd)"
repo_root="$(cd -- "$poc_dir/../.." && pwd)"

runtime_root="${VPP_RUNTIME_BUILD_ROOT:-$repo_root/build-output/android-vpp-runtime}"
build_dir="$runtime_root/build"
stage_dir="${VPP_RUNTIME_STAGE_DIR:-$runtime_root/stage}"
source_input="${VPP_SOURCE_TREE:-$poc_dir/work/vpp}"
source_explicit=0
if [[ -n "${VPP_SOURCE_TREE+x}" ]]; then
  source_explicit=1
fi
product_vpp_commit="${VPP_RUNTIME_SOURCE_REVISION:-9258530f3804a152578ce11cc7c8a1e9eab88ed0}"
source_revision=""
source_origin="$source_input"
source_status=""
if [[ "$source_explicit" == 0 ]]; then
  # The experiment checkout is intentionally mutable (and has carried the
  # rejected P6 conditional-wake patches).  Product builds consume a source
  # snapshot made from its committed revision instead of mutating that
  # checkout or accidentally promoting its working tree.
  git -C "$source_input" cat-file -e "$product_vpp_commit^{commit}" 2>/dev/null \
    || { echo "error: pinned VPP source commit is unavailable: $product_vpp_commit" >&2; exit 1; }
  source_revision="$product_vpp_commit"
  source_status="committed-snapshot"
  vpp_dir="$runtime_root/source/$source_revision"
  source_origin="git:$source_input@$source_revision"
  marker="$vpp_dir/.sakamoto-source-revision"
  if [[ ! -f "$marker" ]] || [[ "$(tr -d '[:space:]' <"$marker" 2>/dev/null || true)" != "$source_revision" ]]; then
    rm -rf -- "$vpp_dir"
    mkdir -p -- "$vpp_dir"
    git -C "$source_input" archive --format=tar "$source_revision" \
      | tar -x -C "$vpp_dir"
    printf '%s\n' "$source_revision" >"$marker"
  fi
else
  vpp_dir="$source_input"
  source_revision="$(git -C "$vpp_dir" rev-parse HEAD 2>/dev/null || true)"
  source_revision="${source_revision:-external}"
  if [[ -n "$(git -C "$vpp_dir" status --porcelain --untracked-files=all 2>/dev/null || true)" ]]; then
    source_status="explicit-working-tree"
  else
    source_status="explicit-committed-tree"
  fi
fi
vpp_source="$vpp_dir/src"
product_path="/usr/bin:/bin:${PATH}"

reject_conditional_wake() {
  local tree="$1"
  if rg -n --hidden --glob '!*.o' --glob '!*.so' \
      'wakeup_epoch|vlib_frame_queue_wakeup_mode|VLIB_WAKE_PHASE|0003-vlib-frame-queue-wakeup-epoch-state' \
      "$tree" >/dev/null 2>&1; then
    echo "error: rejected P6 conditional-wake implementation is present in product source: $tree" >&2
    exit 1
  fi
  if find "$tree" -type f -name '*0003-vlib-frame-queue-wakeup-epoch-state*' \
      -print -quit 2>/dev/null | grep -q .; then
    echo "error: rejected P6 conditional-wake patch is present in product source: $tree" >&2
    exit 1
  fi
}

reject_conditional_wake "$vpp_dir"

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
provenance_file="$stage_dir/runtime/source-provenance.properties"
[[ -f "$provenance_file" ]] || stage_needs_refresh=1
if [[ -f "$provenance_file" ]] && ! grep -Fqx "sourceRevision=$source_revision" "$provenance_file"; then
  stage_needs_refresh=1
fi
if [[ -f "$build_dir/CMakeCache.txt" ]] &&
    ! grep -Fqx "CMAKE_HOME_DIRECTORY:INTERNAL=$vpp_source" "$build_dir/CMakeCache.txt"; then
  stage_needs_refresh=1
fi
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
  for target in vapiclient vlibmemoryclient; do
    PATH="$product_path" VPP_DIR="$vpp_dir" BUILD_DIR="$build_dir" TARGET="$target" \
      "$poc_dir/scripts/android-build-vpp-probe.sh"
  done
  PATH="$product_path" VPP_DIR="$vpp_dir" BUILD_DIR="$build_dir" STAGE_DIR="$stage_dir" \
    VPP_SOURCE_REVISION="$source_revision" VPP_SOURCE_ORIGIN="$source_origin" \
    VPP_SOURCE_STATUS="$source_status" \
    "$poc_dir/scripts/android-stage-vpp-core.sh"
  printf '%s\n' "$build_dir" >"$stage_dir/runtime/vapi-build-dir"
fi

for artifact in "$stage_dir/bin/vpp" "$stage_dir/bin/vppctl"; do
  [[ -f "$artifact" ]] || { echo "error: staged VPP artifact missing: $artifact" >&2; exit 1; }
  if strings "$artifact" | rg -q 'wakeup_epoch|vlib_frame_queue_wakeup_mode|VLIB_WAKE_PHASE'; then
    echo "error: staged VPP artifact contains rejected conditional-wake symbols: $artifact" >&2
    exit 1
  fi
done
[[ -f "$provenance_file" ]] || { echo "error: staged VPP provenance is missing: $provenance_file" >&2; exit 1; }
grep -Fqx 'conditionalWakeSource=absent' "$provenance_file" \
  || { echo "error: staged source provenance does not prove conditional-wake absence" >&2; exit 1; }
grep -Fqx 'conditionalWakeBinary=absent' "$provenance_file" \
  || { echo "error: staged binary provenance does not prove conditional-wake absence" >&2; exit 1; }

printf '%s\n' "$stage_dir"
