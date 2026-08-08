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

# Hash the complete source snapshot deterministically. This deliberately
# includes the relative path so the same bytes moved to another directory do
# not silently acquire different provenance.
source_tree_sha256() {
  local tree="$1"
  (
    cd -- "$tree"
    find . -type f -print0 | sort -z | xargs -0 -r sha256sum
  ) | sha256sum | awk '{print $1}'
}

git_archive_sha256() {
  local repo="$1" revision="$2"
  # Explicit prefix keeps archive member names independent of the checkout
  # directory. Git archive metadata is derived from the immutable commit, so
  # this byte stream is reproducible for a pinned revision.
  git -C "$repo" archive --format=tar --prefix=./ "$revision" \
    | sha256sum | awk '{print $1}'
}

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

provenance_file="$stage_dir/runtime/source-provenance.properties"
overlay_script="$poc_dir/scripts/apply-vpp-android-overlay.sh"
overlay_sha256="$(sha256sum "$overlay_script" | awk '{print $1}')"
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
  base_archive_sha256="$(git_archive_sha256 "$source_input" "$source_revision")" \
    || { echo "error: unable to hash pinned VPP git archive" >&2; exit 1; }

  # A retained source marker is not trusted. If an earlier provenance record
  # exists, first reject any manual mutation of that retained post-overlay
  # tree; then rebuild a clean pinned base and deterministically apply the
  # repository Android overlay so legitimate overlay edits are preserved.
  retained_source_tree_digest=""
  recorded_source_tree_digest=""
  if [[ -f "$provenance_file" && -d "$vpp_dir" ]]; then
    recorded_source_tree_digest="$(awk -F= '$1 == "sourceTreeSha256" {print $2; exit}' \
      "$provenance_file")"
    if [[ "$recorded_source_tree_digest" =~ ^[0-9a-fA-F]{64}$ ]]; then
      retained_source_tree_digest="$(source_tree_sha256 "$vpp_dir")"
    fi
  fi

  mkdir -p -- "$runtime_root/source"
  source_parent="$(mktemp -d "$runtime_root/source-rebuild.XXXXXX")"
  fresh_vpp_dir="$source_parent/$source_revision"
  mkdir -p -- "$fresh_vpp_dir"
  git -C "$source_input" archive --format=tar --prefix=./ "$source_revision" \
    | tar -x -C "$fresh_vpp_dir"
  printf '%s\n' "$source_revision" >"$fresh_vpp_dir/.sakamoto-source-revision"
  # The clean archive must be checked before overlay application. This is the
  # digest bound to the pinned commit, independent of any retained marker.
  base_tree_sha256="$(source_tree_sha256 "$fresh_vpp_dir")"
  INSIDE_VPP_NFQ_CONTAINER=1 PATH="/usr/bin:/bin:${PATH}" VPP_DIR="$fresh_vpp_dir" \
    "$overlay_script" >/dev/null
  reject_conditional_wake "$fresh_vpp_dir"
  fresh_source_tree_sha256="$(source_tree_sha256 "$fresh_vpp_dir")"
  if [[ "$recorded_source_tree_digest" =~ ^[0-9a-fA-F]{64}$ \
      && "$retained_source_tree_digest" != "$recorded_source_tree_digest" \
      && "$fresh_source_tree_sha256" == "$recorded_source_tree_digest" ]]; then
    echo "error: retained VPP source tree was manually mutated: $vpp_dir" >&2
    rm -rf -- "$source_parent"
    exit 1
  fi
  rm -rf -- "$vpp_dir"
  mkdir -p -- "$(dirname -- "$vpp_dir")"
  mv -- "$fresh_vpp_dir" "$vpp_dir"
  rm -rf -- "$source_parent"
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
if [[ -f "$provenance_file" ]] && ! grep -Eq '^sourceTreeSha256=[0-9a-fA-F]{64}$' "$provenance_file"; then
  stage_needs_refresh=1
fi
if [[ "$source_explicit" == 0 ]]; then
  if [[ -f "$provenance_file" ]] && ! grep -Fqx "baseArchiveSha256=$base_archive_sha256" \
      "$provenance_file"; then
    stage_needs_refresh=1
  fi
  if [[ -f "$provenance_file" ]] && ! grep -Fqx "baseTreeSha256=$base_tree_sha256" \
      "$provenance_file"; then
    stage_needs_refresh=1
  fi
  if [[ -f "$provenance_file" ]] && ! grep -Fqx "overlaySha256=$overlay_sha256" \
      "$provenance_file"; then
    stage_needs_refresh=1
  fi
  if [[ -f "$provenance_file" ]] && ! grep -Fqx "sourceTreeSha256=$fresh_source_tree_sha256" \
      "$provenance_file"; then
    stage_needs_refresh=1
  fi
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
  INSIDE_VPP_NFQ_CONTAINER=1 PATH="$product_path" VPP_DIR="$vpp_dir" \
    "$poc_dir/scripts/apply-vpp-android-overlay.sh"
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

source_tree_digest="$(source_tree_sha256 "$vpp_dir")"
if [[ -f "$provenance_file" ]]; then
  recorded_source_tree_digest="$(awk -F= '$1 == "sourceTreeSha256" {print $2; exit}' \
    "$provenance_file")"
  if [[ -n "$recorded_source_tree_digest" && "$recorded_source_tree_digest" != "$source_tree_digest" ]]; then
    echo "error: staged source tree changed after provenance was recorded: $vpp_dir" >&2
    exit 1
  fi
  if [[ -z "$recorded_source_tree_digest" ]]; then
    printf 'sourceTreeSha256=%s\n' "$source_tree_digest" >>"$provenance_file"
  fi
else
  echo "error: staged VPP provenance is missing: $provenance_file" >&2
  exit 1
fi

ensure_provenance_key() {
  local key="$1" expected="$2" existing rewrite
  existing="$(awk -F= -v wanted="$key" '$1 == wanted {print substr($0, index($0, "=") + 1); exit}' \
    "$provenance_file")"
  if [[ -n "$existing" && "$existing" == "$expected" ]]; then
    return 0
  fi
  if [[ -n "$existing" ]]; then
    rewrite="$(mktemp "${provenance_file}.rewrite.XXXXXX")"
    awk -F= -v wanted="$key" '$1 != wanted' "$provenance_file" >"$rewrite"
    printf '%s=%s\n' "$key" "$expected" >>"$rewrite"
    mv -- "$rewrite" "$provenance_file"
  else
    printf '%s=%s\n' "$key" "$expected" >>"$provenance_file"
  fi
}

if [[ "$source_explicit" == 0 ]]; then
  ensure_provenance_key baseArchiveSha256 "$base_archive_sha256"
  ensure_provenance_key baseTreeSha256 "$base_tree_sha256"
  ensure_provenance_key overlaySha256 "$overlay_sha256"
fi

for artifact in "$stage_dir/bin/vpp" "$stage_dir/bin/vppctl"; do
  [[ -f "$artifact" ]] || { echo "error: staged VPP artifact missing: $artifact" >&2; exit 1; }
  if strings "$artifact" | rg -q 'wakeup_epoch|vlib_frame_queue_wakeup_mode|VLIB_WAKE_PHASE'; then
    echo "error: staged VPP artifact contains rejected conditional-wake symbols: $artifact" >&2
    exit 1
  fi
done
[[ -f "$provenance_file" ]] || { echo "error: staged VPP provenance is missing: $provenance_file" >&2; exit 1; }
grep -Fqx "sourceTreeSha256=$source_tree_digest" "$provenance_file" \
  || { echo "error: staged source tree digest is not bound to provenance" >&2; exit 1; }
grep -Fqx 'conditionalWakeSource=absent' "$provenance_file" \
  || { echo "error: staged source provenance does not prove conditional-wake absence" >&2; exit 1; }
grep -Fqx 'conditionalWakeBinary=absent' "$provenance_file" \
  || { echo "error: staged binary provenance does not prove conditional-wake absence" >&2; exit 1; }

printf '%s\n' "$stage_dir"
