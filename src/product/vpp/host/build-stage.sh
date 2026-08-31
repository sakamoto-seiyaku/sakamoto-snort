#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
apply_core="$script_dir/apply-core.sh"
pin_file="$script_dir/pinned-vpp-revision.txt"
identity_file="$script_dir/product-vpp-artifact.properties"
host_excluded_plugins=af_xdp
source_dir=""
stage_dir=""

die() {
  echo "Host VPP stage: $*" >&2
  exit 2
}

property() {
  local manifest="$1"
  local key="$2"
  local value
  value="$(sed -n "s/^${key}=//p" "$manifest")"
  [[ -n "$value" && "$value" != *$'\n'* ]] || \
    die "$manifest must contain exactly one $key"
  printf '%s\n' "$value"
}

runtime_closure() {
  local prefix="$1"
  (
    cd "$prefix"
    while IFS= read -r path; do
      if [[ -L "$path" ]]; then
        printf 'link %s %s\n' "$path" "$(readlink -- "$path")"
      else
        printf 'file %s %s\n' "$path" "$(sha256sum -- "$path" | awk '{print $1}')"
      fi
    done < <(find . -type f -o -type l | LC_ALL=C sort)
  ) | sha256sum | awk '{print $1}'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source-dir)
      [[ $# -ge 2 ]] || die "--source-dir requires a value"
      source_dir="$2"
      shift 2
      ;;
    --stage-dir)
      [[ $# -ge 2 ]] || die "--stage-dir requires a value"
      stage_dir="$2"
      shift 2
      ;;
    --help|-h)
      echo "usage: build-stage.sh --source-dir DIR --stage-dir DIR"
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

[[ -n "$source_dir" ]] || die "--source-dir is required"
[[ -n "$stage_dir" ]] || die "--stage-dir is required"
[[ -x "$apply_core" ]] || die "apply-core.sh is missing"
source_dir="$(realpath -e "$source_dir" 2>/dev/null)" || \
  die "source directory cannot be canonicalized"
stage_parent="$(dirname -- "$stage_dir")"
mkdir -p "$stage_parent"
stage_parent="$(realpath -e "$stage_parent")" || \
  die "stage parent cannot be canonicalized"
stage_dir="$stage_parent/$(basename -- "$stage_dir")"

pinned_revision="$(tr -d '[:space:]' < "$pin_file")"
source_head="$(git -C "$source_dir" rev-parse HEAD 2>/dev/null)" || \
  die "source directory is not a Git checkout"
[[ "$source_head" == "$pinned_revision" ]] || \
  die "source checkout is not at the pinned revision"
[[ -z "$(git -C "$source_dir" status --porcelain=v1 --untracked-files=all)" ]] || \
  die "source checkout must be clean"

core_count="$(property "$identity_file" vpp.core.patch.count)"
core_sha256="$(property "$identity_file" vpp.core.patch.sha256)"
source_closure_sha256="$({
  echo "baseRevision=$pinned_revision"
  echo "corePatchSeriesCount=$core_count"
  echo "corePatchSeriesSha256=$core_sha256"
  echo "profile=host"
  echo "excludedPlugins=$host_excluded_plugins"
  echo "pythonApi=off"
} | sha256sum | awk '{print $1}')"

marker="$stage_dir/.sakamoto-product-vpp-stage"
manifest="$stage_dir/host-vpp-stage.properties"
if [[ -e "$stage_dir" ]]; then
  [[ -d "$stage_dir" && ! -L "$stage_dir"
     && -f "$marker" && ! -L "$marker"
     && "$(tr -d '\r\n' < "$marker")" == \
          sakamoto-product-vpp-stage-v1
     && -f "$manifest" && ! -L "$manifest" ]] || \
    die "existing Host VPP stage is not owned or complete"
  [[ "$(property "$manifest" vpp.base.revision)" == "$pinned_revision"
     && "$(property "$manifest" vpp.core.patch.count)" == "$core_count"
     && "$(property "$manifest" vpp.core.patch.sha256)" == "$core_sha256"
     && "$(property "$manifest" vpp.stage.profile)" == host
     && "$(property "$manifest" vpp.source.closure.sha256)" == \
          "$source_closure_sha256" ]] || \
    die "existing Host VPP stage identity mismatch"
  prefix="$stage_dir/source/build-root/install-vpp-native/vpp"
  [[ -x "$prefix/bin/vpp" ]] || die "existing Host VPP stage runtime is missing"
  actual_source_tree_sha256="$(
    git -C "$stage_dir/source" diff --binary HEAD | sha256sum | awk '{print $1}'
  )"
  [[ "$actual_source_tree_sha256" == \
       "$(property "$manifest" vpp.source.tree.sha256)" ]] || \
    die "existing Host VPP stage source tree mismatch"
  actual_runtime_closure="$(runtime_closure "$prefix")"
  [[ "$actual_runtime_closure" == \
       "$(property "$manifest" vpp.runtime.closure.sha256)" ]] || \
    die "existing Host VPP stage runtime closure mismatch"
  echo "stageDisposition=reused"
  echo "stageDir=$stage_dir"
  echo "vppInstallPrefix=$prefix"
  echo "corePatchSeriesSha256=$core_sha256"
  exit 0
fi

[[ "${BUILD_VPP_RUNTIME:-0}" == 1 ]] || \
  die "BUILD_VPP_RUNTIME=1 is required to create the first Host VPP stage"

stage_name="$(basename -- "$stage_dir")"
build_dir="$stage_parent/.${stage_name}.building"
build_marker="$build_dir/.sakamoto-product-vpp-stage-building"
cleanup() {
  # Keep the owned candidate after a build failure so the next invocation can
  # resume VPP's incremental build instead of discarding thousands of objects.
  :
}
trap cleanup EXIT

patched_source="$build_dir/source"
if [[ -e "$build_dir" ]]; then
  [[ -d "$build_dir" && ! -L "$build_dir"
     && -f "$build_marker" && ! -L "$build_marker"
     && "$(tr -d '\r\n' < "$build_marker")" == \
          "$source_closure_sha256" ]] || \
    die "existing Host VPP build candidate is not owned or has stale identity"
  [[ -d "$patched_source" ]] || die "Host VPP build candidate source is missing"
else
  mkdir "$build_dir"
  printf '%s\n' "$source_closure_sha256" >"$build_marker"
  "$apply_core" --source-dir "$source_dir" --work-dir "$patched_source" \
    >"$build_dir/apply-core.log"
  seed_prefix="$source_dir/build-root/install-vpp-native/vpp"
  if [[ -x "$seed_prefix/bin/vpp" && -d "$source_dir/build-root" ]]; then
    # The clean pin has already completed the one full official build. Copy
    # its build tree, then incrementally rebuild the Product patch closure.
    cp -a "$source_dir/build-root" "$patched_source/build-root"
    touch "$patched_source/build-root/.deps.ok"
  fi
fi
# AF_XDP is outside the Product NFQ/VPN packet path.  Excluding it also keeps
# this Host stage independent of a host-global libbpf/libxdp installation.
VPP_EXCLUDED_PLUGINS="$host_excluded_plugins" \
VPP_EXTRA_CMAKE_ARGS=-DVPP_BUILD_PYTHON_API=OFF \
  make -C "$patched_source" build-release
prefix="$patched_source/build-root/install-vpp-native/vpp"
[[ -x "$prefix/bin/vpp" ]] || die "patched VPP build did not produce a runtime"
runtime_closure_sha256="$(runtime_closure "$prefix")"
source_tree_sha256="$(
  git -C "$patched_source" diff --binary HEAD | sha256sum | awk '{print $1}'
)"
[[ "$runtime_closure_sha256" =~ ^[[:xdigit:]]{64}$ ]] || \
  die "Host VPP runtime closure is invalid"

printf '%s\n' sakamoto-product-vpp-stage-v1 \
  >"$build_dir/.sakamoto-product-vpp-stage"
rm -f -- "$build_marker"
cat >"$build_dir/host-vpp-stage.properties" <<EOF
schema=sakamoto-product-vpp-stage/v1
vpp.base.revision=$pinned_revision
vpp.core.patch.count=$core_count
vpp.core.patch.sha256=$core_sha256
vpp.stage.profile=host
vpp.runtime.closure.sha256=$runtime_closure_sha256
vpp.source.closure.sha256=$source_closure_sha256
vpp.source.tree.sha256=$source_tree_sha256
EOF
mv "$build_dir" "$stage_dir"
build_dir=""
trap - EXIT

echo "stageDisposition=built"
echo "stageDir=$stage_dir"
echo "vppInstallPrefix=$stage_dir/source/build-root/install-vpp-native/vpp"
echo "corePatchSeriesSha256=$core_sha256"
