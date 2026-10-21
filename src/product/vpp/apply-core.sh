#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
pin_file="$script_dir/pinned-vpp-revision.txt"
identity_file="$script_dir/product-vpp-artifact.properties"
patch_dir="$script_dir/patches/core"
series="$patch_dir/series"
source_dir=""
work_dir=""

die() {
  echo "Product VPP core: $*" >&2
  exit 2
}

property() {
  local key="$1"
  local value
  value="$(sed -n "s/^${key}=//p" "$identity_file")"
  [[ -n "$value" && "$value" != *$'\n'* ]] || \
    die "identity manifest must contain exactly one $key"
  printf '%s\n' "$value"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source-dir)
      [[ $# -ge 2 ]] || die "--source-dir requires a value"
      source_dir="$2"
      shift 2
      ;;
    --work-dir)
      [[ $# -ge 2 ]] || die "--work-dir requires a value"
      work_dir="$2"
      shift 2
      ;;
    --help|-h)
      echo "usage: apply-core.sh --source-dir DIR --work-dir DIR"
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

[[ -n "$source_dir" ]] || die "--source-dir is required"
[[ -n "$work_dir" ]] || die "--work-dir is required"
[[ -f "$pin_file" && -f "$identity_file" && -f "$series" ]] || \
  die "core source identity or patch series is missing"

source_dir="$(realpath -e "$source_dir" 2>/dev/null)" || \
  die "source directory cannot be canonicalized"
[[ -d "$source_dir/.git" || -f "$source_dir/.git" ]] || \
  die "source directory is not a Git checkout"
case "${source_dir,,}" in
  *experiments*|*poc*) die "POC/experiment source is not permitted" ;;
esac
[[ ! -e "$work_dir" ]] || die "work directory already exists"

pinned_revision="$(tr -d '[:space:]' < "$pin_file")"
[[ "$pinned_revision" =~ ^[[:xdigit:]]{40}$ ]] || \
  die "pinned revision is invalid"
source_head="$(git -C "$source_dir" rev-parse HEAD)"
[[ "$source_head" == "$pinned_revision" ]] || \
  die "source checkout is not at the pinned revision"
[[ -z "$(git -C "$source_dir" status --porcelain=v1 --untracked-files=all)" ]] || \
  die "source checkout must be clean"

expected_count="$(property vpp.core.patch.count)"
expected_sha256="$(property vpp.core.patch.sha256)"
[[ "$expected_count" =~ ^[1-9][0-9]*$ ]] || \
  die "core patch count allowlist is invalid"
[[ "$expected_sha256" =~ ^[[:xdigit:]]{64}$ ]] || \
  die "core patch hash allowlist is invalid"

patch_count=0
patch_manifest_lines=""
while IFS= read -r patch_name || [[ -n "$patch_name" ]]; do
  [[ -n "$patch_name" ]] || continue
  [[ "$patch_name" != \#* ]] || continue
  [[ "$patch_name" =~ ^[0-9]{4}-[a-z0-9-]+\.patch$ ]] || \
    die "unsafe core patch name: $patch_name"
  patch_file="$patch_dir/$patch_name"
  [[ -f "$patch_file" ]] || die "core patch is missing: $patch_name"
  patch_digest="$(sha256sum "$patch_file" | awk '{print $1}')"
  patch_count=$((patch_count + 1))
  patch_manifest_lines+="$patch_name $patch_digest"$'\n'
done < "$series"
series_digest="$(sha256sum "$series" | awk '{print $1}')"
patch_series_sha256="$({
  printf 'series %s\n' "$series_digest"
  printf '%s' "$patch_manifest_lines"
} | sha256sum | awk '{print $1}')"
[[ "$patch_count" == "$expected_count" ]] || \
  die "core patch count does not match the Product allowlist"
[[ "$patch_series_sha256" == "$expected_sha256" ]] || \
  die "core patch bytes/order do not match the Product allowlist"

mkdir -p "$(dirname -- "$work_dir")"
git clone --no-local --no-checkout "$source_dir" "$work_dir" >/dev/null
git -C "$work_dir" checkout --detach "$pinned_revision" >/dev/null

while IFS= read -r patch_name || [[ -n "$patch_name" ]]; do
  [[ -n "$patch_name" ]] || continue
  [[ "$patch_name" != \#* ]] || continue
  patch_file="$patch_dir/$patch_name"
  git -C "$work_dir" apply --check --whitespace=error "$patch_file" || \
    die "core patch does not apply: $patch_name"
  git -C "$work_dir" apply --whitespace=error "$patch_file"
done < "$series"

expected_paths=$'src/vlib/buffer.c\nsrc/vlib/buffer.h\nsrc/vlib/buffer_funcs.c\nsrc/vlib/buffer_funcs.h\nsrc/vlib/buffer_node.h\nsrc/vlib/threads.c\nsrc/vnet/ip/reass/ip4_full_reass.c\nsrc/vnet/ip/reass/ip4_full_reass.h\nsrc/vnet/ip/reass/ip4_sv_reass.c\nsrc/vnet/ip/reass/ip6_full_reass.c\nsrc/vnet/ip/reass/ip6_full_reass.h\nsrc/vnet/ip/reass/ip6_sv_reass.c'
changed_paths="$({
  git -C "$work_dir" diff --name-only
  git -C "$work_dir" ls-files --others --exclude-standard
} | LC_ALL=C sort -u)"
[[ "$changed_paths" == "$expected_paths" ]] || \
  die "core patches changed files outside the fixed allowlist"
[[ "$(git -C "$source_dir" rev-parse HEAD)" == "$source_head" ]] || \
  die "source checkout revision changed"
[[ -z "$(git -C "$source_dir" status --porcelain=v1 --untracked-files=all)" ]] || \
  die "source checkout content changed"

echo "baseRevision=$source_head"
echo "corePatchSeriesCount=$patch_count"
echo "corePatchSeriesSha256=$patch_series_sha256"
echo "workDir=$work_dir"
echo "corePatchedPaths=$expected_paths"
