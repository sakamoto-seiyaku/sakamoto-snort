#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
apply_core="$repo_root/src/product/vpp/apply-core.sh"
pin_file="$repo_root/src/product/vpp/pinned-vpp-revision.txt"
series_dir="$repo_root/src/product/vpp/patches/core"
series_file="$series_dir/series"
identity_file="$repo_root/src/product/vpp/product-vpp-artifact.properties"

fail() {
  echo "SAKAMOTO-175 VPP core patch contract: FAIL: $*" >&2
  exit 1
}

property() {
  local key="$1"
  local values
  values="$(sed -n "s/^${key}=//p" "$identity_file")"
  [[ -n "$values" && "$values" != *$'\n'* ]] || \
    fail "$identity_file must contain exactly one $key"
  printf '%s\n' "$values"
}

expect_fail() {
  local label="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    fail "$label was accepted"
  fi
}

[[ -x "$apply_core" ]] || fail "missing executable public seam: $apply_core"
[[ -f "$pin_file" ]] || fail "missing pinned VPP revision"
[[ -f "$series_file" ]] || fail "missing ordered Product VPP core series"
[[ -f "$identity_file" ]] || fail "missing Product VPP identity manifest"

expected_series=$'0001-vlib-nonblocking-retained-enqueue.patch\n0002-ip-full-reass-product-custom-seam.patch\n0003-ip-reass-active-expiry.patch\n0004-ip4-custom-retained-exits.patch\n0005-ip6-custom-retained-exits.patch'
actual_series="$(sed -e '/^[[:space:]]*$/d' -e '/^[[:space:]]*#/d' "$series_file")"
[[ "$actual_series" == "$expected_series" ]] || \
  fail "core patches are missing, duplicated, or out of order"

expected_count="$(property vpp.core.patch.count)"
expected_sha256="$(property vpp.core.patch.sha256)"
fixed_sha256=4e6569b35c7b58246448f5260735bf766830483f9323fbb62fde3d4151e46247
[[ "$expected_count" == "5" ]] || fail "core patch count allowlist must remain 5"
[[ "$expected_sha256" =~ ^[[:xdigit:]]{64}$ ]] || \
  fail "core patch hash allowlist is not a SHA-256 digest"
[[ "$expected_sha256" == "$fixed_sha256" ]] || \
  fail "core patch hash does not match the SAKAMOTO-228 fixed allowlist"

manifest_lines=""
while IFS= read -r patch_name; do
  patch_file="$series_dir/$patch_name"
  [[ -f "$patch_file" ]] || fail "missing core patch: $patch_name"
  patch_sha256="$(sha256sum "$patch_file" | awk '{print $1}')"
  manifest_lines+="$patch_name $patch_sha256"$'\n'
done <<<"$actual_series"
series_sha256="$(sha256sum "$series_file" | awk '{print $1}')"
actual_sha256="$({
  printf 'series %s\n' "$series_sha256"
  printf '%s' "$manifest_lines"
} | sha256sum | awk '{print $1}')"
[[ "$actual_sha256" == "$expected_sha256" ]] || \
  fail "core patch bytes/order do not match the fixed Product allowlist"

expected_paths=$'src/vlib/buffer_funcs.c\nsrc/vlib/buffer_funcs.h\nsrc/vlib/buffer_node.h\nsrc/vnet/ip/reass/ip4_full_reass.c\nsrc/vnet/ip/reass/ip4_full_reass.h\nsrc/vnet/ip/reass/ip4_sv_reass.c\nsrc/vnet/ip/reass/ip6_full_reass.c\nsrc/vnet/ip/reass/ip6_full_reass.h\nsrc/vnet/ip/reass/ip6_sv_reass.c'

# Source application is the public integration seam. A normal repository
# checkout need not carry the large official VPP tree; formal Host evidence
# supplies it explicitly, while the source identity checks above always run.
source_dir="${SAKAMOTO_S175_VPP_SOURCE_DIR:-${VPP_SOURCE_DIR:-}}"
if [[ -z "$source_dir" && -d /tmp/sakamoto-172-vpp-official.6CoCcd/source-git ]]; then
  source_dir=/tmp/sakamoto-172-vpp-official.6CoCcd/source-git
fi
if [[ -z "$source_dir" ]]; then
  echo "SAKAMOTO-175 VPP core patch contract: PASS (source apply deferred; set SAKAMOTO_S175_VPP_SOURCE_DIR)"
  exit 0
fi
source_dir="$(realpath -e "$source_dir")"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/sakamoto-s175-core-contract.XXXXXX")"
trap 'rm -rf -- "$tmp_dir"' EXIT

before_head="$(git -C "$source_dir" rev-parse HEAD)"
before_status="$(git -C "$source_dir" status --porcelain=v1 --untracked-files=all)"
[[ -z "$before_status" ]] || fail "formal source fixture must start clean"

work_dir="$tmp_dir/patched-source"
output="$tmp_dir/apply-core.log"
"$apply_core" --source-dir "$source_dir" --work-dir "$work_dir" >"$output"

[[ -d "$work_dir/.git" || -f "$work_dir/.git" ]] || \
  fail "apply-core did not clone a new Git work directory"
[[ "$(realpath -e "$work_dir")" != "$source_dir" ]] || \
  fail "apply-core patched the input checkout in place"
[[ "$(git -C "$work_dir" rev-parse HEAD)" == "$before_head" ]] || \
  fail "core patch application changed the base revision"
[[ "$(git -C "$source_dir" rev-parse HEAD)" == "$before_head" ]] || \
  fail "input checkout revision changed"
[[ -z "$(git -C "$source_dir" status --porcelain=v1 --untracked-files=all)" ]] || \
  fail "input checkout content changed"

changed_paths="$({
  git -C "$work_dir" diff --name-only
  git -C "$work_dir" ls-files --others --exclude-standard
} | LC_ALL=C sort -u)"
[[ "$changed_paths" == "$expected_paths" ]] || \
  fail "core patches changed paths outside the fixed allowlist"

base_revision="$(sed -n 's/^baseRevision=//p' "$output")"
reported_count="$(sed -n 's/^corePatchSeriesCount=//p' "$output")"
reported_sha256="$(sed -n 's/^corePatchSeriesSha256=//p' "$output")"
reported_paths="$(awk '
  /^corePatchedPaths=/ {
    sub(/^corePatchedPaths=/, "")
    print
    capture = 1
    next
  }
  capture { print }
' "$output")"
[[ "$base_revision" == "$before_head" ]] || fail "baseRevision is missing or wrong"
[[ "$reported_count" == "$expected_count" ]] || \
  fail "corePatchSeriesCount is missing or wrong"
[[ "$reported_sha256" == "$expected_sha256" ]] || \
  fail "corePatchSeriesSha256 is missing or wrong"
[[ "$reported_paths" == "$expected_paths" ]] || \
  fail "corePatchedPaths is missing or wrong"

dirty_source="$tmp_dir/dirty-source"
git clone --no-local "$source_dir" "$dirty_source" >/dev/null 2>&1
dirty_path="$(git -C "$dirty_source" ls-files | sed -n '1p')"
printf '\nSAKAMOTO-175 dirty fixture\n' >>"$dirty_source/$dirty_path"
expect_fail "dirty source checkout" \
  "$apply_core" --source-dir "$dirty_source" --work-dir "$tmp_dir/dirty-output"

wrong_source="$tmp_dir/wrong-pin-source"
git clone --no-local "$source_dir" "$wrong_source" >/dev/null 2>&1
git -C "$wrong_source" -c user.name=contract -c user.email=contract.invalid \
  commit --allow-empty -m wrong-pin >/dev/null
expect_fail "wrong pinned revision" \
  "$apply_core" --source-dir "$wrong_source" --work-dir "$tmp_dir/wrong-output"

for mutation in tampered reordered; do
  tool_root="$tmp_dir/$mutation-tool"
  mkdir -p "$tool_root/src/product"
  cp -a "$repo_root/src/product/vpp" "$tool_root/src/product/vpp"
  if [[ "$mutation" == tampered ]]; then
    printf '\n' >>"$tool_root/src/product/vpp/patches/core/0001-vlib-nonblocking-retained-enqueue.patch"
  else
    printf '%s\n' \
      0002-ip-full-reass-product-custom-seam.patch \
      0001-vlib-nonblocking-retained-enqueue.patch \
      0003-ip-reass-active-expiry.patch \
      >"$tool_root/src/product/vpp/patches/core/series"
  fi
  expect_fail "$mutation core patch series" \
    "$tool_root/src/product/vpp/apply-core.sh" \
      --source-dir "$source_dir" --work-dir "$tmp_dir/$mutation-output"
done

echo "SAKAMOTO-175 VPP core patch contract: PASS"
