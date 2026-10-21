#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
profile_module="$repo_root/src/product/vpp/android/apply-profile.sh"
stage_script="$repo_root/src/product/vpp/android/build-stage.sh"
identity_file="$repo_root/src/product/vpp/product-vpp-artifact.properties"
pin_file="$repo_root/src/product/vpp/pinned-vpp-revision.txt"
profile_name=android-api31-arm64

fail() {
  echo "SAKAMOTO-175 Android VPP core/profile contract: FAIL: $*" >&2
  exit 1
}

property() {
  local key="$1"
  local value
  value="$(sed -n "s/^${key}=//p" "$identity_file")"
  [[ -n "$value" && "$value" != *$'\n'* ]] || \
    fail "$identity_file must contain exactly one $key"
  printf '%s\n' "$value"
}

require_literal() {
  local path="$1"
  local literal="$2"
  local description="$3"
  grep -Fq -- "$literal" "$path" || fail "$description"
}

[[ -x "$profile_module" ]] || fail "Android VPP profile module is missing"
[[ -x "$stage_script" ]] || fail "Android VPP stage builder is missing"
[[ -f "$identity_file" ]] || fail "Product VPP identity manifest is missing"
[[ -f "$pin_file" ]] || fail "pinned VPP revision is missing"

expected_core_count="$(property vpp.core.patch.count)"
expected_core_sha256="$(property vpp.core.patch.sha256)"
[[ "$expected_core_count" == 7 ]] || fail "common core patch count must remain 7"
[[ "$expected_core_sha256" =~ ^[[:xdigit:]]{64}$ ]] || \
  fail "common core patch identity is not a SHA-256 digest"

# The Android stage consumes one composed source identity. It must validate
# the same common-core identity as Host in addition to the Android profile
# identity; accepting only the historical Android patch-series hash would let
# the two product targets silently diverge.
require_literal "$stage_script" 'corePatchSeriesCount' \
  "stage does not validate the common-core patch count"
require_literal "$stage_script" 'corePatchSeriesSha256' \
  "stage does not validate the common-core patch hash"
require_literal "$stage_script" 'corePatchSeriesCount=' \
  "published stage manifest omits the common-core patch count"
require_literal "$stage_script" 'corePatchSeriesSha256=' \
  "published stage manifest omits the common-core patch hash"

# Source application is the build-free public composition seam. Formal runs
# supply the clean official checkout; repositories without that large fixture
# still enforce the stage identity checks above.
source_dir="${SAKAMOTO_S175_VPP_SOURCE_DIR:-${VPP_SOURCE_DIR:-}}"
if [[ -z "$source_dir" && -d /tmp/sakamoto-172-vpp-official.6CoCcd/source-git ]]; then
  source_dir=/tmp/sakamoto-172-vpp-official.6CoCcd/source-git
fi
if [[ -z "$source_dir" ]]; then
  echo "SAKAMOTO-175 Android VPP core/profile contract: PASS (source composition deferred; set SAKAMOTO_S175_VPP_SOURCE_DIR)"
  exit 0
fi

source_dir="$(realpath -e "$source_dir")"
work_root="$(mktemp -d "${TMPDIR:-/tmp}/sakamoto-s175-android-core-profile.XXXXXX")"
trap 'rm -rf -- "$work_root"' EXIT
patched_source="$work_root/patched-source"
profile_log="$work_root/profile.log"

before_head="$(git -C "$source_dir" rev-parse HEAD)"
before_status="$(git -C "$source_dir" status --porcelain=v1 --untracked-files=all)"
[[ -z "$before_status" ]] || fail "formal source fixture must start clean"

"$profile_module" \
  --profile "$profile_name" \
  --source-dir "$source_dir" \
  --work-dir "$patched_source" >"$profile_log"

require_literal "$profile_log" 'compositionOrder=product-core,android-api31-arm64' \
  "profile did not report common-core-before-Android composition"
require_literal "$profile_log" "corePatchSeriesCount=$expected_core_count" \
  "profile did not report the Host-identical common-core patch count"
require_literal "$profile_log" "corePatchSeriesSha256=$expected_core_sha256" \
  "profile did not report the Host-identical common-core patch hash"
require_literal "$profile_log" "profile=$profile_name" \
  "profile did not report the Android profile identity"
require_literal "$profile_log" 'patchSeriesCount=' \
  "profile did not report the Android patch count"
require_literal "$profile_log" 'patchSeriesSha256=' \
  "profile did not report the Android patch hash"

# One prepared source must expose both sides of the composition. These are
# public VPP APIs/profile options, not a second reassembly implementation.
require_literal "$patched_source/src/vlib/buffer_funcs.h" \
  'vlib_buffer_enqueue_to_thread_retained' \
  "prepared Android source omitted the common retained-enqueue API"
require_literal "$patched_source/src/vnet/ip/reass/ip4_full_reass.h" \
  'ip4_full_reass_custom_register_consume_hook' \
  "prepared Android source omitted the common IPv4 reassembly seam"
require_literal "$patched_source/src/vnet/ip/reass/ip6_full_reass.h" \
  'ip6_full_reass_custom_register_consume_hook' \
  "prepared Android source omitted the common IPv6 reassembly seam"
require_literal "$patched_source/src/CMakeLists.txt" \
  'option(SAKAMOTO_VPP_NO_IPSEC' \
  "prepared Android source omitted the accepted no-IPsec profile"
require_literal "$patched_source/src/vlib/file.c" \
  'SAKAMOTO_ANDROID_WORKER_IDLE_IGNORES_RECENT_BARRIER_HOLDOFF' \
  "prepared Android source omitted the accepted worker idle behavior"

[[ "$(git -C "$source_dir" rev-parse HEAD)" == "$before_head" ]] || \
  fail "composition changed the clean input revision"
[[ -z "$(git -C "$source_dir" status --porcelain=v1 --untracked-files=all)" ]] || \
  fail "composition modified the clean input checkout"

echo "SAKAMOTO-175 Android VPP core/profile contract: PASS"
