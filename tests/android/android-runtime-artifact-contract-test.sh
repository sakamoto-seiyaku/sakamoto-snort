#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
build_script="$repo_root/app/android-runtime/scripts/build-debug-apk.sh"
default_stage="$repo_root/build-output/android-vpp-runtime/stage"
valid_stage="${VPP_RUNTIME_VALID_STAGE_DIR:-$default_stage}"
if [[ ! -f "$valid_stage/bin/vpp" || ! -f "$valid_stage/bin/vppctl" ]]; then
  valid_stage="$repo_root/experiments/vpp-nfq-poc/work/android-nfq-two-lane-stage"
fi
tmp_dir="$(mktemp -d)"
build_dir="$repo_root/app/android-runtime/build"
build_backup="$tmp_dir/build-backup"
build_was_present=0
restore_build() {
  local exit_code=$?
  if [[ "$build_was_present" == 1 ]]; then
    rm -rf "$build_dir"
    mv "$build_backup" "$build_dir"
  else
    rm -rf "$build_dir"
  fi
  rm -rf "$tmp_dir"
  exit "$exit_code"
}
trap restore_build EXIT

# A stage without VPP core must not produce an APK. Packet adapters are not a
# build input for SAKAMOTO-67.
missing_stage="$tmp_dir/missing-core-stage"
mkdir -p "$missing_stage/bin" "$missing_stage/lib" "$missing_stage/plugins"
source_stage="$default_stage"
if [[ ! -f "$source_stage/bin/vpp" || ! -f "$source_stage/bin/vppctl" ]]; then
  source_stage="$valid_stage"
fi
cp "$source_stage/bin/vpp" "$missing_stage/bin/vpp"
set +e
VPP_RUNTIME_STAGE_DIR="$missing_stage" "$build_script" >"$tmp_dir/missing.log" 2>&1
missing_rc=$?
set -e
if [[ "$missing_rc" == 0 ]]; then
  cat "$tmp_dir/missing.log" >&2
  echo "artifact contract accepted a stage without VPP diagnostics" >&2
  exit 1
fi
grep -Eq 'vppctl|runtime stage' "$tmp_dir/missing.log"

[[ -f "$valid_stage/bin/vpp" && -f "$valid_stage/bin/vppctl" ]] \
  || { echo "missing VPP core stage input: $valid_stage" >&2; exit 1; }
VPP_RUNTIME_STAGE_DIR="$valid_stage" "$build_script"

apk="$repo_root/app/android-runtime/build/outputs/sakamoto-runtime-debug.apk"
apksigner_jar="${APKSIGNER_JAR:-/home/js/android/lineage/prebuilts/sdk/tools/linux/lib/apksigner.jar}"
apk_cert_digest() {
  java -jar "$apksigner_jar" verify --print-certs "$1" \
    | awk -F': ' '/certificate SHA-256 digest/{gsub(":", "", $2); print tolower($2); exit}'
}
cert_before="$(apk_cert_digest "$apk")"
[[ "$cert_before" =~ ^[0-9a-f]{64}$ ]] \
  || { echo "unable to read APK signing certificate digest" >&2; exit 1; }
manifest="$(unzip -p "$apk" assets/vpp-runtime.properties)"
provenance="$(unzip -p "$apk" assets/vpp-runtime-provenance.properties)"
entries="$(unzip -Z1 "$apk")"
root_adapter="$(awk -F= '$1 == "adapter.root" {print $2}' <<<"$manifest")"
vpn_adapter="$(awk -F= '$1 == "adapter.vpn" {print $2}' <<<"$manifest")"
[[ -z "$root_adapter" && -z "$vpn_adapter" ]] \
  || { echo "APK manifest exposes a packet Adapter identity" >&2; exit 1; }
api_identity="$(awk -F= '$1 == "apiIdentity" {print $2}' <<<"$manifest")"
[[ "$api_identity" =~ ^show_version_[0-9a-fA-F]{8}$ ]] \
  || { echo "manifest is missing generated show_version identity: $api_identity" >&2; exit 1; }
grep -Fxq 'conditionalWakeSource=absent' <<<"$manifest"
grep -Fxq 'conditionalWakeBinary=absent' <<<"$manifest"
grep -Fxq 'conditionalWakeSource=absent' <<<"$provenance"
grep -Fxq 'conditionalWakeBinary=absent' <<<"$provenance"
grep -Fxq 'sourceStatus=committed-snapshot' <<<"$provenance"
source_tree="$(awk -F= '$1 == "sourceTree" {print $2}' <<<"$provenance")"
source_revision="$(awk -F= '$1 == "sourceRevision" {print $2}' <<<"$provenance")"
source_tree_digest="$(awk -F= '$1 == "sourceTreeSha256" {print $2}' <<<"$provenance")"
base_archive_digest="$(awk -F= '$1 == "baseArchiveSha256" {print $2}' <<<"$provenance")"
base_tree_digest="$(awk -F= '$1 == "baseTreeSha256" {print $2}' <<<"$provenance")"
overlay_digest="$(awk -F= '$1 == "overlaySha256" {print $2}' <<<"$provenance")"
[[ -f "$source_tree/.sakamoto-source-revision" ]] \
  || { echo "provenance source snapshot marker is missing" >&2; exit 1; }
grep -Fxq "$source_revision" "$source_tree/.sakamoto-source-revision"
[[ "$source_tree_digest" =~ ^[0-9a-fA-F]{64}$ ]] \
  || { echo "provenance source tree digest is missing" >&2; exit 1; }
[[ "$base_archive_digest" =~ ^[0-9a-fA-F]{64}$ ]] \
  || { echo "provenance pinned base archive digest is missing" >&2; exit 1; }
[[ "$base_tree_digest" =~ ^[0-9a-fA-F]{64}$ ]] \
  || { echo "provenance extracted base tree digest is missing" >&2; exit 1; }
[[ "$overlay_digest" =~ ^[0-9a-fA-F]{64}$ ]] \
  || { echo "provenance repository overlay digest is missing" >&2; exit 1; }
grep -Fxq 'sourceRevision=9258530f3804a152578ce11cc7c8a1e9eab88ed0' <<<"$manifest"
grep -Fxq 'sourceRevision=9258530f3804a152578ce11cc7c8a1e9eab88ed0' <<<"$provenance"
if unzip -p "$apk" lib/arm64-v8a/libvpp_runtime.so \
    | strings | grep -Eq 'wakeup_epoch|vlib_frame_queue_wakeup_mode|VLIB_WAKE_PHASE'; then
  echo "APK core binary contains rejected conditional-wake symbols" >&2
  exit 1
fi
grep -Fxq 'lib/arm64-v8a/libsakamoto_runtime_control.so' <<<"$entries"
grep -Fxq 'lib/arm64-v8a/libhev-socks5-tunnel.so' <<<"$entries"
if grep -Eq 'nfqueue_poc|tun_poc' <<<"$entries"; then
  echo "APK promoted an experiment Adapter artifact" >&2
  exit 1
fi
if grep -Eq 'vpnfdprobe|vpppoc' <<<"$entries"; then
  echo "APK promoted a VPN/TUN POC harness artifact" >&2
  exit 1
fi

# The provenance check extracts a fresh pinned archive into build/. Verify the
# APK boundary creates that parent itself rather than relying on a retained
# generated checkout directory.
if [[ -d "$build_dir" ]]; then
  build_was_present=1
  mv "$build_dir" "$build_backup"
fi
if [[ -e "$build_dir" ]]; then
  echo "unable to remove generated Android build directory for clean-build gate" >&2
  exit 1
fi
set +e
VPP_RUNTIME_STAGE_DIR="$valid_stage" "$build_script" >"$tmp_dir/clean-build.log" 2>&1
clean_build_rc=$?
set -e
if [[ "$clean_build_rc" != 0 ]]; then
  cat "$tmp_dir/clean-build.log" >&2
  echo "APK build failed when app/android-runtime/build was absent" >&2
  exit 1
fi
[[ -f "$build_dir/outputs/sakamoto-runtime-debug.apk" ]] \
  || { echo "clean-build gate did not produce an APK" >&2; exit 1; }
cert_after="$(apk_cert_digest "$build_dir/outputs/sakamoto-runtime-debug.apk")"
[[ "$cert_after" == "$cert_before" ]] \
  || { echo "clean-build APK signing certificate changed" >&2; exit 1; }

echo "android runtime core artifact contract seam: PASS"
