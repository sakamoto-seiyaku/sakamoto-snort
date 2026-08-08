#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
build_script="$repo_root/app/android-runtime/scripts/build-debug-apk.sh"
default_stage="$repo_root/build-output/android-vpp-runtime/stage"
valid_stage="${VPP_RUNTIME_VALID_STAGE_DIR:-$repo_root/experiments/vpp-nfq-poc/work/android-nfq-two-lane-stage}"
tmp_dir="$(mktemp -d)"
trap 'rtk rm -rf "$tmp_dir"' EXIT

# A stage without VPP core must not produce an APK. Packet adapters are not a
# build input for SAKAMOTO-67.
missing_stage="$tmp_dir/missing-core-stage"
rtk mkdir -p "$missing_stage/bin" "$missing_stage/lib" "$missing_stage/plugins"
source_stage="$default_stage"
if [[ ! -f "$source_stage/bin/vpp" || ! -f "$source_stage/bin/vppctl" ]]; then
  source_stage="$valid_stage"
fi
rtk cp "$source_stage/bin/vpp" "$missing_stage/bin/vpp"
set +e
VPP_RUNTIME_STAGE_DIR="$missing_stage" "$build_script" >"$tmp_dir/missing.log" 2>&1
missing_rc=$?
set -e
if [[ "$missing_rc" == 0 ]]; then
  rtk cat "$tmp_dir/missing.log" >&2
  echo "artifact contract accepted a stage without VPP diagnostics" >&2
  exit 1
fi
rtk grep -Eq 'vppctl|runtime stage' "$tmp_dir/missing.log"

[[ -f "$valid_stage/bin/vpp" && -f "$valid_stage/bin/vppctl" ]] \
  || { echo "missing VPP core stage input: $valid_stage" >&2; exit 1; }
VPP_RUNTIME_STAGE_DIR="$valid_stage" "$build_script"

apk="$repo_root/app/android-runtime/build/outputs/sakamoto-runtime-debug.apk"
manifest="$(rtk unzip -p "$apk" assets/vpp-runtime.properties)"
entries="$(rtk unzip -Z1 "$apk")"
root_adapter="$(rtk awk -F= '$1 == "adapter.root" {print $2}' <<<"$manifest")"
vpn_adapter="$(rtk awk -F= '$1 == "adapter.vpn" {print $2}' <<<"$manifest")"
[[ -z "$root_adapter" && -z "$vpn_adapter" ]] \
  || { echo "APK manifest exposes a packet Adapter identity" >&2; exit 1; }
api_identity="$(rtk awk -F= '$1 == "apiIdentity" {print $2}' <<<"$manifest")"
[[ "$api_identity" =~ ^show_version_[0-9a-fA-F]{8}$ ]] \
  || { echo "manifest is missing generated show_version identity: $api_identity" >&2; exit 1; }
rtk grep -Fxq 'lib/arm64-v8a/libsakamoto_runtime_control.so' <<<"$entries"
if rtk grep -Eq 'nfqueue_poc|tun_poc' <<<"$entries"; then
  echo "APK promoted an experiment Adapter artifact" >&2
  exit 1
fi

echo "android runtime core artifact contract seam: PASS"
