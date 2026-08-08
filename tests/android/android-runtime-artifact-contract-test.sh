#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
build_script="$repo_root/app/android-runtime/scripts/build-debug-apk.sh"
default_stage="$repo_root/build-output/android-vpp-runtime/stage"
valid_stage="${VPP_RUNTIME_VALID_STAGE_DIR:-$repo_root/experiments/vpp-nfq-poc/work/android-nfq-two-lane-stage}"
tmp_dir="$(mktemp -d)"
trap 'rtk rm -rf "$tmp_dir"' EXIT

# A stage with VPP core only must not produce an APK. This is the regression
# seam for the original SAKAMOTO-67 false-positive host build.
missing_stage="$tmp_dir/missing-plugin-stage"
rtk mkdir -p "$missing_stage/bin" "$missing_stage/lib" "$missing_stage/plugins"
source_stage="$default_stage"
if [[ ! -f "$source_stage/bin/vpp" || ! -f "$source_stage/bin/vppctl" ]]; then
  source_stage="$valid_stage"
fi
rtk cp "$source_stage/bin/vpp" "$missing_stage/bin/vpp"
rtk cp "$source_stage/bin/vppctl" "$missing_stage/bin/vppctl"
set +e
VPP_RUNTIME_STAGE_DIR="$missing_stage" "$build_script" >"$tmp_dir/missing.log" 2>&1
missing_rc=$?
set -e
if [[ "$missing_rc" == 0 ]]; then
  rtk cat "$tmp_dir/missing.log" >&2
  echo "artifact contract accepted a stage without both profile adapters" >&2
  exit 1
fi
rtk grep -Eq 'nfqueue_poc_plugin|tun_poc_plugin|adapter' "$tmp_dir/missing.log"

for plugin in nfqueue_poc_plugin.so tun_poc_plugin.so; do
  [[ -f "$valid_stage/plugins/$plugin" ]] \
    || { echo "missing proven POC adapter stage input: $valid_stage/plugins/$plugin" >&2; exit 1; }
done
VPP_RUNTIME_STAGE_DIR="$valid_stage" "$build_script"

apk="$repo_root/app/android-runtime/build/outputs/sakamoto-runtime-debug.apk"
manifest="$(rtk unzip -p "$apk" assets/vpp-runtime.properties)"
entries="$(rtk unzip -Z1 "$apk")"
root_adapter="$(rtk awk -F= '$1 == "adapter.root" {print $2}' <<<"$manifest")"
vpn_adapter="$(rtk awk -F= '$1 == "adapter.vpn" {print $2}' <<<"$manifest")"
[[ "$root_adapter" == libnfqueue_poc_plugin.so ]] \
  || { echo "root manifest adapter disagrees: $root_adapter" >&2; exit 1; }
[[ "$vpn_adapter" == libtun_poc_plugin.so ]] \
  || { echo "VPN manifest adapter disagrees: $vpn_adapter" >&2; exit 1; }
for plugin in "$root_adapter" "$vpn_adapter"; do
  rtk grep -Fxq "lib/arm64-v8a/$plugin" <<<"$entries" \
    || { echo "APK is missing declared adapter: $plugin" >&2; exit 1; }
done

echo "android runtime artifact contract seam: PASS"
