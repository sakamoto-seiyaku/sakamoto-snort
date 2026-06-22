#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
app_dir="$(cd -- "${script_dir}/.." && pwd)"
repo_root="$(cd -- "${app_dir}/../../../.." && pwd)"
apk="${1:-${app_dir}/build/outputs/snort-vpn-lite-debug.apk}"

source "$repo_root/dev/dev-android-device-lib.sh"

[[ -f "$apk" ]] || {
  echo "APK not found: $apk" >&2
  echo "Run: $script_dir/build-debug-apk.sh" >&2
  exit 1
}

adb_cmd install -r "$apk"
echo "ok: installed $apk"
