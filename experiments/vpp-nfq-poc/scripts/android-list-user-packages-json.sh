#!/usr/bin/env bash
set -euo pipefail

# PROTOTYPE: list third-party Android packages with UID and INTERNET flag.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mapfile -t package_lines < <(
  adb_cmd shell cmd package list packages -3 -U 2>/dev/null |
    tr -d '\r' |
    sort
)

internet_granted() {
  local package="$1"
  local package_dump
  package_dump="$(adb_cmd shell dumpsys package "$package" 2>/dev/null | tr -d '\r')"
  if [[ "$package_dump" == *"android.permission.INTERNET: granted=true"* ]]; then
    printf 'true'
  else
    printf 'false'
  fi
}

printf '{\n'
printf '  "schema": "sakamoto-android-user-packages-v0",\n'
printf '  "source": {\n'
printf '    "type": "android-package-manager",\n'
printf '    "thirdPartyOnly": true\n'
printf '  },\n'
printf '  "packages": [\n'

first=1
for line in "${package_lines[@]}"; do
  package="${line#package:}"
  package="${package%% uid:*}"
  uid="${line##* uid:}"
  if [ -z "$package" ] || [ -z "$uid" ] || [ "$package" = "$line" ]; then
    continue
  fi

  if [ "$first" = "1" ]; then
    first=0
  else
    printf ',\n'
  fi

  internet="$(internet_granted "$package")"
  printf '    {"package":"%s","uid":%s,"internetGranted":%s}' \
    "$package" "$uid" "$internet"
done

printf '\n'
printf '  ]\n'
printf '}\n'
