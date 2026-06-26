#!/usr/bin/env bash
set -euo pipefail

# PROTOTYPE: resolve one Android package to one UID block rule JSON.

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "Usage: $0 PACKAGE [OUT_JSON]" >&2
  exit 2
fi

PACKAGE="$1"
OUT_JSON="${2:-}"
QUEUE="${QUEUE:-42}"
FAMILY="${FAMILY:-ip4}"
ACTION="${ACTION:-block}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"

package_line="$(
  adb_cmd shell cmd package list packages -U "$PACKAGE" 2>/dev/null |
    tr -d '\r' |
    awk -v package="$PACKAGE" '$1 == "package:" package { print; exit }'
)"

if [ -z "$package_line" ]; then
  echo "Package not found: $PACKAGE" >&2
  exit 1
fi

uid="$(printf '%s\n' "$package_line" | sed -n 's/.* uid:\([0-9][0-9]*\).*/\1/p')"
if [ -z "$uid" ]; then
  echo "Could not parse UID from: $package_line" >&2
  exit 1
fi

package_dump="$(adb_cmd shell dumpsys package "$PACKAGE" 2>/dev/null | tr -d '\r')"

internet_granted="false"
if [[ "$package_dump" == *"android.permission.INTERNET: granted=true"* ]]; then
  internet_granted="true"
fi

rule_id="block-${PACKAGE//./-}"

emit_json() {
  cat <<JSON
{
  "schema": "sakamoto-vpp-poc-rules-v0",
  "source": {
    "type": "android-package",
    "package": "$PACKAGE",
    "uid": $uid,
    "internetGranted": $internet_granted
  },
  "queue": $QUEUE,
  "family": "$FAMILY",
  "rules": [
    {
      "id": "$rule_id",
      "enabled": true,
      "action": "$ACTION",
      "uid": $uid,
      "package": "$PACKAGE"
    }
  ]
}
JSON
}

if [ -n "$OUT_JSON" ]; then
  emit_json >"$OUT_JSON"
else
  emit_json
fi
