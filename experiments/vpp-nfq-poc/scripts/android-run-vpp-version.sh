#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"
REMOTE_ROOT="${REMOTE_ROOT:-/data/local/tmp/vpp-nfq-poc}"
LOG_DIR="$POC_DIR/results"
LOG="$LOG_DIR/android-vpp-version.log"
SKIP_PUSH="${SKIP_PUSH:-0}"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$LOG_DIR"
exec > >(tee "$LOG") 2>&1

device_preflight
if [ "$SKIP_PUSH" != "1" ]; then
  "$SCRIPT_DIR/android-push-vpp-core.sh"
fi

echo "# Android VPP version probe"
echo "adb_serial=$(adb_target_desc)"
echo "remote_root=$REMOTE_ROOT"

set +e
adb_su "LD_LIBRARY_PATH='$REMOTE_ROOT/lib' '$REMOTE_ROOT/bin/vpp' -v" 2>&1 | tr -d '\r'
rc=${PIPESTATUS[0]}
set -e

echo "version_rc=$rc"
exit "$rc"
