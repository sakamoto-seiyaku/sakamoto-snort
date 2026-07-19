#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"
VPP_WORK_ROOT="${VPP_WORK_ROOT:-$POC_DIR/work}"
STAGE_DIR="${STAGE_DIR:-$VPP_WORK_ROOT/android-vpp-core-stage}"
STAGE_SCRIPT="${STAGE_SCRIPT:-$SCRIPT_DIR/android-stage-vpp-core.sh}"
REMOTE_ROOT="${REMOTE_ROOT:-/data/local/tmp/vpp-nfq-poc}"
LOG_DIR="$POC_DIR/results"
LOG="$LOG_DIR/android-vpp-push-core.log"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$LOG_DIR"
exec > >(tee "$LOG") 2>&1

device_preflight
"$STAGE_SCRIPT"

echo "# Android VPP core push"
echo "adb_serial=$(adb_target_desc)"
echo "remote_root=$REMOTE_ROOT"
echo "stage_dir=$STAGE_DIR"
echo "stage_script=$STAGE_SCRIPT"

adb_su "rm -rf '$REMOTE_ROOT/bin' '$REMOTE_ROOT/lib' '$REMOTE_ROOT/plugins' '$REMOTE_ROOT/runtime/startup.conf'; mkdir -p '$REMOTE_ROOT/bin' '$REMOTE_ROOT/lib' '$REMOTE_ROOT/plugins' '$REMOTE_ROOT/runtime' '$REMOTE_ROOT/logs'; chmod 777 '$REMOTE_ROOT' '$REMOTE_ROOT/bin' '$REMOTE_ROOT/lib' '$REMOTE_ROOT/plugins' '$REMOTE_ROOT/runtime'"
for file in "$STAGE_DIR/bin"/*; do
  [ -f "$file" ] || continue
  adb_push_file "$file" "$REMOTE_ROOT/bin/$(basename "$file")"
done
for file in "$STAGE_DIR/lib"/*; do
  [ -f "$file" ] || continue
  adb_push_file "$file" "$REMOTE_ROOT/lib/$(basename "$file")"
done
for file in "$STAGE_DIR/plugins"/*; do
  [ -f "$file" ] || continue
  adb_push_file "$file" "$REMOTE_ROOT/plugins/$(basename "$file")"
done
adb_cmd push "$STAGE_DIR/runtime/startup.conf" "$REMOTE_ROOT/runtime/startup.conf"
adb_su "chmod 755 '$REMOTE_ROOT' '$REMOTE_ROOT/bin' '$REMOTE_ROOT/lib' '$REMOTE_ROOT/plugins' '$REMOTE_ROOT/runtime'; find '$REMOTE_ROOT/bin' -type f -exec chmod 755 {} +; find '$REMOTE_ROOT/lib' -type f -name '*.so' -exec chmod 755 {} +; find '$REMOTE_ROOT/plugins' -type f -name '*.so' -exec chmod 755 {} +; chmod 644 '$REMOTE_ROOT/runtime/startup.conf'; find '$REMOTE_ROOT/bin' '$REMOTE_ROOT/lib' '$REMOTE_ROOT/plugins' -maxdepth 1 -type f -printf '%p %s %m\\n' | sort; ls -l '$REMOTE_ROOT/runtime/startup.conf'"

echo "# Done"
echo "push log: $LOG"
