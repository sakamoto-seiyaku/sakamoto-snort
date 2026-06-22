#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"
REMOTE_ROOT="${REMOTE_ROOT:-/data/local/tmp/vpp-nfq-poc}"
REMOTE_SHM_DIR="${REMOTE_SHM_DIR:-/data/local/tmp/vpp-shm}"
LOG_DIR="$POC_DIR/results"
LOG="$LOG_DIR/android-vpp-minimal.log"
SKIP_PUSH="${SKIP_PUSH:-0}"
STOP_AFTER="${STOP_AFTER:-1}"
WAIT_SECS="${WAIT_SECS:-3}"
VPP_EXTRA_ARGS="${VPP_EXTRA_ARGS:-}"
VPP_PLUGIN_PATH_ARGS="${VPP_PLUGIN_PATH_ARGS-plugin_path $REMOTE_ROOT/plugins}"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$LOG_DIR"
exec > >(tee "$LOG") 2>&1

device_preflight
if [ "$SKIP_PUSH" != "1" ]; then
  "$SCRIPT_DIR/android-push-vpp-core.sh"
fi

echo "# Android VPP minimal startup probe"
echo "adb_serial=$(adb_target_desc)"
echo "remote_root=$REMOTE_ROOT"
echo "remote_shm_dir=$REMOTE_SHM_DIR"
echo "vpp_plugin_path_args=$VPP_PLUGIN_PATH_ARGS"
echo "vpp_extra_args=$VPP_EXTRA_ARGS"

adb_su "if [ -f '$REMOTE_ROOT/runtime/vpp.pid' ]; then kill -TERM \$(cat '$REMOTE_ROOT/runtime/vpp.pid') 2>/dev/null || true; sleep 1; kill -9 \$(cat '$REMOTE_ROOT/runtime/vpp.pid') 2>/dev/null || true; fi; for p in \$(pidof vpp 2>/dev/null); do kill -TERM \$p 2>/dev/null || true; done; rm -rf '$REMOTE_SHM_DIR'; mkdir -p '$REMOTE_SHM_DIR'; rm -f '$REMOTE_ROOT/runtime/vpp.pid' '$REMOTE_ROOT/runtime/cli.sock' '$REMOTE_ROOT/runtime/statseg.sock' '$REMOTE_ROOT/logs/vpp.log' '$REMOTE_ROOT/logs/vpp-stdout.log'"
adb_su "cd '$REMOTE_ROOT' && export LD_LIBRARY_PATH='$REMOTE_ROOT/lib'; nohup '$REMOTE_ROOT/bin/vpp' $VPP_PLUGIN_PATH_ARGS $VPP_EXTRA_ARGS -c '$REMOTE_ROOT/runtime/startup.conf' >'$REMOTE_ROOT/logs/vpp-stdout.log' 2>&1 < /dev/null & echo \$! > '$REMOTE_ROOT/runtime/vpp.pid'"
sleep "$WAIT_SECS"

echo
echo "## process"
adb_su "cat '$REMOTE_ROOT/runtime/vpp.pid' 2>/dev/null || true; ps -A 2>/dev/null | grep '[v]pp' || true" | tr -d '\r'

echo
echo "## vpp stdout"
adb_su "cat '$REMOTE_ROOT/logs/vpp-stdout.log' 2>/dev/null || true" | tr -d '\r'

echo
echo "## vpp log"
adb_su "cat '$REMOTE_ROOT/logs/vpp.log' 2>/dev/null || true" | tr -d '\r'

echo
echo "## vppctl show version"
set +e
adb_su "LD_LIBRARY_PATH='$REMOTE_ROOT/lib' '$REMOTE_ROOT/bin/vppctl' -s '$REMOTE_ROOT/runtime/cli.sock' show version" 2>&1 | tr -d '\r'
rc=${PIPESTATUS[0]}
set -e
echo "vppctl_rc=$rc"

if [ "$STOP_AFTER" = "1" ]; then
  adb_su "if [ -f '$REMOTE_ROOT/runtime/vpp.pid' ]; then kill -TERM \$(cat '$REMOTE_ROOT/runtime/vpp.pid') 2>/dev/null || true; sleep 1; kill -9 \$(cat '$REMOTE_ROOT/runtime/vpp.pid') 2>/dev/null || true; fi; rm -f '$REMOTE_ROOT/runtime/vpp.pid'"
fi

exit "$rc"
