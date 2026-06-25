#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"
REMOTE_ROOT="${REMOTE_ROOT:-/data/local/tmp/vpp-nfq-poc}"
REMOTE_SHM_DIR="${REMOTE_SHM_DIR:-/data/local/tmp/vpp-shm-workers}"
MAIN_CORE="${MAIN_CORE:-0}"
WORKER_CORES="${WORKER_CORES:-1-2}"
WAIT_SECS="${WAIT_SECS:-3}"
STOP_AFTER="${STOP_AFTER:-1}"
LOG_DIR="$POC_DIR/results"
LOG="$LOG_DIR/android-vpp-worker-affinity.log"
LOCAL_CONF="$POC_DIR/build/android-vpp-worker-affinity-startup.conf"
REMOTE_CONF="$REMOTE_ROOT/runtime/startup-workers.conf"

if [ -z "${ADB:-}" ] && [ -x "$HOME/.local/android/platform-tools/adb" ]; then
  export ADB="$HOME/.local/android/platform-tools/adb"
fi

source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$LOG_DIR" "$(dirname "$LOCAL_CONF")"
exec > >(tee "$LOG") 2>&1

cat >"$LOCAL_CONF" <<EOF
unix {
  nodaemon
  nobanner
  full-coredump
  runtime-dir $REMOTE_ROOT/runtime-workers
  log $REMOTE_ROOT/logs/vpp-workers.log
  cli-listen $REMOTE_ROOT/runtime-workers/cli.sock
}

api-segment {
  prefix vpp-nfq-poc-workers
}

statseg {
  socket-name $REMOTE_ROOT/runtime-workers/statseg.sock
}

cpu {
  main-core $MAIN_CORE
  corelist-workers $WORKER_CORES
}

buffers {
  page-size default
}

plugins {
  path $REMOTE_ROOT/plugins
  plugin default { disable }
  plugin nfqueue_poc_plugin.so { enable }
  plugin tun_poc_plugin.so { enable }
}
EOF

device_preflight

echo "# Android VPP worker affinity probe"
echo "adb_serial=$(adb_target_desc)"
echo "remote_root=$REMOTE_ROOT"
echo "main_core=$MAIN_CORE"
echo "worker_cores=$WORKER_CORES"
echo "remote_conf=$REMOTE_CONF"
echo

adb_su "test -x '$REMOTE_ROOT/bin/vpp' && test -x '$REMOTE_ROOT/bin/vppctl' && test -d '$REMOTE_ROOT/lib'"

echo "## cpu topology"
adb_su "for c in /sys/devices/system/cpu/cpu[0-9]*; do cpu=\${c##*cpu}; online=\$(cat \"\$c/online\" 2>/dev/null || echo 1); core=\$(cat \"\$c/topology/core_id\" 2>/dev/null || echo '?'); pkg=\$(cat \"\$c/topology/physical_package_id\" 2>/dev/null || echo '?'); cap=\$(cat \"\$c/cpu_capacity\" 2>/dev/null || echo '?'); max=\$(cat \"/sys/devices/system/cpu/cpufreq/policy\$cpu/cpuinfo_max_freq\" 2>/dev/null || cat \"\$c/cpufreq/cpuinfo_max_freq\" 2>/dev/null || echo '?'); printf 'cpu=%s online=%s core=%s pkg=%s cap=%s max_freq=%s\n' \"\$cpu\" \"\$online\" \"\$core\" \"\$pkg\" \"\$cap\" \"\$max\"; done" | tr -d '\r'
echo

adb_su "if [ -f '$REMOTE_ROOT/runtime-workers/vpp.pid' ]; then kill -TERM \$(cat '$REMOTE_ROOT/runtime-workers/vpp.pid') 2>/dev/null || true; sleep 1; kill -9 \$(cat '$REMOTE_ROOT/runtime-workers/vpp.pid') 2>/dev/null || true; fi; for p in \$(pidof vpp 2>/dev/null); do kill -TERM \$p 2>/dev/null || true; done; rm -rf '$REMOTE_SHM_DIR' '$REMOTE_ROOT/runtime-workers'; mkdir -p '$REMOTE_SHM_DIR' '$REMOTE_ROOT/runtime-workers' '$REMOTE_ROOT/logs'; chmod 777 '$REMOTE_ROOT/runtime'"
adb_cmd push "$LOCAL_CONF" "$REMOTE_CONF" >/dev/null
adb_su "chmod 644 '$REMOTE_CONF'"

echo "## startup.conf"
sed 's/^/  /' "$LOCAL_CONF"

adb_su "cd '$REMOTE_ROOT' && export LD_LIBRARY_PATH='$REMOTE_ROOT/lib' SAKAMOTO_ANDROID_SHM_DIR='$REMOTE_SHM_DIR'; nohup '$REMOTE_ROOT/bin/vpp' plugin_path '$REMOTE_ROOT/plugins' -c '$REMOTE_CONF' >'$REMOTE_ROOT/logs/vpp-workers-stdout.log' 2>&1 < /dev/null & echo \$! > '$REMOTE_ROOT/runtime-workers/vpp.pid'"
sleep "$WAIT_SECS"

echo
echo "## process"
adb_su "cat '$REMOTE_ROOT/runtime-workers/vpp.pid' 2>/dev/null || true; ps -A 2>/dev/null | grep '[v]pp' || true" | tr -d '\r'

echo
echo "## stdout"
adb_su "cat '$REMOTE_ROOT/logs/vpp-workers-stdout.log' 2>/dev/null || true" | tr -d '\r'

echo
echo "## log"
adb_su "cat '$REMOTE_ROOT/logs/vpp-workers.log' 2>/dev/null || true" | tr -d '\r'

echo
echo "## vppctl show threads"
set +e
adb_su "LD_LIBRARY_PATH='$REMOTE_ROOT/lib' '$REMOTE_ROOT/bin/vppctl' -s '$REMOTE_ROOT/runtime-workers/cli.sock' show threads" 2>&1 | tr -d '\r'
threads_rc=${PIPESTATUS[0]}
set -e
echo "show_threads_rc=$threads_rc"

echo
echo "## /proc thread affinity"
adb_su "pid=\$(cat '$REMOTE_ROOT/runtime-workers/vpp.pid' 2>/dev/null || true); if [ -n \"\$pid\" ]; then for t in /proc/\$pid/task/*; do tid=\${t##*/}; comm=\$(cat \"\$t/comm\" 2>/dev/null || true); cpu=\$(awk '{print \$39}' \"\$t/stat\" 2>/dev/null || true); allowed=\$(grep '^Cpus_allowed_list:' \"\$t/status\" 2>/dev/null | awk '{print \$2}'); printf '%s comm=%s cpu=%s allowed=%s\n' \"\$tid\" \"\$comm\" \"\$cpu\" \"\$allowed\"; done; fi" | tr -d '\r'

if [ "$STOP_AFTER" = "1" ]; then
  adb_su "if [ -f '$REMOTE_ROOT/runtime-workers/vpp.pid' ]; then kill -TERM \$(cat '$REMOTE_ROOT/runtime-workers/vpp.pid') 2>/dev/null || true; sleep 1; kill -9 \$(cat '$REMOTE_ROOT/runtime-workers/vpp.pid') 2>/dev/null || true; fi; rm -f '$REMOTE_ROOT/runtime-workers/vpp.pid'"
fi

exit "$threads_rc"
