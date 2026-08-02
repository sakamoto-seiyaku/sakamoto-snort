#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-44: bounded queue-count matrix. The lane-matrix mode is deliberately
# throwaway: it uses one clib_file callback per NFQUEUE socket, records the
# requested polling-context count, and keeps owner selection independent of the
# queue number. It is not a production queue scheduler.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd -- "$POC_DIR/../.." && pwd)"
VPP_WORK_ROOT="${VPP_WORK_ROOT:-$POC_DIR/work}"
BUILD_DIR="${BUILD_DIR:-$VPP_WORK_ROOT/vpp-android-configure-probe}"
STAGE_DIR="${STAGE_DIR:-$VPP_WORK_ROOT/android-nfq-matrix-stage}"
REMOTE_ROOT="${REMOTE_ROOT:-/data/local/tmp/vpp-nfq-poc-44}"
REMOTE_BASE="${REMOTE_BASE:-/data/local/tmp/vpp-nfq-poc-44-matrix}"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
RESULT_DIR="${RESULT_DIR:-$POC_DIR/results/2026-07-20/sakamoto-44-nfqueue-topology-$RUN_ID}"
QUEUE_BASE="${QUEUE_BASE:-60}"
TARGETS_TEXT="${TARGETS:-192.168.4.1 192.168.4.2 192.168.4.3 192.168.4.4}"
BURST_COUNT="${BURST_COUNT:-16}"
SAMPLE_SECS="${SAMPLE_SECS:-3}"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"
mkdir -p "$RESULT_DIR"
exec > >(tee "$RESULT_DIR/run.log") 2>&1

vppctl_cmd() {
  local runtime_dir="$1" command="$2"
  adb_su "LD_LIBRARY_PATH='$REMOTE_ROOT/lib' '$REMOTE_ROOT/bin/vppctl' -s '$runtime_dir/cli.sock' $command" | tr -d '\r'
}

remove_rules() {
  local lane target queue
  read -r -a targets <<< "$TARGETS_TEXT"
  for lane in 0 1 2 3; do
    target="${targets[$lane]:-192.168.4.$((lane + 1))}"
    queue=$((QUEUE_BASE + lane))
    while adb_su "/system/bin/iptables -w -D OUTPUT -p icmp -d '$target' -j NFQUEUE --queue-num '$queue' --queue-bypass 2>/dev/null" >/dev/null 2>&1; do :; done
  done
}

stop_vpp() {
  local runtime_dir="$1"
  vppctl_cmd "$runtime_dir" 'nfqueue-poc disable' >/dev/null 2>&1 || true
  adb_su "if [ -f '$runtime_dir/vpp.pid' ]; then kill -TERM \$(cat '$runtime_dir/vpp.pid') 2>/dev/null || true; sleep 1; kill -KILL \$(cat '$runtime_dir/vpp.pid') 2>/dev/null || true; fi; for p in \$(pidof vpp 2>/dev/null || true); do kill -TERM \$p 2>/dev/null || true; done; sleep 1; for p in \$(pidof vpp 2>/dev/null || true); do kill -KILL \$p 2>/dev/null || true; done; rm -f '$runtime_dir/vpp.pid' '$runtime_dir/cli.sock' '$runtime_dir/statseg.sock'"
}

write_startup() {
  local name="$1"
  local conf="$RESULT_DIR/$name-startup.conf"
  cat > "$conf" <<EOF
unix {
  nodaemon
  nobanner
  runtime-dir $REMOTE_BASE/$name/runtime
  log $REMOTE_BASE/$name/logs/vpp.log
  cli-listen $REMOTE_BASE/$name/runtime/cli.sock
  cli-no-pager
}

api-segment {
  prefix vpp-nfq-poc-44-$name
}

statseg {
  socket-name $REMOTE_BASE/$name/runtime/statseg.sock
}

cpu {
  main-core 0
  corelist-workers 1-2
}

buffers {
  page-size default
}

plugins {
  path $REMOTE_ROOT/plugins
  plugin default { disable }
  plugin nfqueue_poc_plugin.so { enable }
}
EOF
  printf '%s\n' "$conf"
}

start_vpp() {
  local name="$1" runtime_dir="$2" conf="$3"
  adb_su "rm -rf '$REMOTE_BASE/$name'; mkdir -p '$runtime_dir' '$REMOTE_BASE/$name/logs' '$REMOTE_BASE/$name/shm'; chmod -R 777 '$REMOTE_BASE/$name'"
  adb_cmd push "$conf" "$REMOTE_BASE/$name/startup.conf" >/dev/null
  adb_su "chmod 644 '$REMOTE_BASE/$name/startup.conf'; cd '$REMOTE_ROOT' && export LD_LIBRARY_PATH='$REMOTE_ROOT/lib' SAKAMOTO_ANDROID_SHM_DIR='$REMOTE_BASE/$name/shm'; nohup '$REMOTE_ROOT/bin/vpp' plugin_path '$REMOTE_ROOT/plugins' -c '$REMOTE_BASE/$name/startup.conf' >'$REMOTE_BASE/$name/logs/stdout.log' 2>&1 < /dev/null & echo \$! > '$runtime_dir/vpp.pid'"
  sleep 3
  vppctl_cmd "$runtime_dir" 'show version' >/dev/null
}

sample_threads() {
  local runtime_dir="$1"
  adb_su "pid=\$(cat '$runtime_dir/vpp.pid' 2>/dev/null || true); if [ -n \"\$pid\" ]; then for t in /proc/\$pid/task/*; do tid=\${t##*/}; comm=\$(cat \"\$t/comm\" 2>/dev/null || true); ticks=\$(awk '{print \$14+\$15}' \"\$t/stat\" 2>/dev/null || echo 0); ctx=\$(awk '/voluntary_ctxt_switches:/{v+=\$2} /nonvoluntary_ctxt_switches:/{v+=\$2} END{print v+0}' \"\$t/status\" 2>/dev/null || echo 0); allowed=\$(grep '^Cpus_allowed_list:' \"\$t/status\" 2>/dev/null | awk '{print \$2}'); printf '%s comm=%s ticks=%s ctx=%s allowed=%s\\n' \"\$tid\" \"\$comm\" \"\$ticks\" \"\$ctx\" \"\$allowed\"; done; fi" | tr -d '\r'
}

run_case() {
  local lanes="$1" contexts="$2"
  local name="lanes${lanes}-contexts${contexts}"
  local runtime_dir="$REMOTE_BASE/$name/runtime"
  local case_dir="$RESULT_DIR/$name"
  local queue target lane
  mkdir -p "$case_dir"
  remove_rules
  stop_vpp "$runtime_dir"
  local conf
  conf="$(write_startup "$name")"
  start_vpp "$name" "$runtime_dir" "$conf"
  vppctl_cmd "$runtime_dir" "nfqueue-poc enable queue $QUEUE_BASE family ip4 mode lane-matrix lanes $lanes polling-contexts $contexts two-lane-stale" >"$case_dir/enable.txt"
  read -r -a targets <<< "$TARGETS_TEXT"
  for ((lane=0; lane<lanes; lane++)); do
    target="${targets[$lane]}"
    queue=$((QUEUE_BASE + lane))
    adb_su "/system/bin/iptables -w -I OUTPUT 1 -p icmp -d '$target' -j NFQUEUE --queue-num '$queue' --queue-bypass"
  done
  local probe_cmd="i=0; while [ \$i -lt $BURST_COUNT ]; do"
  for ((lane=0; lane<lanes; lane++)); do
    probe_cmd+=" /system/bin/ping -c 1 -W 1 '${targets[$lane]}' >/dev/null 2>&1 &"
  done
  probe_cmd+=' i=$((i + 1)); done; wait'
  adb_su "$probe_cmd" >"$case_dir/probes.txt" 2>&1 || true
  sleep 1
  vppctl_cmd "$runtime_dir" 'show nfqueue-poc' | tee "$case_dir/show.txt"
  adb_su 'cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null || true' | tr -d '\r' >"$case_dir/nfnetlink_queue.txt"
  sample_threads "$runtime_dir" >"$case_dir/threads.txt"
  sleep "$SAMPLE_SECS"
  sample_threads "$runtime_dir" >>"$case_dir/threads.txt"
  remove_rules
  local show
  show="$(cat "$case_dir/show.txt")"
  if ! grep -Eq 'mode lane-matrix' <<< "$show"; then echo "NO-GO $name: mode not active"; return 1; fi
  if ! grep -Eq "lane-matrix lanes $lanes polling-contexts $contexts" <<< "$show"; then echo "NO-GO $name: topology identity missing"; return 1; fi
  if grep -Eq 'verdict-errors [1-9]' <<< "$show"; then echo "NO-GO $name: verdict error"; return 1; fi
  for ((lane=0; lane<lanes; lane++)); do
    if ! grep -Eq "lane${lane} seen [1-9]" <<< "$show"; then echo "NO-GO $name: lane $lane did not receive traffic"; return 1; fi
    done
  echo "GO $name"
}

cleanup() {
  local rc=$?
  remove_rules || true
  stop_vpp "$REMOTE_BASE/lanes2-contexts1/runtime" || true
  stop_vpp "$REMOTE_BASE/lanes2-contexts2/runtime" || true
  stop_vpp "$REMOTE_BASE/lanes4-contexts1/runtime" || true
  stop_vpp "$REMOTE_BASE/lanes4-contexts2/runtime" || true
  local pids queues hooks
  pids="$(adb_su 'pidof vpp 2>/dev/null || true' | tr -d '\r\n')"
  queues="$(adb_su 'cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null || true' | tr -d '\r' | sed '/^[[:space:]]*$/d' | wc -l)"
  hooks="$(adb_su '/system/bin/iptables -S 2>/dev/null || true' | tr -d '\r' | grep -Ec 'NFQUEUE|nfqueue_poc' || true)"
  echo "final residue: vpp_pids=${pids:-none} queue_lines=$queues nfqueue_hooks=$hooks"
  if [[ -n "$pids" || "$queues" != 0 || "$hooks" != 0 ]]; then rc=1; fi
  return "$rc"
}
trap cleanup EXIT

echo '# SAKAMOTO-44 Android NFQUEUE topology matrix'
echo "run_id=$RUN_ID adb_serial=$(resolve_adb_serial) queue_base=$QUEUE_BASE"
echo "targets=$TARGETS_TEXT burst_count=$BURST_COUNT sample_secs=$SAMPLE_SECS"
device_preflight
if [[ "${SKIP_BUILD:-0}" != 1 ]]; then
  PYTHONPATH=/home/js/android/lineage/external/ply/ply TARGET=nfqueue_poc_plugin JOBS=4 "$POC_DIR/scripts/android-build-vpp-probe.sh"
  BUILD_DIR="$BUILD_DIR" STAGE_DIR="$STAGE_DIR" "$POC_DIR/scripts/android-stage-vpp-core.sh"
fi
BUILD_DIR="$BUILD_DIR" STAGE_DIR="$STAGE_DIR" REMOTE_ROOT="$REMOTE_ROOT" "$POC_DIR/scripts/android-push-vpp-core.sh"
run_case 2 1
run_case 2 2
run_case 4 1
run_case 4 2
echo 'matrix=GO'
