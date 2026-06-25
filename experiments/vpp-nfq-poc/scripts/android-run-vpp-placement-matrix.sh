#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"
REMOTE_ROOT="${REMOTE_ROOT:-/data/local/tmp/vpp-nfq-poc}"
REMOTE_BASE="${REMOTE_BASE:-/data/local/tmp/vpp-nfq-poc-matrix}"
SCENARIOS="${SCENARIOS:-low:0:1-2 single-mid:0:4 big:4:6-7}"
SAMPLES="${SAMPLES:-3}"
SAMPLE_SECS="${SAMPLE_SECS:-5}"
WAIT_SECS="${WAIT_SECS:-3}"
QUEUE_NUM="${QUEUE_NUM:-42}"
PING_IP="${PING_IP:-1.1.1.1}"
RUN_NFQUEUE="${RUN_NFQUEUE:-1}"
RUN_DATAPATH="${RUN_DATAPATH:-1}"
DATAPATH_SCENARIO="${DATAPATH_SCENARIO:-big}"
LOG_DIR="$POC_DIR/results"
LOG="${LOG:-$LOG_DIR/android-vpp-placement-matrix.log}"

if [ -z "${ADB:-}" ] && [ -x "$HOME/.local/android/platform-tools/adb" ]; then
  export ADB="$HOME/.local/android/platform-tools/adb"
fi

source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$LOG_DIR" "$POC_DIR/build"
exec > >(tee "$LOG") 2>&1

vppctl() {
  local runtime_dir="$1"
  local cmd="$2"
  adb_su "LD_LIBRARY_PATH='$REMOTE_ROOT/lib' '$REMOTE_ROOT/bin/vppctl' -s '$runtime_dir/cli.sock' $cmd" 2>&1 | tr -d '\r'
}

cleanup_device() {
  adb_su "for p in \$(pidof vpp 2>/dev/null); do kill -TERM \$p 2>/dev/null || true; done; sleep 1; for p in \$(pidof vpp 2>/dev/null); do kill -9 \$p 2>/dev/null || true; done; while iptables -w -D OUTPUT -p icmp -d '$PING_IP' -j NFQUEUE --queue-num '$QUEUE_NUM' --queue-bypass 2>/dev/null; do :; done" >/dev/null 2>&1 || true
}

write_startup() {
  local name="$1"
  local main_core="$2"
  local worker_cores="$3"
  local conf="$POC_DIR/build/android-vpp-placement-$name.conf"
  cat >"$conf" <<EOF
unix {
  nodaemon
  nobanner
  full-coredump
  runtime-dir $REMOTE_BASE/$name/runtime
  log $REMOTE_BASE/$name/logs/vpp.log
  cli-listen $REMOTE_BASE/$name/runtime/cli.sock
}

api-segment {
  prefix vpp-nfq-poc-$name
}

statseg {
  socket-name $REMOTE_BASE/$name/runtime/statseg.sock
}

cpu {
  main-core $main_core
  corelist-workers $worker_cores
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
  printf '%s\n' "$conf"
}

start_vpp() {
  local name="$1"
  local main_core="$2"
  local worker_cores="$3"
  local conf runtime_dir shm_dir
  conf="$(write_startup "$name" "$main_core" "$worker_cores")"
  runtime_dir="$REMOTE_BASE/$name/runtime"
  shm_dir="$REMOTE_BASE/$name/shm"

  adb_su "rm -rf '$REMOTE_BASE/$name'; mkdir -p '$runtime_dir' '$REMOTE_BASE/$name/logs' '$shm_dir'; chmod -R 777 '$REMOTE_BASE/$name'"
  adb_cmd push "$conf" "$REMOTE_BASE/$name/startup.conf" >/dev/null
  adb_su "chmod 644 '$REMOTE_BASE/$name/startup.conf'"

  adb_su "cd '$REMOTE_ROOT' && export LD_LIBRARY_PATH='$REMOTE_ROOT/lib' SAKAMOTO_ANDROID_SHM_DIR='$shm_dir'; nohup '$REMOTE_ROOT/bin/vpp' plugin_path '$REMOTE_ROOT/plugins' -c '$REMOTE_BASE/$name/startup.conf' >'$REMOTE_BASE/$name/logs/stdout.log' 2>&1 < /dev/null & echo \$! > '$runtime_dir/vpp.pid'"
  sleep "$WAIT_SECS"
}

pid_for() {
  local name="$1"
  adb_su "cat '$REMOTE_BASE/$name/runtime/vpp.pid' 2>/dev/null || true" | tr -d '\r\n'
}

print_cpu_topology() {
  echo "## cpu topology"
  adb_su "for c in /sys/devices/system/cpu/cpu[0-9]*; do cpu=\${c##*cpu}; online=\$(cat \"\$c/online\" 2>/dev/null || echo 1); cap=\$(cat \"\$c/cpu_capacity\" 2>/dev/null || echo '?'); max=\$(cat \"/sys/devices/system/cpu/cpufreq/policy\$cpu/cpuinfo_max_freq\" 2>/dev/null || cat \"\$c/cpufreq/cpuinfo_max_freq\" 2>/dev/null || echo '?'); printf 'cpu=%s online=%s cap=%s max_freq=%s\n' \"\$cpu\" \"\$online\" \"\$cap\" \"\$max\"; done" | tr -d '\r'
}

print_threads() {
  local name="$1"
  local runtime_dir="$REMOTE_BASE/$name/runtime"
  local pid
  pid="$(pid_for "$name")"

  echo "## show threads ($name)"
  vppctl "$runtime_dir" "show threads"

  echo "## /proc affinity ($name)"
  adb_su "pid='$pid'; if [ -n \"\$pid\" ]; then for t in /proc/\$pid/task/*; do tid=\${t##*/}; comm=\$(cat \"\$t/comm\" 2>/dev/null || true); cpu=\$(awk '{print \$39}' \"\$t/stat\" 2>/dev/null || true); allowed=\$(grep '^Cpus_allowed_list:' \"\$t/status\" 2>/dev/null | awk '{print \$2}'); ticks=\$(awk '{print \$14+\$15}' \"\$t/stat\" 2>/dev/null || true); printf '%s comm=%s cpu=%s allowed=%s ticks=%s\n' \"\$tid\" \"\$comm\" \"\$cpu\" \"\$allowed\" \"\$ticks\"; done; fi" | tr -d '\r'
}

read_snapshot() {
  local name="$1"
  local pid
  pid="$(pid_for "$name")"
  adb_su "pid='$pid'; if [ -n \"\$pid\" ]; then for t in /proc/\$pid/task/*; do tid=\${t##*/}; comm=\$(cat \"\$t/comm\" 2>/dev/null || true); cpu=\$(awk '{print \$39}' \"\$t/stat\" 2>/dev/null || true); allowed=\$(grep '^Cpus_allowed_list:' \"\$t/status\" 2>/dev/null | awk '{print \$2}'); ticks=\$(awk '{print \$14+\$15}' \"\$t/stat\" 2>/dev/null || true); printf '%s %s %s %s %s\n' \"\$tid\" \"\$comm\" \"\$cpu\" \"\$allowed\" \"\$ticks\"; done; fi" | tr -d '\r'
}

sample_cpu() {
  local name="$1"
  local label="$2"
  local hz interval
  hz="$(adb_su "getconf CLK_TCK 2>/dev/null || echo 100" | tr -d '\r\n')"
  interval="$SAMPLE_SECS"

  echo "## cpu sample name=$name label=$label samples=$SAMPLES window=${SAMPLE_SECS}s hz=$hz"
  for idx in $(seq 1 "$SAMPLES"); do
    declare -A start_ticks=()
    declare -A start_comm=()
    declare -A start_allowed=()
    while read -r tid comm cpu allowed ticks; do
      [ -n "${tid:-}" ] || continue
      start_ticks["$tid"]="$ticks"
      start_comm["$tid"]="$comm"
      start_allowed["$tid"]="$allowed"
    done < <(read_snapshot "$name")

    sleep "$interval"

    echo "sample=$idx"
    local total_pct="0.000"
    while read -r tid comm cpu allowed ticks; do
      [ -n "${tid:-}" ] || continue
      local prev="${start_ticks[$tid]:-}"
      [ -n "$prev" ] || continue
      local pct
      pct="$(awk -v a="$prev" -v b="$ticks" -v hz="$hz" -v sec="$interval" 'BEGIN { printf "%.3f", ((b-a) * 100.0) / (hz * sec) }')"
      total_pct="$(awk -v a="$total_pct" -v b="$pct" 'BEGIN { printf "%.3f", a + b }')"
      printf '  tid=%s comm=%s cpu=%s allowed=%s ticks_delta=%s cpu_pct=%s\n' \
        "$tid" "$comm" "$cpu" "$allowed" "$((ticks - prev))" "$pct"
    done < <(read_snapshot "$name")
    echo "  total_cpu_pct=$total_pct"
  done
}

nfqueue_enable() {
  local name="$1"
  local mode="$2"
  local runtime_dir="$REMOTE_BASE/$name/runtime"
  vppctl "$runtime_dir" "nfqueue-poc disable" >/dev/null || true
  vppctl "$runtime_dir" "nfqueue-poc enable queue $QUEUE_NUM mode $mode"
  vppctl "$runtime_dir" "show nfqueue-poc"
}

run_datapath_regression() {
  local name="$1"
  local runtime_dir="$REMOTE_BASE/$name/runtime"
  echo "## datapath regression ($name)"

  adb_su "while iptables -w -D OUTPUT -p icmp -d '$PING_IP' -j NFQUEUE --queue-num '$QUEUE_NUM' --queue-bypass 2>/dev/null; do :; done"
  adb_su "iptables -w -I OUTPUT 1 -p icmp -d '$PING_IP' -j NFQUEUE --queue-num '$QUEUE_NUM' --queue-bypass"

  echo "### accept-all"
  nfqueue_enable "$name" "accept-all"
  set +e
  adb_su "ping -c 4 -W 1 '$PING_IP'" 2>&1 | tr -d '\r'
  local accept_rc=${PIPESTATUS[0]}
  set -e
  echo "accept_ping_rc=$accept_rc"
  vppctl "$runtime_dir" "show nfqueue-poc"

  echo "### drop-all"
  nfqueue_enable "$name" "drop-all"
  set +e
  adb_su "ping -c 4 -W 1 '$PING_IP'" 2>&1 | tr -d '\r'
  local drop_rc=${PIPESTATUS[0]}
  set -e
  echo "drop_ping_rc=$drop_rc"
  vppctl "$runtime_dir" "show nfqueue-poc"

  adb_su "while iptables -w -D OUTPUT -p icmp -d '$PING_IP' -j NFQUEUE --queue-num '$QUEUE_NUM' --queue-bypass 2>/dev/null; do :; done"

  if [ "$accept_rc" -ne 0 ]; then
    echo "accept-all ping failed" >&2
    return 1
  fi
  if [ "$drop_rc" -eq 0 ]; then
    echo "drop-all ping unexpectedly succeeded" >&2
    return 1
  fi
}

device_preflight
trap cleanup_device EXIT

echo "# Android VPP placement matrix"
echo "adb_serial=$(adb_target_desc)"
echo "remote_root=$REMOTE_ROOT"
echo "remote_base=$REMOTE_BASE"
echo "scenarios=$SCENARIOS"
echo "samples=$SAMPLES sample_secs=$SAMPLE_SECS run_nfqueue=$RUN_NFQUEUE run_datapath=$RUN_DATAPATH"
echo

adb_su "test -x '$REMOTE_ROOT/bin/vpp' && test -x '$REMOTE_ROOT/bin/vppctl' && test -d '$REMOTE_ROOT/lib'"
cleanup_device
print_cpu_topology

for scenario in $SCENARIOS; do
  IFS=: read -r name main_core worker_cores <<<"$scenario"
  echo
  echo "# scenario name=$name main_core=$main_core worker_cores=$worker_cores"
  start_vpp "$name" "$main_core" "$worker_cores"
  print_threads "$name"
  sample_cpu "$name" "baseline"
  if [ "$RUN_NFQUEUE" = "1" ]; then
    echo "## enable nfqueue no-traffic ($name)"
    nfqueue_enable "$name" "accept-all"
    sample_cpu "$name" "nfqueue-enabled"
  fi
  if [ "$RUN_DATAPATH" = "1" ] && [ "$name" = "$DATAPATH_SCENARIO" ]; then
    run_datapath_regression "$name"
  fi
  cleanup_device
done

echo
echo "# matrix complete"
