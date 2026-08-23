#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-122 real-device UDP matrix.  This script only records raw device
# output; interpretation stays in S122_PACKET_PATH_PERF_MEMO.md.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"
REMOTE_ROOT="${REMOTE_ROOT:-/data/local/tmp/s122-vpp}"
HEV_LIB="${HEV_LIB:-$REMOTE_ROOT/lib/libhev-socks5-tunnel.so}"
RESULT_DIR="${RESULT_DIR:-$POC_DIR/results/s122/20260821-pixel6a-udp-matrix}"
TARGET_THREAD="${TARGET_THREAD:-1}"
LOW_COUNT="${LOW_COUNT:-1000}"
HIGH_COUNT="${HIGH_COUNT:-100000}"
WAIT_SECS="${WAIT_SECS:-1}"

export ADB="${ADB:-$REPO_ROOT/dev/adb}"
source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$RESULT_DIR"
device_preflight

vppctl() {
  local command="$1"
  adb_su "LD_LIBRARY_PATH='$REMOTE_ROOT/lib' '$REMOTE_ROOT/bin/vppctl' -s '$REMOTE_ROOT/runtime/cli.sock' $command" | tr -d '\r'
}

pid="$(adb_su "cat '$REMOTE_ROOT/runtime/vpp.pid'" | tr -d '\r\n')"
{
  echo "device=$(adb_target_desc)"
  echo "date=$(adb_su 'date -Ins' | tr -d '\r\n')"
  echo "product=$(adb_su 'getprop ro.product.device' | tr -d '\r\n')"
  echo "model=$(adb_su 'getprop ro.product.model' | tr -d '\r\n')"
  echo "build=$(adb_su 'getprop ro.build.fingerprint' | tr -d '\r\n')"
  echo "vpp_pid=$pid"
  echo "threads=$(adb_su "cat /proc/$pid/status | grep '^Threads:'" | tr -d '\r')"
  echo "--- show threads ---"
  vppctl "show threads"
  echo "--- affinity ---"
  adb_su "for t in /proc/$pid/task/*; do tid=\${t##*/}; comm=\$(cat \"\$t/comm\" 2>/dev/null || true); allowed=\$(grep '^Cpus_allowed_list:' \"\$t/status\" 2>/dev/null | awk '{print \$2}'); cpu=\$(awk '{print \$39}' \"\$t/stat\" 2>/dev/null || true); printf '%s comm=%s cpu=%s allowed=%s\\n' \"\$tid\" \"\$comm\" \"\$cpu\" \"\$allowed\"; done" | tr -d '\r'
  echo "--- cpu topology ---"
  adb_su "for c in /sys/devices/system/cpu/cpu[0-9]*; do cpu=\${c##*cpu}; online=\$(cat \"\$c/online\" 2>/dev/null || echo 1); cap=\$(cat \"\$c/cpu_capacity\" 2>/dev/null || echo '?'); max=\$(cat \"/sys/devices/system/cpu/cpufreq/policy\$cpu/cpuinfo_max_freq\" 2>/dev/null || echo '?'); printf 'cpu=%s online=%s capacity=%s max_freq=%s\\n' \"\$cpu\" \"\$online\" \"\$cap\" \"\$max\"; done" | tr -d '\r'
} >"$RESULT_DIR/device-metadata.raw"

run_one() {
  local name="$1"
  local payload="$2"
  local count="$3"
  local burst="$4"
  local raw="$RESULT_DIR/$name.raw"
  local show=""
  local started

  started="$(date -Ins)"
  {
    echo "run=$name"
    echo "started=$started"
    echo "device=$(adb_target_desc)"
    echo "vpp_pid=$pid"
    echo "command=s122-packet-path-perf run target-thread $TARGET_THREAD payload $payload count $count burst $burst lib $HEV_LIB"
    vppctl "s122-packet-path-perf run target-thread $TARGET_THREAD payload $payload count $count burst $burst lib $HEV_LIB"
    for _ in $(seq 1 120); do
      sleep "$WAIT_SECS"
      show="$(vppctl "show s122-packet-path-perf")"
      printf '%s\n' "$show"
      if printf '%s\n' "$show" | grep -q 'finished 1 remaining 0' &&
         printf '%s\n' "$show" | grep -q 'active 0 pending 0'; then
        break
      fi
    done
    echo "finished=$(date -Ins)"
    echo "--- vpp stdout tail ---"
    adb_su "tail -20 '$REMOTE_ROOT/logs/vpp-stdout.log'" | tr -d '\r'
  } | tee "$raw"
}

for payload in 33 64 512 1400; do
  run_one "udp-p${payload}-low" "$payload" "$LOW_COUNT" 1
  run_one "udp-p${payload}-high" "$payload" "$HIGH_COUNT" 1
  run_one "udp-p${payload}-burst8" "$payload" "$HIGH_COUNT" 8
  run_one "udp-p${payload}-burst32" "$payload" "$HIGH_COUNT" 32
done

echo "results=$RESULT_DIR"
