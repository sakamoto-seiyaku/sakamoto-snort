#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-122 sustained real-device sample.  The packet generator is still
# the test-only VPP worker fixture; the sample itself is collected from the
# Pixel 6a VPP process, never from a host binary.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"
REMOTE_ROOT="${REMOTE_ROOT:-/data/local/tmp/s122-vpp}"
HEV_LIB="${HEV_LIB:-$REMOTE_ROOT/lib/libhev-socks5-tunnel.so}"
RESULT_DIR="${RESULT_DIR:-$POC_DIR/results/s122/20260821-pixel6a-flamegraph}"
SIMPLEPERF_HOST="${SIMPLEPERF_HOST:-/home/js/.local/share/android-sdk/ndk/29.0.14206865/simpleperf/bin/linux/x86_64/simpleperf}"
SIMPLEPERF_REMOTE="${SIMPLEPERF_REMOTE:-/data/local/tmp/simpleperf-s122}"
TARGET_THREAD="${TARGET_THREAD:-1}"
PAYLOAD="${PAYLOAD:-1400}"
COUNT="${COUNT:-1000000}"
BURST="${BURST:-32}"
DURATION="${DURATION:-30}"
PROTOCOL="${PROTOCOL:-udp}"

export ADB="${ADB:-$REPO_ROOT/dev/adb}"
source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$RESULT_DIR/symfs/data/local/tmp/s122-vpp/lib" \
  "$RESULT_DIR/symfs/data/local/tmp/s122-vpp/plugins"
device_preflight

vppctl() {
  local command="$1"
  adb_su "LD_LIBRARY_PATH='$REMOTE_ROOT/lib' '$REMOTE_ROOT/bin/vppctl' -s '$REMOTE_ROOT/runtime/cli.sock' $command" | tr -d '\r'
}

pid="$(adb_su "cat '$REMOTE_ROOT/runtime/vpp.pid'" | tr -d '\r\n')"
perf_remote="$REMOTE_ROOT/perf-s122.data"
perf_local="$RESULT_DIR/perf.data"

{
  echo "device=$(adb_target_desc)"
  echo "date=$(adb_su 'date -Ins' | tr -d '\r\n')"
  echo "product=$(adb_su 'getprop ro.product.device' | tr -d '\r\n')"
  echo "model=$(adb_su 'getprop ro.product.model' | tr -d '\r\n')"
  echo "build=$(adb_su 'getprop ro.build.fingerprint' | tr -d '\r\n')"
  echo "vpp_pid=$pid"
  echo "command=s122-packet-path-perf run protocol $PROTOCOL target-thread $TARGET_THREAD payload $PAYLOAD count $COUNT burst $BURST lib $HEV_LIB"
  echo "simpleperf=/data/local/tmp/simpleperf-s122 record -p $pid -g --duration $DURATION"
} | tee "$RESULT_DIR/metadata.raw"

adb_su "rm -f '$perf_remote' '$REMOTE_ROOT/perf-s122.log' '$REMOTE_ROOT/perf-s122.pid'; '$SIMPLEPERF_REMOTE' record -p '$pid' -g --call-graph fp --duration '$DURATION' -o '$perf_remote' >'$REMOTE_ROOT/perf-s122.log' 2>&1 & echo \$! >'$REMOTE_ROOT/perf-s122.pid'"
sleep 1

{
  echo "--- trigger ---"
  vppctl "s122-packet-path-perf run protocol $PROTOCOL target-thread $TARGET_THREAD payload $PAYLOAD count $COUNT burst $BURST lib $HEV_LIB"
  for _ in $(seq 1 90); do
    sleep 1
    show="$(vppctl "show s122-packet-path-perf")"
    echo "$show"
    rss="$(adb_su "grep -E '^(VmRSS|VmHWM|Threads):' /proc/$pid/status" | tr -d '\r' || true)"
    cpu="$(adb_su "cat /proc/$pid/stat 2>/dev/null" | tr -d '\r' || true)"
    echo "--- proc sample ---"
    echo "$rss"
    echo "stat=$cpu"
    if printf '%s\n' "$show" | grep -q 'finished 1 remaining 0' &&
       printf '%s\n' "$show" | grep -q 'active 0 pending 0'; then
      break
    fi
  done
  echo "--- vpp stdout tail ---"
  adb_su "tail -20 '$REMOTE_ROOT/logs/vpp-stdout.log'" | tr -d '\r'
  echo "--- simpleperf log ---"
  adb_su "cat '$REMOTE_ROOT/perf-s122.log' 2>/dev/null || true" | tr -d '\r'
} | tee "$RESULT_DIR/execution.raw"

adb_cmd pull "$perf_remote" "$perf_local" >/dev/null
adb_cmd pull "$REMOTE_ROOT/perf-s122.log" "$RESULT_DIR/perf-device.log" >/dev/null 2>&1 || true

# Keep the exact unstripped arm64 objects beside the report for symbolization.
cp /tmp/s122-android-vpp-stage/bin/vpp "$RESULT_DIR/symfs/data/local/tmp/s122-vpp/bin-vpp" 2>/dev/null || true
cp /tmp/s122-android-vpp-stage/lib/*.so "$RESULT_DIR/symfs/data/local/tmp/s122-vpp/lib/" 2>/dev/null || true
cp /tmp/s122-android-vpp-stage/plugins/*.so "$RESULT_DIR/symfs/data/local/tmp/s122-vpp/plugins/" 2>/dev/null || true
cp /tmp/s122-hev-android-build/libs/arm64-v8a/libhev-socks5-tunnel.so "$RESULT_DIR/symfs/data/local/tmp/s122-vpp/lib/" 2>/dev/null || true

"$SIMPLEPERF_HOST" report -i "$perf_local" --symfs "$RESULT_DIR/symfs" --sort comm,dso,symbol --children -g --full-callgraph >"$RESULT_DIR/report.txt" || true
echo "results=$RESULT_DIR"
