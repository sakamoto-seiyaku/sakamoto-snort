#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-122 raw resource sample.  It intentionally records device output
# only; interpretation belongs in S122_PACKET_PATH_PERF_MEMO.md.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"
REMOTE_ROOT="${REMOTE_ROOT:-/data/local/tmp/s122-vpp}"
HEV_LIB="${HEV_LIB:-$REMOTE_ROOT/lib/libhev-socks5-tunnel.so}"
RESULT_DIR="${RESULT_DIR:-$POC_DIR/results/s122/20260821-pixel6a-resource-udp}"
PROTOCOL="${PROTOCOL:-udp}"
PAYLOAD="${PAYLOAD:-1400}"
COUNT="${COUNT:-300000}"
BURST="${BURST:-32}"
TARGET_THREAD="${TARGET_THREAD:-1}"

export ADB="${ADB:-$REPO_ROOT/dev/adb}"
source "$REPO_ROOT/dev/dev-android-device-lib.sh"
mkdir -p "$RESULT_DIR"
device_preflight

vppctl() {
  local command="$1"
  adb_su "LD_LIBRARY_PATH='$REMOTE_ROOT/lib' '$REMOTE_ROOT/bin/vppctl' -s '$REMOTE_ROOT/runtime/cli.sock' $command" | tr -d '\r'
}

pid="$(adb_su "cat '$REMOTE_ROOT/runtime/vpp.pid'" | tr -d '\r\n')"
raw="$RESULT_DIR/resource.raw"
{
  echo "device=$(adb_target_desc)"
  echo "date=$(adb_su 'date -Ins' | tr -d '\r\n')"
  echo "vpp_pid=$pid"
  echo "run=s122-packet-path-perf protocol $PROTOCOL payload $PAYLOAD count $COUNT burst $BURST"
  echo "--- affinity ---"
  adb_su "for t in /proc/$pid/task/*; do tid=\${t##*/}; comm=\$(cat \"\$t/comm\" 2>/dev/null || true); allowed=\$(grep '^Cpus_allowed_list:' \"\$t/status\" 2>/dev/null | awk '{print \$2}'); cpu=\$(awk '{print \$39}' \"\$t/stat\" 2>/dev/null || true); printf '%s comm=%s cpu=%s allowed=%s\\n' \"\$tid\" \"\$comm\" \"\$cpu\" \"\$allowed\"; done" | tr -d '\r'
  echo "--- thermal-before ---"
  adb_su 'dumpsys thermalservice 2>/dev/null | head -120' | tr -d '\r' || true
  vppctl "s122-packet-path-perf run protocol $PROTOCOL target-thread $TARGET_THREAD payload $PAYLOAD count $COUNT burst $BURST lib $HEV_LIB"
  for sample in 1 2 3 4 5 6 7 8 9 10; do
    sleep 1
    echo "--- sample=$sample ---"
    adb_su "grep -E '^(Name|VmRSS|VmHWM|Threads):' /proc/$pid/status" | tr -d '\r'
    adb_su "for t in /proc/$pid/task/*; do tid=\${t##*/}; echo thread=\$tid; cat \"\$t/stat\" 2>/dev/null || true; done" | tr -d '\r'
    echo "cpuinfo"
    adb_su 'dumpsys cpuinfo 2>/dev/null | head -25' | tr -d '\r' || true
    echo "thermal"
    adb_su 'dumpsys thermalservice 2>/dev/null | head -120' | tr -d '\r' || true
    show="$(vppctl 'show s122-packet-path-perf')"
    echo "$show"
    if printf '%s\n' "$show" | grep -q 'finished 1 remaining 0' &&
       printf '%s\n' "$show" | grep -q 'active 0 pending 0'; then
      break
    fi
  done
  echo "--- final ---"
  vppctl 'show s122-packet-path-perf'
} | tee "$raw"

echo "results=$RESULT_DIR"
