#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"
LOG_DIR="$POC_DIR/results"
LOG="$LOG_DIR/android-preflight.log"
REMOTE_ROOT="${REMOTE_ROOT:-/data/local/tmp/vpp-nfq-poc}"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$LOG_DIR"
exec > >(tee "$LOG") 2>&1

run_su() {
  local title="$1"
  local command="$2"

  echo
  echo "## $title"
  set +e
  adb_su "$command" 2>&1 | tr -d '\r'
  local rc=${PIPESTATUS[0]}
  set -e
  echo "rc=$rc"
}

run_adb() {
  local title="$1"
  shift

  echo
  echo "## $title"
  set +e
  adb_cmd "$@" 2>&1 | tr -d '\r'
  local rc=$?
  set -e
  echo "rc=$rc"
}

device_preflight

echo "# Android VPP NFQUEUE preflight"
echo "adb_serial=$(adb_target_desc)"
echo "remote_root=$REMOTE_ROOT"
echo "log=$LOG"

run_adb "adb get-state" get-state
run_su "root identity" "id"
run_su "kernel and arch" "uname -a; uname -m"
run_su "android properties" "getprop ro.product.cpu.abi; getprop ro.build.version.sdk; getprop ro.build.version.release; getprop ro.product.model"
run_su "selinux" "nsenter -t 1 -m -- getenforce 2>/dev/null || getenforce 2>/dev/null || true"
run_su "tool paths" "command -v iptables ip6tables toybox busybox nsenter setenforce getenforce 2>/dev/null || true"
run_su "iptables version" "iptables --version 2>/dev/null || true; ip6tables --version 2>/dev/null || true"
run_su "iptables NFQUEUE help" "iptables -j NFQUEUE -h 2>&1 | head -80 || true"
run_su "existing NFQUEUE rules" "for tool in iptables ip6tables; do for table in raw mangle filter nat; do echo \"### \$tool -t \$table\"; \$tool -t \$table -S 2>/dev/null | grep -E 'NFQUEUE|sucre|snort|vpp' || true; done; done"
run_su "nfnetlink_queue proc" "cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null || true"
run_su "netfilter modules" "cat /proc/modules 2>/dev/null | grep -E 'nfnetlink_queue|nfnetlink|iptable|nft' || true"
run_su "related processes" "ps -A 2>/dev/null | grep -E 'sucre|snort|vpp|nfq' || true"
run_su "runtime linker paths" "ls -l /system/bin/linker64 /apex/com.android.runtime/bin/linker64 2>/dev/null || true"
run_su "data mount" "mount | grep -E ' /data |/data/local/tmp' || true"
run_su "prepare remote root" "mkdir -p '$REMOTE_ROOT/bin' '$REMOTE_ROOT/lib' '$REMOTE_ROOT/plugins' '$REMOTE_ROOT/runtime' '$REMOTE_ROOT/logs' && ls -ld '$REMOTE_ROOT' '$REMOTE_ROOT/bin' '$REMOTE_ROOT/lib' '$REMOTE_ROOT/plugins' '$REMOTE_ROOT/runtime' '$REMOTE_ROOT/logs'"

echo
echo "# Done"
echo "preflight log: $LOG"
