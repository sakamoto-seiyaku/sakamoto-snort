#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-77 proportional Android lane: run the same native live-buffer
# plugin on a rooted device, with two VPP workers and one IPv4/IPv6 OUTPUT
# queue per family. Host/netns fault cases remain the authoritative fault
# matrix; this device case proves the Android artifact and native round trip.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd -- "$POC_DIR/../.." && pwd)"
REMOTE_ROOT="${REMOTE_ROOT:-/data/local/tmp/vpp-nfq-s77}"
QUEUE_BASE="${QUEUE_BASE:-72}"
IP4_TARGET="${IP4_TARGET:-1.1.1.1}"
IP6_TARGET="${IP6_TARGET:-2606:4700:4700::1111}"
PING_COUNT="${PING_COUNT:-4}"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
RESULT_DIR="${RESULT_DIR:-$POC_DIR/results/sakamoto-77-android-live-$RUN_ID}"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"
mkdir -p "$RESULT_DIR"
exec > >(tee "$RESULT_DIR/run.log") 2>&1

vppctl_cmd() {
  adb_su "LD_LIBRARY_PATH='$REMOTE_ROOT/lib' '$REMOTE_ROOT/bin/vppctl' -s '$REMOTE_ROOT/runtime/cli.sock' $1"
}

remove_rules() {
  while adb_su "/system/bin/iptables -w -D OUTPUT -p icmp -d '$IP4_TARGET' -j NFQUEUE --queue-num '$QUEUE_BASE' --queue-bypass 2>/dev/null" >/dev/null 2>&1; do :; done
  while adb_su "/system/bin/ip6tables -w -D OUTPUT -p ipv6-icmp -d '$IP6_TARGET' -j NFQUEUE --queue-num '$((QUEUE_BASE + 2))' --queue-bypass 2>/dev/null" >/dev/null 2>&1; do :; done
}

stop_vpp() {
  vppctl_cmd 'nfqueue-live-poc disable' >/dev/null 2>&1 || true
  adb_su "if [ -f '$REMOTE_ROOT/runtime/vpp.pid' ]; then kill -TERM \$(cat '$REMOTE_ROOT/runtime/vpp.pid') 2>/dev/null || true; sleep 1; kill -KILL \$(cat '$REMOTE_ROOT/runtime/vpp.pid') 2>/dev/null || true; fi; for p in \$(pidof vpp 2>/dev/null || true); do kill -TERM \$p 2>/dev/null || true; done; sleep 1; rm -f '$REMOTE_ROOT/runtime/vpp.pid' '$REMOTE_ROOT/runtime/cli.sock' '$REMOTE_ROOT/runtime/statseg.sock'"
}

capture_residue() {
  local label="$1"
  adb_su 'pidof vpp 2>/dev/null || true' | tr -d '\r' >"$RESULT_DIR/$label-vpp-pids.txt"
  adb_su 'cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null || true' | tr -d '\r' >"$RESULT_DIR/$label-nfnetlink-queue.txt"
  adb_su '/system/bin/iptables -S 2>/dev/null || true; /system/bin/ip6tables -S 2>/dev/null || true' | tr -d '\r' >"$RESULT_DIR/$label-firewall.txt"
}

cleanup() {
  local rc=$?
  remove_rules || true
  stop_vpp || true
  capture_residue final || true
  local pids queues hooks
  pids="$(adb_su 'pidof vpp 2>/dev/null || true' | tr -d '\r\n')"
  queues="$(adb_su 'cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null || true' | tr -d '\r' | sed '/^[[:space:]]*$/d' | wc -l)"
  hooks="$(adb_su '/system/bin/iptables -S 2>/dev/null || true; /system/bin/ip6tables -S 2>/dev/null || true' | tr -d '\r' | grep -Ec 'NFQUEUE' || true)"
  echo "Android S77 residue: vpp_pids=${pids:-none} queue_lines=$queues nfqueue_hooks=$hooks"
  if [[ -n "$pids" || "$queues" != 0 || "$hooks" != 0 ]]; then
    rc=1
  fi
  return "$rc"
}
trap cleanup EXIT

device_preflight
remove_rules
stop_vpp
adb_su "chown -R shell:shell '$REMOTE_ROOT' 2>/dev/null || true; chmod -R 777 '$REMOTE_ROOT' 2>/dev/null || true; rm -rf '$REMOTE_ROOT/runtime/cli.sock' '$REMOTE_ROOT/runtime/statseg.sock' '$REMOTE_ROOT/logs/vpp.log' '$REMOTE_ROOT/logs/vpp-stdout.log'; mkdir -p '$REMOTE_ROOT/runtime' '$REMOTE_ROOT/logs' '$REMOTE_ROOT/shm'; chmod 777 '$REMOTE_ROOT/shm'; cd '$REMOTE_ROOT' && export LD_LIBRARY_PATH='$REMOTE_ROOT/lib' SAKAMOTO_ANDROID_SHM_DIR='$REMOTE_ROOT/shm'; nohup '$REMOTE_ROOT/bin/vpp' plugin_path '$REMOTE_ROOT/plugins' -c '$REMOTE_ROOT/runtime/startup.conf' >'$REMOTE_ROOT/logs/vpp-stdout.log' 2>&1 < /dev/null & echo \$! > '$REMOTE_ROOT/runtime/vpp.pid'"
sleep 3
vppctl_cmd 'show version' | tr -d '\r' | tee "$RESULT_DIR/version.txt"

vppctl_cmd "nfqueue-live-poc enable-dual queue-base '$QUEUE_BASE' two-workers owner-remote" | tee "$RESULT_DIR/enable.txt"
adb_su "/system/bin/iptables -w -I OUTPUT 1 -p icmp -d '$IP4_TARGET' -j NFQUEUE --queue-num '$QUEUE_BASE' --queue-bypass"
adb_su "/system/bin/ip6tables -w -I OUTPUT 1 -p ipv6-icmp -d '$IP6_TARGET' -j NFQUEUE --queue-num '$((QUEUE_BASE + 2))' --queue-bypass"

set +e
adb_su "/system/bin/ping -c '$PING_COUNT' -W 2 '$IP4_TARGET'" >"$RESULT_DIR/ping4.txt" 2>&1
ping4_rc=$?
adb_su "/system/bin/ping6 -c '$PING_COUNT' -W 2 '$IP6_TARGET'" >"$RESULT_DIR/ping6.txt" 2>&1
ping6_rc=$?
set -e
sleep 1

vppctl_cmd 'show nfqueue-live-poc' | tr -d '\r' | tee "$RESULT_DIR/show-before-disable.txt"
vppctl_cmd 'nfqueue-live-poc disable' | tee "$RESULT_DIR/disable.txt"
remove_rules
echo "ping4_rc=$ping4_rc ping6_rc=$ping6_rc"

show="$(cat "$RESULT_DIR/show-before-disable.txt")"
value_for() { awk -v key="$1" '$1 == key { print $2; exit }' <<<"$show"; }
require_ge() {
  local key="$1" minimum="$2" value="$(value_for "$1")"
  [[ "$value" =~ ^[0-9]+$ && "$value" -ge "$minimum" ]] || { echo "Android S77 acceptance: $key=$value expected >= $minimum" >&2; exit 1; }
}
require_eq() {
  local key="$1" expected="$2" value="$(value_for "$1")"
  [[ "$value" == "$expected" ]] || { echo "Android S77 acceptance: $key=$value expected $expected" >&2; exit 1; }
}

grep -q 'workers 2' <<<"$show"
require_ge datagrams 1
require_ge callbacks 1
require_ge physical-verdict-attempts 1
require_eq outstanding-obligations 0
require_eq completion-debt 0
require_eq packet-copies 0
require_eq verdict-identity-mismatches 0
require_eq retry-attempts 0
require_eq worker-reentries 0
require_eq policy-re-evaluations 0
require_eq replacement-payloads 0
require_eq terminal-intent-rewrites 0
require_eq policy-verdict-rewrites 0
echo 'S77 Android live-buffer acceptance: PASS'
echo "result_dir=$RESULT_DIR"
