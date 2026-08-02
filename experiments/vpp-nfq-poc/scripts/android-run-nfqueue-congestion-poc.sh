#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-39: separate userspace worker backpressure from listener-missing and
# kernel queue overflow on a rooted Android NFQUEUE path.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd -- "$POC_DIR/../.." && pwd)"
VPP_WORK_ROOT="${VPP_WORK_ROOT:-$POC_DIR/work}"
BUILD_DIR="${BUILD_DIR:-$VPP_WORK_ROOT/vpp-android-configure-probe}"
STAGE_DIR="${STAGE_DIR:-$VPP_WORK_ROOT/android-nfq-congestion-stage}"
REMOTE_ROOT="${REMOTE_ROOT:-/data/local/tmp/vpp-nfq-poc-39}"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
RESULT_DIR="$POC_DIR/results/sakamoto-39-nfqueue-congestion-$RUN_ID"
RUN_LOG="$RESULT_DIR/run.log"
IP4_TARGET="${IP4_TARGET:-192.168.4.1}"
IP6_TARGET="${IP6_TARGET:-::1}"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"
mkdir -p "$RESULT_DIR"
exec > >(tee "$RUN_LOG") 2>&1

failures=0
vpp_running=0

vppctl_cmd() {
  adb_su "LD_LIBRARY_PATH='$REMOTE_ROOT/lib' '$REMOTE_ROOT/bin/vppctl' -s '$REMOTE_ROOT/runtime/cli.sock' $1"
}

remove_rules() {
  while adb_su "/system/bin/iptables -w -D OUTPUT -p icmp -d '$IP4_TARGET' -j NFQUEUE --queue-num 54 --queue-bypass 2>/dev/null" >/dev/null 2>&1; do :; done
  while adb_su "/system/bin/ip6tables -w -D OUTPUT -p ipv6-icmp -d '$IP6_TARGET' -j NFQUEUE --queue-num 55 --queue-bypass 2>/dev/null" >/dev/null 2>&1; do :; done
}

stop_vpp() {
  vppctl_cmd 'nfqueue-poc disable' >/dev/null 2>&1 || true
  adb_su "if [ -f '$REMOTE_ROOT/runtime/vpp.pid' ]; then kill -TERM \$(cat '$REMOTE_ROOT/runtime/vpp.pid') 2>/dev/null || true; sleep 1; kill -KILL \$(cat '$REMOTE_ROOT/runtime/vpp.pid') 2>/dev/null || true; fi; for p in \$(pidof vpp 2>/dev/null || true); do kill -TERM \$p 2>/dev/null || true; done; sleep 1; rm -f '$REMOTE_ROOT/runtime/vpp.pid' '$REMOTE_ROOT/runtime/cli.sock' '$REMOTE_ROOT/runtime/statseg.sock'"
  vpp_running=0
}

start_vpp() {
  stop_vpp
  adb_su "rm -rf '$REMOTE_ROOT/runtime/cli.sock' '$REMOTE_ROOT/runtime/statseg.sock' '$REMOTE_ROOT/logs/vpp-stdout.log'; mkdir -p '$REMOTE_ROOT/runtime' '$REMOTE_ROOT/logs'; cd '$REMOTE_ROOT' && export LD_LIBRARY_PATH='$REMOTE_ROOT/lib'; nohup '$REMOTE_ROOT/bin/vpp' plugin_path '$REMOTE_ROOT/plugins' -c '$REMOTE_ROOT/runtime/startup.conf' >'$REMOTE_ROOT/logs/vpp-stdout.log' 2>&1 < /dev/null & echo \$! > '$REMOTE_ROOT/runtime/vpp.pid'"
  sleep 3
  vppctl_cmd 'show version' >/dev/null
  vpp_running=1
}

capture_residue() {
  local label="$1" dir="$RESULT_DIR/$1"
  mkdir -p "$dir"
  adb_su 'ps -A -o USER,PID,PPID,NAME,args 2>/dev/null || ps -A 2>/dev/null' | tr -d '\r' >"$dir/processes.txt"
  adb_su '/system/bin/iptables -S 2>/dev/null || true; /system/bin/ip6tables -S 2>/dev/null || true' | tr -d '\r' >"$dir/iptables.txt"
  adb_su 'cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null || true' | tr -d '\r' >"$dir/nfnetlink_queue.txt"
}

assert_clean() {
  local pids queues hooks
  pids="$(adb_su 'pidof vpp 2>/dev/null || true' | tr -d '\r\n')"
  queues="$(adb_su 'cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null || true' | tr -d '\r' | sed '/^[[:space:]]*$/d' | wc -l)"
  hooks="$(adb_su '/system/bin/iptables -S 2>/dev/null || true; /system/bin/ip6tables -S 2>/dev/null || true' | tr -d '\r' | grep -Ec 'NFQUEUE|nfqueue_poc' || true)"
  echo "final residue: vpp_pids=${pids:-none} queue_lines=$queues nfqueue_hooks=$hooks"
  if [[ -n "$pids" || "$queues" != 0 || "$hooks" != 0 ]]; then failures=$((failures + 1)); fi
}

run_userspace_case() {
  local name="$1" family="$2" queue="$3" table="$4" proto="$5" target="$6" ping="$7"
  local dir="$RESULT_DIR/$name" rule show ping_rc
  mkdir -p "$dir"
  rule="/system/bin/$table -w -I OUTPUT 1 -p $proto -d '$target' -j NFQUEUE --queue-num $queue --queue-bypass"
  vppctl_cmd 'nfqueue-poc disable' >/dev/null 2>&1 || true
  vppctl_cmd "nfqueue-poc enable queue $queue family $family queue-maxlen 4096 mode async-lease async-delay-ms 500 event-log '$REMOTE_ROOT/logs/$name.ndjson'" >"$dir/enable.txt"
  adb_su "$rule"
  set +e
  adb_su "$ping" >"$dir/ping.txt" 2>&1
  ping_rc=$?
  set -e
  sleep 1
  vppctl_cmd 'show nfqueue-poc' | tr -d '\r' >"$dir/show.txt"
  adb_su 'cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null || true' | tr -d '\r' >"$dir/nfnetlink_queue.txt"
  adb_su "cat '$REMOTE_ROOT/logs/$name.ndjson' 2>/dev/null || true" | tr -d '\r' >"$dir/events.ndjson"
  adb_su "${rule/-I /-D }" >/dev/null 2>&1 || true
  echo "case=$name ping_rc=$ping_rc"
  cat "$dir/show.txt"
  if ! grep -Eq 'worker-backpressure [1-9]' "$dir/show.txt"; then
    echo "FAIL: $name did not exercise userspace worker backpressure" >&2
    failures=$((failures + 1))
  fi
  if grep -Eq 'verdict-errors [1-9]|pipe-errors [1-9]' "$dir/show.txt"; then
    echo "FAIL: $name verdict/pipe error" >&2
    failures=$((failures + 1))
  fi
}

run_kernel_case() {
  local name="kernel-queue-overflow-ip4" dir="$RESULT_DIR/kernel-queue-overflow-ip4"
  local rule show ping_rc
  mkdir -p "$dir"
  rule="/system/bin/iptables -w -I OUTPUT 1 -p icmp -d '$IP4_TARGET' -j NFQUEUE --queue-num 54 --queue-bypass"
  vppctl_cmd 'nfqueue-poc disable' >/dev/null 2>&1 || true
  vppctl_cmd "nfqueue-poc enable queue 54 family ip4 queue-maxlen 8 async-ingress-delay-ms 20 mode async-lease async-delay-ms 500" >"$dir/enable.txt"
  adb_su "$rule"
  set +e
  adb_su "i=0; while [ \$i -lt 128 ]; do /system/bin/ping -c 1 -W 1 '$IP4_TARGET' >/dev/null 2>&1 & i=\$((i + 1)); done; wait" >"$dir/ping.txt" 2>&1
  ping_rc=$?
  set -e
  sleep 1
  show="$(vppctl_cmd 'show nfqueue-poc' | tr -d '\r')"
  printf '%s\n' "$show" >"$dir/show.txt"
  adb_su 'cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null || true' | tr -d '\r' >"$dir/nfnetlink_queue.txt"
  adb_su "${rule/-I /-D }" >/dev/null 2>&1 || true
  echo "case=$name ping_rc=$ping_rc"
  printf '%s\n' "$show"
  # ENOBUFS is the direct socket-level kernel overflow signal. A lower seen
  # count with queue-maxlen 8 is retained as supporting evidence, but is not
  # mislabeled as ENOBUFS when the kernel does not report it.
  if grep -Eq 'enobufs [1-9]' "$dir/show.txt"; then
    echo 'kernel_queue_overflow_policy=enobufs'
  else
    echo 'kernel_queue_overflow_policy=not-reproduced-enobufs-zero'
  fi
  if grep -Eq 'verdict-errors [1-9]|pipe-errors [1-9]' "$dir/show.txt"; then failures=$((failures + 1)); fi
}

run_listener_missing_case() {
  local dir="$RESULT_DIR/listener-missing" rule
  mkdir -p "$dir"
  rule="/system/bin/iptables -w -I OUTPUT 1 -p icmp -d '$IP4_TARGET' -j NFQUEUE --queue-num 54 --queue-bypass"
  vppctl_cmd 'nfqueue-poc disable' >/dev/null 2>&1 || true
  adb_su "$rule"
  set +e
  adb_su "/system/bin/ping -c 4 -W 1 '$IP4_TARGET'" >"$dir/ping.txt" 2>&1
  local rc=$?
  set -e
  adb_su 'cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null || true' | tr -d '\r' >"$dir/nfnetlink_queue.txt"
  adb_su "${rule/-I /-D }" >/dev/null 2>&1 || true
  printf 'listener_missing_policy=queue-bypass\nping_rc=%s\n' "$rc" >"$dir/policy.txt"
  echo "case=listener-missing ping_rc=$rc queue_listener_lines=$(sed '/^[[:space:]]*$/d' "$dir/nfnetlink_queue.txt" | wc -l)"
  if [[ "$rc" != 0 ]]; then failures=$((failures + 1)); fi
}

cleanup() {
  local rc=$?
  remove_rules || true
  stop_vpp || true
  capture_residue final || true
  assert_clean || true
  if [[ "$failures" != 0 && "$rc" == 0 ]]; then rc=1; fi
  return "$rc"
}
trap cleanup EXIT

echo '# SAKAMOTO-39 Android NFQUEUE congestion POC'
echo "run_id=$RUN_ID"
echo "adb_serial=$(resolve_adb_serial)"
device_preflight
remove_rules
if [[ "${SKIP_BUILD:-0}" != 1 ]]; then
  PYTHONPATH=/tmp/sakamoto-vpp-build-deps TARGET=nfqueue_poc_plugin JOBS=4 "$POC_DIR/scripts/android-build-vpp-probe.sh"
  VPP_DIR="$VPP_WORK_ROOT/vpp" OVERLAY_DIR="$POC_DIR/overlay" "$POC_DIR/scripts/apply-vpp-overlay.sh"
  PYTHONPATH=/tmp/sakamoto-vpp-build-deps TARGET=nfqueue_poc_plugin JOBS=4 "$POC_DIR/scripts/android-build-vpp-probe.sh"
  BUILD_DIR="$BUILD_DIR" STAGE_DIR="$STAGE_DIR" "$POC_DIR/scripts/android-stage-vpp-core.sh"
fi
BUILD_DIR="$BUILD_DIR" STAGE_DIR="$STAGE_DIR" REMOTE_ROOT="$REMOTE_ROOT" "$POC_DIR/scripts/android-push-vpp-core.sh"
start_vpp
run_userspace_case userspace-backpressure-ip4 ip4 54 iptables icmp "$IP4_TARGET" "i=0; while [ \$i -lt 128 ]; do /system/bin/ping -c 1 -W 1 '$IP4_TARGET' >/dev/null 2>&1 & i=\$((i + 1)); done; wait"
run_userspace_case userspace-backpressure-ip6 ip6 55 ip6tables ipv6-icmp "$IP6_TARGET" "i=0; while [ \$i -lt 128 ]; do /system/bin/ping6 -c 1 -W 1 '$IP6_TARGET' >/dev/null 2>&1 & i=\$((i + 1)); done; wait"
run_kernel_case
run_listener_missing_case
echo "failures=$failures"
[[ "$failures" == 0 ]]
