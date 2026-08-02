#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-40: two independent NFQUEUE sockets with a shared canonical owner
# selector. This is deliberately a narrow lane/owner POC, not production code.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd -- "$POC_DIR/../.." && pwd)"
VPP_WORK_ROOT="${VPP_WORK_ROOT:-$POC_DIR/work}"
BUILD_DIR="${BUILD_DIR:-$VPP_WORK_ROOT/vpp-android-configure-probe}"
STAGE_DIR="${STAGE_DIR:-$VPP_WORK_ROOT/android-nfq-two-lane-stage}"
REMOTE_ROOT="${REMOTE_ROOT:-/data/local/tmp/vpp-nfq-poc-40}"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
RESULT_DIR="$POC_DIR/results/sakamoto-40-nfqueue-two-lane-$RUN_ID"
RUN_LOG="$RESULT_DIR/run.log"
IP4_A="${IP4_A:-192.168.4.1}"
IP4_B="${IP4_B:-192.168.4.2}"
IP6_A="${IP6_A:-::1}"
IP6_B="${IP6_B:-::2}"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"
mkdir -p "$RESULT_DIR"
exec > >(tee "$RUN_LOG") 2>&1
failures=0

vppctl_cmd() {
  adb_su "LD_LIBRARY_PATH='$REMOTE_ROOT/lib' '$REMOTE_ROOT/bin/vppctl' -s '$REMOTE_ROOT/runtime/cli.sock' $1"
}

stop_vpp() {
  vppctl_cmd 'nfqueue-poc disable' >/dev/null 2>&1 || true
  adb_su "if [ -f '$REMOTE_ROOT/runtime/vpp.pid' ]; then kill -TERM \$(cat '$REMOTE_ROOT/runtime/vpp.pid') 2>/dev/null || true; sleep 1; kill -KILL \$(cat '$REMOTE_ROOT/runtime/vpp.pid') 2>/dev/null || true; fi; for p in \$(pidof vpp 2>/dev/null || true); do kill -TERM \$p 2>/dev/null || true; done; sleep 1; rm -f '$REMOTE_ROOT/runtime/vpp.pid' '$REMOTE_ROOT/runtime/cli.sock' '$REMOTE_ROOT/runtime/statseg.sock'"
}

remove_rules() {
  for r in \
    "/system/bin/iptables -w -D OUTPUT -p icmp -d '$IP4_A' -j NFQUEUE --queue-num 56 --queue-bypass" \
    "/system/bin/iptables -w -D OUTPUT -p icmp -d '$IP4_B' -j NFQUEUE --queue-num 57 --queue-bypass" \
    "/system/bin/ip6tables -w -D OUTPUT -p ipv6-icmp -d '$IP6_A' -j NFQUEUE --queue-num 58 --queue-bypass" \
    "/system/bin/ip6tables -w -D OUTPUT -p ipv6-icmp -d '$IP6_B' -j NFQUEUE --queue-num 59 --queue-bypass"; do
    while adb_su "$r 2>/dev/null" >/dev/null 2>&1; do :; done
  done
}

start_vpp() {
  stop_vpp
  adb_su "rm -rf '$REMOTE_ROOT/runtime/cli.sock' '$REMOTE_ROOT/runtime/statseg.sock' '$REMOTE_ROOT/logs/vpp-stdout.log'; mkdir -p '$REMOTE_ROOT/runtime' '$REMOTE_ROOT/logs'; cd '$REMOTE_ROOT' && export LD_LIBRARY_PATH='$REMOTE_ROOT/lib'; nohup '$REMOTE_ROOT/bin/vpp' plugin_path '$REMOTE_ROOT/plugins' -c '$REMOTE_ROOT/runtime/startup.conf' >'$REMOTE_ROOT/logs/vpp-stdout.log' 2>&1 < /dev/null & echo \$! > '$REMOTE_ROOT/runtime/vpp.pid'"
  sleep 3
  vppctl_cmd 'show version' >/dev/null
}

capture_case() {
  local name="$1" dir="$RESULT_DIR/$1"
  mkdir -p "$dir"
  vppctl_cmd 'show nfqueue-poc' | tr -d '\r' >"$dir/show.txt"
  adb_su 'cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null || true' | tr -d '\r' >"$dir/nfnetlink_queue.txt"
  cat "$dir/show.txt"
  if ! grep -Eq 'mode two-lane' "$dir/show.txt"; then failures=$((failures + 1)); fi
  if grep -Eq 'verdict-errors [1-9]' "$dir/show.txt"; then failures=$((failures + 1)); fi
  if ! grep -Eq 'two-lane lane0 seen [1-9].*lane1 seen [1-9]' "$dir/show.txt"; then failures=$((failures + 1)); fi
  if ! grep -Eq 'stale-completions [1-9]' "$dir/show.txt"; then failures=$((failures + 1)); fi
}

run_family() {
  local family="$1" table="$2" proto="$3" qbase="$4" a="$5" b="$6" ping_bin="$7"
  local name="two-lane-$family" dir="$RESULT_DIR/two-lane-$family" r1 r2
  mkdir -p "$dir"
  vppctl_cmd 'nfqueue-poc disable' >/dev/null 2>&1 || true
  vppctl_cmd "nfqueue-poc enable queue $qbase family $family mode two-lane two-lane-stale" >"$dir/enable.txt"
  if [[ "$family" == ip4 ]]; then
    r1="/system/bin/$table -w -I OUTPUT 1 -p $proto -d '$a' -j NFQUEUE --queue-num $qbase --queue-bypass"
    r2="/system/bin/$table -w -I OUTPUT 1 -p $proto -d '$b' -j NFQUEUE --queue-num $((qbase + 1)) --queue-bypass"
  else
    r1="/system/bin/$table -w -I OUTPUT 1 -p $proto -d '$a' -j NFQUEUE --queue-num $qbase --queue-bypass"
    r2="/system/bin/$table -w -I OUTPUT 1 -p $proto -d '$b' -j NFQUEUE --queue-num $((qbase + 1)) --queue-bypass"
  fi
  adb_su "$r1"; adb_su "$r2"
  adb_su "i=0; while [ \$i -lt 32 ]; do $ping_bin -c 1 -W 1 '$a' >/dev/null 2>&1 & $ping_bin -c 1 -W 1 '$b' >/dev/null 2>&1 & i=\$((i + 1)); done; wait" >"$dir/probes.txt" 2>&1 || true
  sleep 1
  capture_case "$name"
  adb_su "${r1/-I /-D }" >/dev/null 2>&1 || true
  adb_su "${r2/-I /-D }" >/dev/null 2>&1 || true
}

cleanup() {
  local rc=$?
  remove_rules || true
  stop_vpp || true
  local pids queues hooks
  pids="$(adb_su 'pidof vpp 2>/dev/null || true' | tr -d '\r\n')"
  queues="$(adb_su 'cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null || true' | tr -d '\r' | sed '/^[[:space:]]*$/d' | wc -l)"
  hooks="$(adb_su '/system/bin/iptables -S 2>/dev/null || true; /system/bin/ip6tables -S 2>/dev/null || true' | tr -d '\r' | grep -Ec 'NFQUEUE|nfqueue_poc' || true)"
  echo "final residue: vpp_pids=${pids:-none} queue_lines=$queues nfqueue_hooks=$hooks"
  if [[ -n "$pids" || "$queues" != 0 || "$hooks" != 0 ]]; then failures=$((failures + 1)); fi
  if [[ "$failures" != 0 && "$rc" == 0 ]]; then rc=1; fi
  return "$rc"
}
trap cleanup EXIT

echo '# SAKAMOTO-40 Android NFQUEUE two-lane POC'
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
run_family ip4 iptables icmp 56 "$IP4_A" "$IP4_B" /system/bin/ping
run_family ip6 ip6tables ipv6-icmp 58 "$IP6_A" "$IP6_B" /system/bin/ping6
echo "failures=$failures"
[[ "$failures" == 0 ]]
