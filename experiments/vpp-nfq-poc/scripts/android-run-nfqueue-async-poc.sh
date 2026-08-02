#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-38: verify the single-lane asynchronous PacketLease contract on a
# rooted Android device.  The mode is intentionally throwaway: it exercises
# ownership, generation checks, duplicate/stale/missing completion handling,
# bounded overload, and shutdown draining before a production worker design.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd -- "$POC_DIR/../.." && pwd)"
VPP_WORK_ROOT="${VPP_WORK_ROOT:-$POC_DIR/work}"
BUILD_DIR="${BUILD_DIR:-$VPP_WORK_ROOT/vpp-android-configure-probe}"
STAGE_DIR="${STAGE_DIR:-$VPP_WORK_ROOT/android-nfq-async-stage}"
REMOTE_ROOT="${REMOTE_ROOT:-/data/local/tmp/vpp-nfq-poc-38}"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
RESULT_DIR="$POC_DIR/results/sakamoto-38-nfqueue-async-$RUN_ID"
RUN_LOG="$RESULT_DIR/run.log"
IP4_TARGET="${IP4_TARGET:-1.1.1.1}"
IP6_TARGET="${IP6_TARGET:-2606:4700:4700::1111}"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$RESULT_DIR"
exec > >(tee "$RUN_LOG") 2>&1

failures=0
vpp_running=0

vppctl_cmd() {
  adb_su "LD_LIBRARY_PATH='$REMOTE_ROOT/lib' '$REMOTE_ROOT/bin/vppctl' -s '$REMOTE_ROOT/runtime/cli.sock' $1"
}

remove_rules() {
  while adb_su "/system/bin/iptables -w -D OUTPUT -p icmp -d '$IP4_TARGET' -j NFQUEUE --queue-num 52 --queue-bypass 2>/dev/null" >/dev/null 2>&1; do :; done
  while adb_su "/system/bin/ip6tables -w -D OUTPUT -p ipv6-icmp -d '$IP6_TARGET' -j NFQUEUE --queue-num 53 --queue-bypass 2>/dev/null" >/dev/null 2>&1; do :; done
}

device_stop_vpp() {
  vppctl_cmd "nfqueue-poc disable" >/dev/null 2>&1 || true
  adb_su "if [ -f '$REMOTE_ROOT/runtime/vpp.pid' ]; then kill -TERM \$(cat '$REMOTE_ROOT/runtime/vpp.pid') 2>/dev/null || true; sleep 1; kill -KILL \$(cat '$REMOTE_ROOT/runtime/vpp.pid') 2>/dev/null || true; fi; for p in \$(pidof vpp 2>/dev/null || true); do kill -TERM \$p 2>/dev/null || true; done; sleep 1; rm -f '$REMOTE_ROOT/runtime/vpp.pid' '$REMOTE_ROOT/runtime/cli.sock' '$REMOTE_ROOT/runtime/statseg.sock'"
  vpp_running=0
}

capture_residue() {
  local label="$1"
  local dir="$RESULT_DIR/$label"
  mkdir -p "$dir"
  adb_su 'ps -A -o USER,PID,PPID,NAME,args 2>/dev/null || ps -A 2>/dev/null' | tr -d '\r' >"$dir/processes.txt"
  adb_su '/system/bin/iptables -S 2>/dev/null || true; /system/bin/ip6tables -S 2>/dev/null || true' | tr -d '\r' >"$dir/iptables.txt"
  adb_su 'cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null || true' | tr -d '\r' >"$dir/nfnetlink_queue.txt"
  adb_su "cat '$REMOTE_ROOT/logs/vpp-stdout.log' 2>/dev/null || true" | tr -d '\r' >"$dir/vpp-stdout.log"
}

assert_no_residue() {
  local label="$1"
  local pids queue_lines hook_lines
  pids="$(adb_su 'pidof vpp 2>/dev/null || true' | tr -d '\r\n')"
  queue_lines="$(adb_su 'cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null || true' | tr -d '\r' | sed '/^[[:space:]]*$/d' | wc -l)"
  hook_lines="$(adb_su '/system/bin/iptables -S 2>/dev/null || true; /system/bin/ip6tables -S 2>/dev/null || true' | tr -d '\r' | grep -Ec 'NFQUEUE|nfqueue_poc' || true)"
  echo "$label residue: vpp_pids=${pids:-none} queue_lines=$queue_lines nfqueue_hooks=$hook_lines"
  if [[ -n "$pids" || "$queue_lines" != "0" || "$hook_lines" != "0" ]]; then
    echo "FAIL: $label left Android NFQUEUE/VPP residue" >&2
    failures=$((failures + 1))
  fi
}

start_vpp() {
  device_stop_vpp
  adb_su "rm -rf '$REMOTE_ROOT/runtime/cli.sock' '$REMOTE_ROOT/runtime/statseg.sock' '$REMOTE_ROOT/logs/vpp-stdout.log'; mkdir -p '$REMOTE_ROOT/runtime' '$REMOTE_ROOT/logs'; cd '$REMOTE_ROOT' && export LD_LIBRARY_PATH='$REMOTE_ROOT/lib'; nohup '$REMOTE_ROOT/bin/vpp' plugin_path '$REMOTE_ROOT/plugins' -c '$REMOTE_ROOT/runtime/startup.conf' >'$REMOTE_ROOT/logs/vpp-stdout.log' 2>&1 < /dev/null & echo \$! > '$REMOTE_ROOT/runtime/vpp.pid'"
  sleep 3
  if ! vppctl_cmd 'show version' >/dev/null 2>&1; then
    echo "FAIL: VPP CLI did not become ready" >&2
    adb_su "cat '$REMOTE_ROOT/logs/vpp-stdout.log' 2>/dev/null || true" | tr -d '\r'
    failures=$((failures + 1))
    return 1
  fi
  vpp_running=1
}

run_fault_case() {
  local name="$1" family="$2" queue="$3" table="$4" protocol="$5" target="$6" ping_cmd="$7"
  local dir="$RESULT_DIR/$name" show ping_out ping_rc rule
  mkdir -p "$dir"
  echo "## case=$name family=$family"
  vppctl_cmd 'nfqueue-poc disable' >/dev/null 2>&1 || true
  vppctl_cmd "nfqueue-poc enable queue $queue family $family mode async-lease async-duplicate async-stale async-missing async-missing-id async-delay-ms 5 event-log '$REMOTE_ROOT/logs/$name.ndjson'" >"$dir/enable.txt"
  rule="/system/bin/$table -w -I OUTPUT 1 -p $protocol -d '$target' -j NFQUEUE --queue-num $queue --queue-bypass"
  adb_su "$rule"
  set +e
  ping_out="$(adb_su "$ping_cmd" 2>&1 | tr -d '\r')"
  ping_rc=$?
  set -e
  printf '%s\n' "$ping_out" >"$dir/ping.txt"
  sleep 1
  show="$(vppctl_cmd 'show nfqueue-poc' | tr -d '\r')"
  printf '%s\n' "$show" >"$dir/show.txt"
  adb_su "cat '$REMOTE_ROOT/logs/$name.ndjson' 2>/dev/null || true" | tr -d '\r' >"$dir/events.ndjson"
  adb_su "${rule/-I /-D }" >/dev/null 2>&1 || true
  echo "case=$name ping_rc=$ping_rc"
  printf '%s\n' "$show"
  if ! printf '%s\n' "$show" | grep -q 'mode async-lease'; then
    echo "FAIL: $name did not enter async-lease mode" >&2
    failures=$((failures + 1))
  fi
  if ! printf '%s\n' "$show" | grep -Eq 'async leases ingress [1-9]'; then
    echo "FAIL: $name did not observe async ingress" >&2
    failures=$((failures + 1))
  fi
  if ! printf '%s\n' "$show" | grep -Eq 'async faults .*duplicate [1-9].*stale [1-9].*missing [1-9].*missing-id [1-9].*deadline [1-9]'; then
    echo "FAIL: $name did not observe all completion fault classes" >&2
    failures=$((failures + 1))
  fi
  if printf '%s\n' "$show" | grep -Eq 'verdict-errors [1-9]|pipe-errors [1-9]'; then
    echo "FAIL: $name reported verdict/pipe errors" >&2
    failures=$((failures + 1))
  fi
}

run_shutdown_case() {
  local name="shutdown-drain-ip4" dir="$RESULT_DIR/shutdown-drain-ip4"
  local rule show ping_pid
  mkdir -p "$dir"
  echo "## case=$name family=ip4"
  vppctl_cmd 'nfqueue-poc disable' >/dev/null 2>&1 || true
  vppctl_cmd "nfqueue-poc enable queue 52 family ip4 mode async-lease async-shutdown async-delay-ms 200" >"$dir/enable.txt"
  rule="/system/bin/iptables -w -I OUTPUT 1 -p icmp -d '$IP4_TARGET' -j NFQUEUE --queue-num 52 --queue-bypass"
  adb_su "$rule"
  adb_su "/system/bin/ping -c 16 -W 1 '$IP4_TARGET' > '$REMOTE_ROOT/logs/shutdown-drain-ip4-ping.txt' 2>&1 & echo \$!"
  sleep 0.15
  vppctl_cmd 'nfqueue-poc disable' >"$dir/disable.txt"
  show="$(vppctl_cmd 'show nfqueue-poc' | tr -d '\r')"
  printf '%s\n' "$show" >"$dir/show-after-disable.txt"
  adb_su "${rule/-I /-D }" >/dev/null 2>&1 || true
  adb_su "cat '$REMOTE_ROOT/logs/shutdown-drain-ip4-ping.txt' 2>/dev/null || true" | tr -d '\r' >"$dir/ping.txt"
  echo "case=$name"
  printf '%s\n' "$show"
  if ! printf '%s\n' "$show" | grep -Eq 'shutdown [1-9]'; then
    echo "FAIL: shutdown case did not drain a pending lease" >&2
    failures=$((failures + 1))
  fi
  if printf '%s\n' "$show" | grep -Eq 'verdict-errors [1-9]|pipe-errors [1-9]'; then
    echo "FAIL: shutdown case reported verdict/pipe errors" >&2
    failures=$((failures + 1))
  fi
}

cleanup() {
  local exit_code=$?
  remove_rules || true
  device_stop_vpp || true
  capture_residue final || true
  assert_no_residue final || true
  if [[ "$failures" != "0" && "$exit_code" == "0" ]]; then
    exit_code=1
  fi
  return "$exit_code"
}
trap cleanup EXIT

echo "# SAKAMOTO-38 Android NFQUEUE async PacketLease POC"
echo "run_id=$RUN_ID"
echo "adb_serial=$(resolve_adb_serial)"
echo "vpp_commit=$(git -C "$VPP_WORK_ROOT/vpp" rev-parse HEAD)"

device_preflight
remove_rules
PYTHONPATH=/tmp/sakamoto-vpp-build-deps TARGET=nfqueue_poc_plugin JOBS=4 \
  "$POC_DIR/scripts/android-build-vpp-probe.sh"
VPP_DIR="$VPP_WORK_ROOT/vpp" OVERLAY_DIR="$POC_DIR/overlay" \
  "$POC_DIR/scripts/apply-vpp-overlay.sh"
PYTHONPATH=/tmp/sakamoto-vpp-build-deps TARGET=nfqueue_poc_plugin JOBS=4 \
  "$POC_DIR/scripts/android-build-vpp-probe.sh"
BUILD_DIR="$BUILD_DIR" STAGE_DIR="$STAGE_DIR" \
  "$POC_DIR/scripts/android-stage-vpp-core.sh"
BUILD_DIR="$BUILD_DIR" STAGE_DIR="$STAGE_DIR" REMOTE_ROOT="$REMOTE_ROOT" \
  "$POC_DIR/scripts/android-push-vpp-core.sh"

start_vpp
run_fault_case "faults-ip4" ip4 52 iptables icmp "$IP4_TARGET" "/system/bin/ping -c 16 -W 1 '$IP4_TARGET'"
run_fault_case "faults-ip6" ip6 53 ip6tables ipv6-icmp "$IP6_TARGET" "/system/bin/ping6 -c 16 -W 1 '$IP6_TARGET'"
run_shutdown_case

echo "failures=$failures"
[[ "$failures" == "0" ]]
