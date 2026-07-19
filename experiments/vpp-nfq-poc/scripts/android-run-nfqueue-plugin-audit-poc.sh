#!/usr/bin/env bash
set -euo pipefail

# Android-only audit of the current experimental nfqueue_poc VPP plugin.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd -- "$POC_DIR/../.." && pwd)"
VPP_WORK_ROOT="${VPP_WORK_ROOT:-$POC_DIR/work}"
BUILD_DIR="${BUILD_DIR:-$VPP_WORK_ROOT/vpp-android-release-no-multiarch-no-ipsec-idle}"
STAGE_DIR="${STAGE_DIR:-$VPP_WORK_ROOT/android-vpp-release-no-multiarch-no-ipsec-idle-stage}"
REMOTE_ROOT="${REMOTE_ROOT:-/data/local/tmp/vpp-nfq-poc}"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
RESULT_DIR="$POC_DIR/results/sakamoto-32-nfqueue-plugin-audit-$RUN_ID"
RUN_LOG="$RESULT_DIR/run.log"
IP4_TARGET="${IP4_TARGET:-1.1.1.1}"
IP6_TARGET="${IP6_TARGET:-2606:4700:4700::1111}"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$RESULT_DIR"
exec > >(tee "$RUN_LOG") 2>&1

failures=0
battery_unplugged=0
vpp_running=0

vppctl_cmd() {
  adb_su "LD_LIBRARY_PATH='$REMOTE_ROOT/lib' '$REMOTE_ROOT/bin/vppctl' -s '$REMOTE_ROOT/runtime/cli.sock' $1"
}

device_stop_vpp() {
  vppctl_cmd "nfqueue-poc disable" >/dev/null 2>&1 || true
  adb_su "if [ -f '$REMOTE_ROOT/runtime/vpp.pid' ]; then kill -TERM \$(cat '$REMOTE_ROOT/runtime/vpp.pid') 2>/dev/null || true; sleep 1; kill -KILL \$(cat '$REMOTE_ROOT/runtime/vpp.pid') 2>/dev/null || true; fi; for p in \$(pidof vpp 2>/dev/null || true); do kill -TERM \$p 2>/dev/null || true; done; sleep 1; rm -f '$REMOTE_ROOT/runtime/vpp.pid' '$REMOTE_ROOT/runtime/cli.sock' '$REMOTE_ROOT/runtime/statseg.sock'"
  vpp_running=0
}

remove_rules() {
  while adb_su "/system/bin/iptables -w -D OUTPUT -p icmp -d '$IP4_TARGET' -j NFQUEUE --queue-num 42 --queue-bypass 2>/dev/null" >/dev/null 2>&1; do :; done
  while adb_su "/system/bin/iptables -w -D INPUT -p icmp -s '$IP4_TARGET' -j NFQUEUE --queue-num 42 --queue-bypass 2>/dev/null" >/dev/null 2>&1; do :; done
  while adb_su "/system/bin/ip6tables -w -D OUTPUT -p ipv6-icmp -d '$IP6_TARGET' -j NFQUEUE --queue-num 43 --queue-bypass 2>/dev/null" >/dev/null 2>&1; do :; done
  while adb_su "/system/bin/ip6tables -w -D INPUT -p ipv6-icmp -s '$IP6_TARGET' -j NFQUEUE --queue-num 43 --queue-bypass 2>/dev/null" >/dev/null 2>&1; do :; done
}

capture_device_state() {
  local name="$1"
  local dir="$RESULT_DIR/$name"
  mkdir -p "$dir"
  adb_su 'ps -A -o USER,PID,PPID,NAME,args 2>/dev/null || ps -A 2>/dev/null' | tr -d '\r' >"$dir/processes.txt"
  adb_su '/system/bin/iptables -S 2>/dev/null || true; /system/bin/ip6tables -S 2>/dev/null || true' | tr -d '\r' >"$dir/iptables.txt"
  adb_su 'cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null || true' | tr -d '\r' >"$dir/nfnetlink_queue.txt"
  adb_su "cat '$REMOTE_ROOT/logs/vpp.log' 2>/dev/null || true" | tr -d '\r' >"$dir/vpp.log"
}

assert_no_residue() {
  local label="$1"
  local pids
  local queue_lines
  local hook_lines
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
  adb_su "rm -rf '$REMOTE_ROOT/runtime/cli.sock' '$REMOTE_ROOT/runtime/statseg.sock' '$REMOTE_ROOT/logs/vpp.log' '$REMOTE_ROOT/logs/vpp-stdout.log'; mkdir -p '$REMOTE_ROOT/runtime' '$REMOTE_ROOT/logs'; cd '$REMOTE_ROOT' && export LD_LIBRARY_PATH='$REMOTE_ROOT/lib'; nohup '$REMOTE_ROOT/bin/vpp' plugin_path '$REMOTE_ROOT/plugins' -c '$REMOTE_ROOT/runtime/startup.conf' >'$REMOTE_ROOT/logs/vpp-stdout.log' 2>&1 < /dev/null & echo \$! > '$REMOTE_ROOT/runtime/vpp.pid'"
  sleep 3
  if ! vppctl_cmd 'show version' >/dev/null 2>&1; then
    echo "FAIL: VPP CLI did not become ready" >&2
    adb_su "cat '$REMOTE_ROOT/logs/vpp-stdout.log' 2>/dev/null || true" | tr -d '\r'
    failures=$((failures + 1))
    return 1
  fi
  vpp_running=1
}

case_stats() {
  local show="$1"
  local seen accepted dropped
  seen="$(printf '%s\n' "$show" | awk '$1 == "seen" { print $2 }' | tr -cd '0-9')"
  accepted="$(printf '%s\n' "$show" | awk '$1 == "seen" { print $4 }' | tr -cd '0-9')"
  dropped="$(printf '%s\n' "$show" | awk '$1 == "seen" { print $6 }' | tr -cd '0-9')"
  printf '%s %s %s\n' "${seen:-0}" "${accepted:-0}" "${dropped:-0}"
}

run_case() {
  local name="$1"
  local family="$2"
  local direction="$3"
  local mode="$4"
  local target="$5"
  local ping_cmd="$6"
  local expected="$7"
  local queue=42
  local table=iptables
  local protocol=icmp
  local match_direction=OUTPUT
  local match_operator=-d
  local event_arg=""
  local rule
  local delete_rule
  local ping_rc
  local ping_out
  local show
  local stats
  local seen accepted dropped
  local dir="$RESULT_DIR/$name"

  if [[ "$family" == "ip6" ]]; then
    queue=43
    table=ip6tables
    protocol=ipv6-icmp
  fi
  if [[ "$direction" == "input" ]]; then
    match_direction=INPUT
    match_operator=-s
  fi
  rule="/system/bin/$table -w -I $match_direction 1 -p $protocol $match_operator '$target' -j NFQUEUE --queue-num $queue --queue-bypass"
  delete_rule="${rule/-I /-D }"

  mkdir -p "$dir"
  echo "## case=$name family=$family direction=$direction mode=$mode"
  vppctl_cmd 'nfqueue-poc disable' >/dev/null 2>&1 || true
  if [[ "$name" == "ip4-output-accept" ]]; then
    event_arg=" event-log '$REMOTE_ROOT/logs/$name.ndjson'"
  fi
  vppctl_cmd "nfqueue-poc enable queue $queue family $family mode $mode$event_arg" >"$dir/enable.txt"
  adb_su "$rule"
  set +e
  ping_out="$(adb_su "$ping_cmd" 2>&1 | tr -d '\r')"
  ping_rc=$?
  set -e
  printf '%s\n' "$ping_out" >"$dir/ping.txt"
  show="$(vppctl_cmd 'show nfqueue-poc' | tr -d '\r')"
  printf '%s\n' "$show" >"$dir/show.txt"
  if ! printf '%s\n' "$show" | grep -q 'copy-range 512'; then
    echo "FAIL: $name did not report bounded copy-range 512" >&2
    failures=$((failures + 1))
  fi
  if [[ -n "$event_arg" ]]; then
    adb_su "cat '$REMOTE_ROOT/logs/$name.ndjson' 2>/dev/null || true" | tr -d '\r' >"$dir/events.ndjson"
  fi
  adb_su "$delete_rule" >/dev/null 2>&1 || true

  stats="$(case_stats "$show")"
  read -r seen accepted dropped <<<"$stats"
  echo "case=$name ping_rc=$ping_rc seen=$seen accepted=$accepted dropped=$dropped"
  if [[ "$expected" == "mixed" ]]; then
    if [[ "$accepted" == "0" || "$dropped" == "0" ]]; then
      echo "FAIL: $name expected both ACCEPT and DROP" >&2
      failures=$((failures + 1))
    fi
  elif [[ "$expected" == "accept" ]]; then
    if [[ "$ping_rc" != "0" || "$accepted" == "0" || "$dropped" != "0" ]]; then
      echo "FAIL: $name expected ACCEPT" >&2
      failures=$((failures + 1))
    fi
  else
    if [[ "$ping_rc" == "0" || "$dropped" == "0" || "$accepted" != "0" ]]; then
      echo "FAIL: $name expected DROP" >&2
      failures=$((failures + 1))
    fi
  fi
}

run_active_teardown() {
  local dir="$RESULT_DIR/active-teardown"
  local rule delete_rule queue_lines

  mkdir -p "$dir"
  echo "## case=active-teardown family=ip4 direction=output"
  rule="/system/bin/iptables -w -I OUTPUT 1 -p icmp -d '$IP4_TARGET' -j NFQUEUE --queue-num 42 --queue-bypass"
  delete_rule="${rule/-I /-D }"
  vppctl_cmd 'nfqueue-poc disable' >/dev/null 2>&1 || true
  vppctl_cmd 'nfqueue-poc enable queue 42 family ip4 mode accept-all' >"$dir/enable.txt"
  adb_su "$rule"
  adb_su 'cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null || true' | tr -d '\r' >"$dir/queue-before-disable.txt"
  vppctl_cmd 'nfqueue-poc disable' >"$dir/disable.txt"
  adb_su 'cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null || true' | tr -d '\r' >"$dir/queue-after-disable.txt"
  queue_lines="$(sed '/^[[:space:]]*$/d' "$dir/queue-after-disable.txt" | wc -l)"
  echo "case=active-teardown queue_lines_after_disable=$queue_lines"
  if [[ "$queue_lines" != "0" ]]; then
    echo "FAIL: active-teardown left an Android NFQUEUE queue after plugin disable" >&2
    failures=$((failures + 1))
  fi
  adb_su "$delete_rule" >/dev/null 2>&1 || true
}

sample_vpp_proc() {
  local label="$1"
  local seconds="$2"
  local dir="$RESULT_DIR/idle-profile"
  local i

  mkdir -p "$dir"
  : >"$dir/$label.txt"
  for i in $(seq 1 "$seconds"); do
    printf 'sample=%s ' "$i" >>"$dir/$label.txt"
    adb_su "pid=\$(cat '$REMOTE_ROOT/runtime/vpp.pid' 2>/dev/null || true); if [ -n \"\$pid\" ] && [ -r \"/proc/\$pid/stat\" ]; then printf 'pid=%s stat=' \"\$pid\"; cat \"/proc/\$pid/stat\"; printf 'status='; grep -E '^(VmRSS|VmSize):' \"/proc/\$pid/status\" 2>/dev/null || true; fi" | tr -d '\r' >>"$dir/$label.txt"
    sleep 1
  done
}

run_idle_profile() {
  echo "## case=idle-profile seconds=10"
  vppctl_cmd 'nfqueue-poc disable' >/dev/null 2>&1 || true
  sample_vpp_proc disabled 10
  vppctl_cmd 'nfqueue-poc enable queue 42 family ip4 mode accept-all' >"$RESULT_DIR/idle-profile/enable.txt"
  sample_vpp_proc enabled 10
  vppctl_cmd 'show nfqueue-poc' | tr -d '\r' >"$RESULT_DIR/idle-profile/show.txt"
  vppctl_cmd 'nfqueue-poc disable' >/dev/null 2>&1 || true
}

cleanup() {
  local exit_code=$?
  remove_rules || true
  device_stop_vpp || true
  capture_device_state final || true
  assert_no_residue final || true
  if [[ "$battery_unplugged" == "1" ]]; then
    adb_cmd shell dumpsys battery reset >/dev/null 2>&1 || true
    battery_unplugged=0
  fi
  if [[ "$failures" != "0" && "$exit_code" == "0" ]]; then
    exit_code=1
  fi
  return "$exit_code"
}
trap cleanup EXIT

echo "# SAKAMOTO-32 Android NFQUEUE plugin audit POC"
echo "run_id=$RUN_ID"
echo "adb_serial=$(resolve_adb_serial)"
echo "vpp_commit=$(git -C "$VPP_WORK_ROOT/vpp" rev-parse HEAD)"
echo "vpp_describe=$(git -C "$VPP_WORK_ROOT/vpp" describe --tags --always 2>/dev/null || true)"
echo "plugin_source_sha=$(sha256sum "$POC_DIR/overlay/src/plugins/nfqueue_poc/nfqueue_poc.c" | awk '{print $1}')"
echo "plugin_cmake_sha=$(sha256sum "$POC_DIR/overlay/src/plugins/nfqueue_poc/CMakeLists.txt" | awk '{print $1}')"

device_preflight
remove_rules
adb_cmd shell dumpsys battery unplug >/dev/null
battery_unplugged=1
if ! adb_cmd shell dumpsys battery | tr -d '\r' | grep -Eq 'USB powered: false|USB powered=false'; then
  echo "FAIL: USB power simulation failed" >&2
  exit 1
fi

echo "## Android cross-build and stage"
BUILD_DIR="$BUILD_DIR" TARGET=vpp "$SCRIPT_DIR/android-build-vpp-probe.sh"
BUILD_DIR="$BUILD_DIR" TARGET=vppctl "$SCRIPT_DIR/android-build-vpp-probe.sh"
BUILD_DIR="$BUILD_DIR" TARGET=nfqueue_poc_plugin "$SCRIPT_DIR/android-build-vpp-probe.sh"
BUILD_DIR="$BUILD_DIR" STAGE_DIR="$STAGE_DIR" "$SCRIPT_DIR/android-stage-vpp-core.sh"
echo "plugin_artifact_sha=$(sha256sum "$BUILD_DIR/lib/aarch64-linux-android/vpp_plugins/nfqueue_poc_plugin.so" | awk '{print $1}')"
BUILD_DIR="$BUILD_DIR" STAGE_DIR="$STAGE_DIR" "$SCRIPT_DIR/android-push-vpp-core.sh"

start_vpp
vppctl_cmd 'show version' | tr -d '\r' | tee "$RESULT_DIR/vpp-version.txt"
vppctl_cmd 'show plugins' | tr -d '\r' | tee "$RESULT_DIR/vpp-plugins.txt"
capture_device_state startup

run_case ip4-output-accept ip4 output accept-all "$IP4_TARGET" "ping -c 4 -W 2 '$IP4_TARGET'" accept
run_case ip4-output-drop ip4 output drop-all "$IP4_TARGET" "ping -c 4 -W 2 '$IP4_TARGET'" drop
run_case ip4-output-ratio ip4 output 'drop-ratio 50' "$IP4_TARGET" "ping -c 20 -W 2 '$IP4_TARGET'" mixed
run_case ip4-input-accept ip4 input accept-all "$IP4_TARGET" "ping -c 4 -W 2 '$IP4_TARGET'" accept
run_case ip4-input-drop ip4 input drop-all "$IP4_TARGET" "ping -c 4 -W 2 '$IP4_TARGET'" drop
run_active_teardown
run_idle_profile

device_stop_vpp
start_vpp
run_case ip6-output-accept ip6 output accept-all "$IP6_TARGET" "ping6 -c 4 -W 2 '$IP6_TARGET'" accept
run_case ip6-output-drop ip6 output drop-all "$IP6_TARGET" "ping6 -c 4 -W 2 '$IP6_TARGET'" drop
run_case ip6-output-ratio ip6 output 'drop-ratio 50' "$IP6_TARGET" "ping6 -c 20 -W 2 '$IP6_TARGET'" mixed
run_case ip6-input-accept ip6 input accept-all "$IP6_TARGET" "ping6 -c 4 -W 2 '$IP6_TARGET'" accept
run_case ip6-input-drop ip6 input drop-all "$IP6_TARGET" "ping6 -c 4 -W 2 '$IP6_TARGET'" drop

vppctl_cmd 'nfqueue-poc disable' >/dev/null
device_stop_vpp
remove_rules
assert_no_residue after_tests

if [[ "$failures" != "0" ]]; then
  echo "FAIL: SAKAMOTO-32 Android NFQUEUE plugin audit failures=$failures"
  echo "result_dir=$RESULT_DIR"
  exit 1
fi
echo "PASS: SAKAMOTO-32 Android NFQUEUE plugin audit baseline"
echo "result_dir=$RESULT_DIR"
