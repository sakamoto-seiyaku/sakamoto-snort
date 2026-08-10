#!/usr/bin/env bash
set -Eeuo pipefail

# SAKAMOTO-80 Android acceptance runner.
#
# This runner owns a disposable VPP process, four real NFQUEUE hooks, the
# traffic that exercises both IP families, and the raw evidence directory. It
# deliberately keeps host/netns evidence and Android evidence separate: a
# host PASS never masks an Android FAIL or PARTIAL result.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd -- "$POC_DIR/../.." && pwd)"
STAGE_SCRIPT="$SCRIPT_DIR/android-stage-nfqueue-live-s80.sh"
VPP_WORK_ROOT="${VPP_WORK_ROOT:-$POC_DIR/work}"
STAGE_DIR="${STAGE_DIR:-$VPP_WORK_ROOT/android-s80-live-stage}"
REMOTE_ROOT="${REMOTE_ROOT:-/data/local/tmp/vpp-nfq-s80}"
QUEUE_BASE="${QUEUE_BASE:-120}"
IP4_TARGET="${IP4_TARGET:-1.1.1.1}"
IP6_TARGET="${IP6_TARGET:-2606:4700:4700::1111}"
PING_COUNT="${PING_COUNT:-4}"
PING_TIMEOUT="${PING_TIMEOUT:-2}"
S80_BUILD="${S80_BUILD:-0}"
S80_STAGE="${S80_STAGE:-1}"
S80_PUSH="${S80_PUSH:-1}"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
RESULT_DIR="${RESULT_DIR:-$POC_DIR/results/sakamoto-80-android-live-$RUN_ID}"

# Force every device operation through the repository wrapper.  The shared
# helper is retained for its root/serial handling, but it will select this
# exact path because ADB is set before it is sourced.
export ADB="$REPO_ROOT/dev/adb"
source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$RESULT_DIR"
exec > >(tee "$RESULT_DIR/run.log") 2>&1

CURRENT_CASE="bootstrap"
CASE_DIR="$RESULT_DIR/$CURRENT_CASE"
CURRENT_PID=""
CASE_FAILED=0
MATRIX_FILE="$RESULT_DIR/matrix.tsv"

mkdir -p "$CASE_DIR"
printf 'case\tstatus\tresult_dir\tdevice\tqueue_base\tartifacts\n' >"$MATRIX_FILE"

echo "# SAKAMOTO-80 Android live-buffer acceptance"
echo "ticket=SAKAMOTO-80"
echo "repo_root=$REPO_ROOT"
echo "runner=$SCRIPT_DIR/$(basename "$0")"
echo "adb_wrapper=$REPO_ROOT/dev/adb"
echo "stage_dir=$STAGE_DIR"
echo "remote_root=$REMOTE_ROOT"
echo "queue_base=$QUEUE_BASE"
echo "ip4_target=$IP4_TARGET"
echo "ip6_target=$IP6_TARGET"
echo "ping_count=$PING_COUNT"
echo "result_dir=$RESULT_DIR"

device_capture() {
  local label="$1"
  local command="$2"
  local output="$CASE_DIR/$label.txt"
  echo
  echo "## device[$CURRENT_CASE] $label"
  echo "adb-shell-command=$command"
  set +e
  adb_su "$command" 2>&1 | tr -d '\r' | tee "$output"
  local rc=${PIPESTATUS[0]}
  set -e
  echo "command_rc=$rc" | tee -a "$output"
  return "$rc"
}

host_capture() {
  local label="$1"
  shift
  local output="$CASE_DIR/$label.txt"
  echo
  echo "## host[$CURRENT_CASE] $label"
  echo "command=$*"
  set +e
  "$@" 2>&1 | tee "$output"
  local rc=${PIPESTATUS[0]}
  set -e
  echo "command_rc=$rc" | tee -a "$output"
  return "$rc"
}

vppctl_cmd() {
  local command="$1"
  adb_su "LD_LIBRARY_PATH='$REMOTE_ROOT/lib' '$REMOTE_ROOT/bin/vppctl' -s '$REMOTE_ROOT/runtime/cli.sock' $command"
}

vppctl_capture() {
  local label="$1"
  local command="$2"
  local output="$CASE_DIR/$label.txt"
  echo
  echo "## vppctl[$CURRENT_CASE] $label"
  echo "vppctl-command=$command"
  set +e
  vppctl_cmd "$command" 2>&1 | tr -d '\r' | tee "$output"
  local rc=${PIPESTATUS[0]}
  set -e
  echo "command_rc=$rc" | tee -a "$output"
  return "$rc"
}

run_maybe() {
  local description="$1"
  shift
  if "$@"; then
    return 0
  fi
  echo "S80 step failed: $description"
  CASE_FAILED=1
  return 0
}

remove_hooks() {
  while adb_su "/system/bin/iptables -w -D OUTPUT -p icmp -d '$IP4_TARGET' -j NFQUEUE --queue-num '$QUEUE_BASE' --queue-bypass 2>/dev/null" >/dev/null 2>&1; do :; done
  while adb_su "/system/bin/iptables -w -D INPUT -p icmp -s '$IP4_TARGET' -j NFQUEUE --queue-num '$((QUEUE_BASE + 1))' --queue-bypass 2>/dev/null" >/dev/null 2>&1; do :; done
  while adb_su "/system/bin/ip6tables -w -D OUTPUT -p ipv6-icmp -d '$IP6_TARGET' -j NFQUEUE --queue-num '$((QUEUE_BASE + 2))' --queue-bypass 2>/dev/null" >/dev/null 2>&1; do :; done
  while adb_su "/system/bin/ip6tables -w -D INPUT -p ipv6-icmp -s '$IP6_TARGET' -j NFQUEUE --queue-num '$((QUEUE_BASE + 3))' --queue-bypass 2>/dev/null" >/dev/null 2>&1; do :; done
}

capture_residue() {
  device_capture residue-vpp-pids 'pidof vpp 2>/dev/null || true' || true
  device_capture residue-nfnetlink-queue 'cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null || true' || true
  device_capture residue-firewall '/system/bin/iptables -S 2>/dev/null || true; /system/bin/ip6tables -S 2>/dev/null || true' || true
  device_capture residue-sockets "ls -la '$REMOTE_ROOT/runtime' 2>/dev/null || true; find '$REMOTE_ROOT' -maxdepth 2 -type s -print 2>/dev/null || true" || true
}

residue_summary() {
  local pids queue_lines hooks
  pids="$(adb_su 'pidof vpp 2>/dev/null || true' | tr -d '\r\n')"
  queue_lines="$(adb_su 'cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null || true' | tr -d '\r' | sed '/^[[:space:]]*$/d' | wc -l)"
  hooks="$(adb_su '/system/bin/iptables -S 2>/dev/null || true; /system/bin/ip6tables -S 2>/dev/null || true' | tr -d '\r' | grep -Ec 'NFQUEUE' || true)"
  echo "residue-summary vpp_pids=${pids:-none} queue_lines=$queue_lines nfqueue_hooks=$hooks"
  [[ -z "$pids" && "$queue_lines" = 0 && "$hooks" = 0 ]]
}

capture_remote_logs() {
  device_capture remote-vpp-stdout "cat '$REMOTE_ROOT/logs/vpp-stdout.log' 2>/dev/null || true" || true
  device_capture remote-vpp-log "cat '$REMOTE_ROOT/logs/vpp.log' 2>/dev/null || true" || true
}

stop_vpp() {
  vppctl_cmd 'nfqueue-live-poc disable' >/dev/null 2>&1 || true
  local pid
  pid="$(adb_su "cat '$REMOTE_ROOT/runtime/vpp.pid' 2>/dev/null || true" | tr -d '\r\n')"
  if [[ "$pid" =~ ^[0-9]+$ ]]; then
    adb_su "kill -TERM '$pid' 2>/dev/null || true; sleep 1; kill -KILL '$pid' 2>/dev/null || true" >/dev/null 2>&1 || true
  fi
  sleep 1
  capture_remote_logs
  adb_su "rm -f '$REMOTE_ROOT/runtime/vpp.pid' '$REMOTE_ROOT/runtime/cli.sock' '$REMOTE_ROOT/runtime/api.sock' '$REMOTE_ROOT/runtime/statseg.sock'; rm -rf '$REMOTE_ROOT/shm'" >/dev/null 2>&1 || true
  CURRENT_PID=""
}

kill_vpp_for_process_case() {
  local pid
  pid="$(adb_su "cat '$REMOTE_ROOT/runtime/vpp.pid' 2>/dev/null || true" | tr -d '\r\n')"
  echo "process-death-pid=$pid"
  if [[ "$pid" =~ ^[0-9]+$ ]]; then
    adb_su "kill -KILL '$pid' 2>/dev/null || true" >/dev/null 2>&1 || true
  fi
  sleep 1
  CURRENT_PID=""
}

push_stage() {
  device_preflight
  adb_su "rm -rf '$REMOTE_ROOT/bin' '$REMOTE_ROOT/lib' '$REMOTE_ROOT/plugins' '$REMOTE_ROOT/runtime'; mkdir -p '$REMOTE_ROOT/bin' '$REMOTE_ROOT/lib' '$REMOTE_ROOT/plugins' '$REMOTE_ROOT/runtime' '$REMOTE_ROOT/logs'; chmod 777 '$REMOTE_ROOT' '$REMOTE_ROOT/bin' '$REMOTE_ROOT/lib' '$REMOTE_ROOT/plugins' '$REMOTE_ROOT/runtime' '$REMOTE_ROOT/logs'"
  local file
  for file in "$STAGE_DIR/bin"/*; do
    [ -f "$file" ] || continue
    adb_push_file "$file" "$REMOTE_ROOT/bin/$(basename "$file")"
  done
  for file in "$STAGE_DIR/lib"/*; do
    [ -f "$file" ] || continue
    adb_push_file "$file" "$REMOTE_ROOT/lib/$(basename "$file")"
  done
  for file in "$STAGE_DIR/plugins"/*; do
    [ -f "$file" ] || continue
    adb_push_file "$file" "$REMOTE_ROOT/plugins/$(basename "$file")"
  done
  adb_cmd push "$STAGE_DIR/runtime/startup.conf" "$REMOTE_ROOT/runtime/startup.conf"
  adb_cmd push "$STAGE_DIR/runtime/source-provenance.properties" "$REMOTE_ROOT/runtime/source-provenance.properties"
  adb_su "chmod 755 '$REMOTE_ROOT/bin' '$REMOTE_ROOT/lib' '$REMOTE_ROOT/plugins' '$REMOTE_ROOT/runtime'; find '$REMOTE_ROOT/bin' -type f -exec chmod 755 {} +; find '$REMOTE_ROOT/lib' '$REMOTE_ROOT/plugins' -type f -name '*.so' -exec chmod 755 {} +; chmod 644 '$REMOTE_ROOT/runtime/startup.conf' '$REMOTE_ROOT/runtime/source-provenance.properties'"
  device_capture remote-artifact-hashes "sha256sum '$REMOTE_ROOT/bin/vpp' '$REMOTE_ROOT/bin/vppctl' '$REMOTE_ROOT/plugins/nfqueue_live_poc_plugin.so'; cat '$REMOTE_ROOT/runtime/source-provenance.properties'" || true
}

start_vpp() {
  stop_vpp
  remove_hooks
  adb_su "rm -f '$REMOTE_ROOT/runtime/cli.sock' '$REMOTE_ROOT/runtime/api.sock' '$REMOTE_ROOT/runtime/statseg.sock' '$REMOTE_ROOT/runtime/vpp.pid'; rm -rf '$REMOTE_ROOT/shm'; mkdir -p '$REMOTE_ROOT/runtime' '$REMOTE_ROOT/logs' '$REMOTE_ROOT/shm'; chmod 777 '$REMOTE_ROOT/shm'; cd '$REMOTE_ROOT' && export LD_LIBRARY_PATH='$REMOTE_ROOT/lib' SAKAMOTO_ANDROID_SHM_DIR='$REMOTE_ROOT/shm'; nohup '$REMOTE_ROOT/bin/vpp' plugin_path '$REMOTE_ROOT/plugins' -c '$REMOTE_ROOT/runtime/startup.conf' >'$REMOTE_ROOT/logs/vpp-stdout.log' 2>&1 < /dev/null & echo \$! > '$REMOTE_ROOT/runtime/vpp.pid'"
  local ready=0
  for _ in {1..40}; do
    if vppctl_cmd 'show version' >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 0.25
  done
  [[ "$ready" = 1 ]] || {
    device_capture startup-failure "cat '$REMOTE_ROOT/logs/vpp-stdout.log' 2>/dev/null || true; cat '$REMOTE_ROOT/logs/vpp.log' 2>/dev/null || true"
    return 1
  }
  CURRENT_PID="$(adb_su "cat '$REMOTE_ROOT/runtime/vpp.pid' 2>/dev/null || true" | tr -d '\r\n')"
  vppctl_capture version 'show version'
  device_capture startup-process "cat '$REMOTE_ROOT/runtime/vpp.pid'; cat /proc/\$(cat '$REMOTE_ROOT/runtime/vpp.pid')/status 2>/dev/null | head -30 || true"
}

install_hooks() {
  adb_su "/system/bin/iptables -w -I OUTPUT 1 -p icmp -d '$IP4_TARGET' -j NFQUEUE --queue-num '$QUEUE_BASE' --queue-bypass"
  adb_su "/system/bin/iptables -w -I INPUT 1 -p icmp -s '$IP4_TARGET' -j NFQUEUE --queue-num '$((QUEUE_BASE + 1))' --queue-bypass"
  adb_su "/system/bin/ip6tables -w -I OUTPUT 1 -p ipv6-icmp -d '$IP6_TARGET' -j NFQUEUE --queue-num '$((QUEUE_BASE + 2))' --queue-bypass"
  adb_su "/system/bin/ip6tables -w -I INPUT 1 -p ipv6-icmp -s '$IP6_TARGET' -j NFQUEUE --queue-num '$((QUEUE_BASE + 3))' --queue-bypass"
  device_capture hooks-installed '/system/bin/iptables -S OUTPUT 2>/dev/null || true; /system/bin/iptables -S INPUT 2>/dev/null || true; /system/bin/ip6tables -S OUTPUT 2>/dev/null || true; /system/bin/ip6tables -S INPUT 2>/dev/null || true'
}

run_real_traffic() {
  device_capture ping4 "/system/bin/ping -c '$PING_COUNT' -W '$PING_TIMEOUT' '$IP4_TARGET'" || true
  device_capture ping6 "/system/bin/ping6 -c '$PING_COUNT' -W '$PING_TIMEOUT' '$IP6_TARGET'" || true
  sleep 1
}

show_value() {
  local file="$1"
  local key="$2"
  awk -v key="$key" '{ for (i = 1; i <= NF; i++) if ($i == key) { print $(i + 1); exit } }' "$file" 2>/dev/null || true
}

lane_value() {
  local file="$1"
  local lane="$2"
  local key="$3"
  awk -v lane="$lane" -v key="$key" '$1 == "lane" && $2 == lane { for (i = 1; i <= NF; i++) if ($i == key) { print $(i + 1); exit } }' "$file" 2>/dev/null || true
}

require_ge() {
  local file="$1"
  local key="$2"
  local minimum="$3"
  local value
  value="$(show_value "$file" "$key")"
  [[ "$value" =~ ^[0-9]+$ && "$value" -ge "$minimum" ]] || {
    echo "S80 assertion failed: $file $key=$value expected >= $minimum"
    return 1
  }
}

require_eq() {
  local file="$1"
  local key="$2"
  local expected="$3"
  local value
  value="$(show_value "$file" "$key")"
  [[ "$value" = "$expected" ]] || {
    echo "S80 assertion failed: $file $key=$value expected $expected"
    return 1
  }
}

require_lane_ge() {
  local file="$1"
  local lane="$2"
  local key="$3"
  local minimum="$4"
  local value
  value="$(lane_value "$file" "$lane" "$key")"
  [[ "$value" =~ ^[0-9]+$ && "$value" -ge "$minimum" ]] || {
    echo "S80 assertion failed: $file lane=$lane $key=$value expected >= $minimum"
    return 1
  }
}

assert_traffic_progress() {
  local file="$1"
  grep -Eq '[1-9][0-9]* received' "$file" || {
    echo "S80 assertion failed: no successful packet evidence in $file"
    return 1
  }
}

assert_live_show() {
  local file="$1"
  require_ge "$file" datagrams 1
  require_ge "$file" callbacks 1
  require_ge "$file" 'envelope-messages' 1
  require_ge "$file" 'valid-messages' 1
  require_ge "$file" 'live-buffer-receives' 1
  require_ge "$file" 'inline-metadata-writes' 1
  require_ge "$file" 'payload-pointer-projections' 1
  require_ge "$file" 'payload-span-checks' 1
  require_ge "$file" handoffs 1
  require_ge "$file" 'owner-remote-obligations' 1
  require_ge "$file" 'owner-remote-handoffs' 1
  require_ge "$file" 'identity-proof-checks' 1
  require_ge "$file" 'identity-proof-matches' 1
  require_ge "$file" 'physical-verdict-attempts' 1
  require_ge "$file" 'native-verdict-calls' 1
  require_ge "$file" 'completion-outcome-succeeded' 1
  require_ge "$file" 'native-buffer-returns' 1
  require_ge "$file" 'message-obligations' 1
  require_lane_ge "$file" 0 obligations 1
  require_lane_ge "$file" 2 obligations 1
  require_eq "$file" 'packet-copies' 0
  require_eq "$file" 'scratch-rx-buffers' 0
  require_eq "$file" 'full-packet-memcpy' 0
  require_eq "$file" 'per-packet-heap-objects' 0
  require_eq "$file" 'verdict-identity-mismatches' 0
  require_eq "$file" 'retry-attempts' 0
  require_eq "$file" 'worker-reentries' 0
  require_eq "$file" 'policy-re-evaluations' 0
  require_eq "$file" 'replacement-payloads' 0
  require_eq "$file" 'terminal-intent-rewrites' 0
  require_eq "$file" 'policy-verdict-rewrites' 0
  require_eq "$file" 'outstanding-obligations' 0
  require_eq "$file" 'completion-debt' 0
  require_eq "$file" 'completion-credits-held' 0
  require_eq "$file" 'residue-completion-credits' 0
  require_eq "$file" 'residue-obligations' 0
  require_eq "$file" 'completion-outcome-failed-definite' 0
  require_eq "$file" 'completion-outcome-unknown' 0
}

assert_teardown_show() {
  local file="$1"
  require_eq "$file" 'teardown-state' COMPLETE
  require_eq "$file" 'ingress-depth' 0
  require_eq "$file" 'completion-depth' 0
  require_eq "$file" 'origin-return-depth' 0
  require_eq "$file" 'late-return-depth' 0
  require_eq "$file" 'completion-channel-open' 0
  require_eq "$file" 'netlink-fd' -1
  require_eq "$file" 'completion-fd' -1
  require_eq "$file" 'queue-open' 0
  require_eq "$file" 'handle-open' 0
  require_eq "$file" 'enabled-lanes' 0
  require_eq "$file" 'outstanding-obligations' 0
  require_eq "$file" 'completion-debt' 0
  require_eq "$file" 'completion-credits-held' 0
  require_eq "$file" 'residue-completion-credits' 0
  require_eq "$file" 'residue-obligations' 0
}

assert_process_death_before_cleanup() {
  local file="$1"
  require_ge "$file" 'held-obligation' 1
  require_ge "$file" 'outstanding-obligations' 1
  require_ge "$file" 'completion-debt' 1
  require_ge "$file" 'completion-credits-held' 1
}

capture_and_assert_show() {
  local label="$1"
  local output="$CASE_DIR/$label.txt"
  run_maybe "capture $label" vppctl_capture "$label" 'show nfqueue-live-poc'
  run_maybe "assert live show $label" assert_live_show "$output"
}

disable_and_assert_teardown() {
  local label="${1:-disable}"
  run_maybe disable vppctl_capture "$label-command" 'nfqueue-live-poc disable'
  run_maybe teardown-show vppctl_capture "$label" 'show nfqueue-live-poc'
  run_maybe assert-teardown assert_teardown_show "$CASE_DIR/$label.txt"
}

finish_case() {
  local status="$1"
  remove_hooks || true
  stop_vpp || true
  run_maybe "residue check $CURRENT_CASE" capture_residue
  if ! residue_summary; then
    status=1
    CASE_FAILED=1
  fi
  local result="PASS"
  if [[ "$status" != 0 || "$CASE_FAILED" != 0 ]]; then
    result="FAIL"
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$CURRENT_CASE" "$result" "$CASE_DIR" "$(adb_target_desc)" \
    "$QUEUE_BASE" "$(basename "$STAGE_DIR")" >>"$MATRIX_FILE"
  echo "S80 case $CURRENT_CASE: $result"
  CURRENT_CASE="bootstrap"
  CASE_DIR="$RESULT_DIR/$CURRENT_CASE"
  mkdir -p "$CASE_DIR"
  return "$status"
}

run_case_normal() {
  CURRENT_CASE="normal-dual-owner-remote"
  CASE_DIR="$RESULT_DIR/$CURRENT_CASE"
  mkdir -p "$CASE_DIR"
  CASE_FAILED=0
  run_maybe start-vpp start_vpp
  run_maybe enable-dual vppctl_capture enable 'nfqueue-live-poc enable-dual queue-base '"$QUEUE_BASE"' two-workers owner-remote'
  run_maybe install-hooks install_hooks
  run_maybe real-dual-traffic run_real_traffic
  run_maybe ping4-progress assert_traffic_progress "$CASE_DIR/ping4.txt"
  run_maybe ping6-progress assert_traffic_progress "$CASE_DIR/ping6.txt"
  capture_and_assert_show show-before-disable
  disable_and_assert_teardown disable
  finish_case "$CASE_FAILED" || true
}

run_case_duplicate_stale() {
  CURRENT_CASE="duplicate-stale-completion"
  CASE_DIR="$RESULT_DIR/$CURRENT_CASE"
  mkdir -p "$CASE_DIR"
  CASE_FAILED=0
  run_maybe start-vpp start_vpp
  run_maybe enable-dual-fault vppctl_capture enable 'nfqueue-live-poc enable-dual queue-base '"$QUEUE_BASE"' two-workers owner-remote inject-duplicate inject-stale'
  run_maybe install-hooks install_hooks
  run_maybe real-dual-traffic run_real_traffic
  capture_and_assert_show show-before-disable
  run_maybe duplicate-count require_ge "$CASE_DIR/show-before-disable.txt" duplicate 1
  run_maybe stale-count require_ge "$CASE_DIR/show-before-disable.txt" stale 1
  run_maybe duplicate-attempt-count require_ge "$CASE_DIR/show-before-disable.txt" duplicate-attempts 1
  run_maybe stale-generation-count require_ge "$CASE_DIR/show-before-disable.txt" stale-generation-completions 1
  disable_and_assert_teardown disable
  finish_case "$CASE_FAILED" || true
}

run_case_clean_drain() {
  CURRENT_CASE="queue-clean-drain"
  CASE_DIR="$RESULT_DIR/$CURRENT_CASE"
  mkdir -p "$CASE_DIR"
  CASE_FAILED=0
  run_maybe start-vpp start_vpp
  run_maybe enable-hold vppctl_capture enable 'nfqueue-live-poc enable-dual queue-base '"$QUEUE_BASE"' two-workers owner-remote hold-obligation'
  run_maybe install-hooks install_hooks
  run_maybe held-traffic run_real_traffic
  run_maybe capture-held vppctl_capture show-before-disable 'show nfqueue-live-poc'
  run_maybe assert-held assert_process_death_before_cleanup "$CASE_DIR/show-before-disable.txt"
  disable_and_assert_teardown disable
  run_maybe drain-accept require_ge "$CASE_DIR/disable.txt" teardown-drain-accepts 1
  finish_case "$CASE_FAILED" || true
}

run_case_process_death_fresh_restart() {
  CURRENT_CASE="process-death-fresh-restart"
  CASE_DIR="$RESULT_DIR/$CURRENT_CASE"
  mkdir -p "$CASE_DIR"
  CASE_FAILED=0
  run_maybe start-vpp start_vpp
  run_maybe enable-hold vppctl_capture enable 'nfqueue-live-poc enable-dual queue-base '"$QUEUE_BASE"' two-workers owner-remote hold-obligation'
  run_maybe install-hooks install_hooks
  run_maybe held-traffic run_real_traffic
  run_maybe capture-held vppctl_capture show-before-process-death 'show nfqueue-live-poc'
  run_maybe assert-held assert_process_death_before_cleanup "$CASE_DIR/show-before-process-death.txt"
  capture_remote_logs
  kill_vpp_for_process_case
  device_capture process-termination-before-cleanup 'pidof vpp 2>/dev/null || true; cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null || true; /system/bin/iptables -S 2>/dev/null || true; /system/bin/ip6tables -S 2>/dev/null || true' || true
  echo 'failure-category=PROCESS_TERMINATED_WITH_LIVE_CURRENT_GENERATION_OBLIGATION' >"$CASE_DIR/process-termination-ledger.txt"
  cat "$CASE_DIR/show-before-process-death.txt" >>"$CASE_DIR/process-termination-ledger.txt" 2>/dev/null || true
  remove_hooks
  run_maybe fresh-start start_vpp
  run_maybe fresh-enable vppctl_capture fresh-enable 'nfqueue-live-poc enable-dual queue-base '"$QUEUE_BASE"' two-workers owner-remote'
  run_maybe fresh-hooks install_hooks
  run_maybe fresh-traffic run_real_traffic
  capture_and_assert_show fresh-restart-show
  run_maybe fresh-generation require_eq "$CASE_DIR/fresh-restart-show.txt" 'queue-generation' 1
  disable_and_assert_teardown fresh-disable
  finish_case "$CASE_FAILED" || true
}

capture_provenance() {
  local output="$RESULT_DIR/provenance.properties"
  local serial
  serial="$(adb_target_desc)"
  {
    echo "ticket=SAKAMOTO-80"
    echo "deviceSerial=$serial"
    echo "adbWrapper=$REPO_ROOT/dev/adb"
    echo "repoRevision=$(git -C "$REPO_ROOT" rev-parse HEAD)"
    echo "repoBranch=$(git -C "$REPO_ROOT" branch --show-current)"
    echo "s80FixedPoint=db7547c012626a82896f33e08f8f40f9b5262a86"
    echo "runnerSha256=$(sha256sum "$SCRIPT_DIR/$(basename "$0")" | awk '{print $1}')"
    echo "stageSha256=$(sha256sum "$STAGE_DIR/runtime/source-provenance.properties" | awk '{print $1}')"
    echo "localVppSha256=$(sha256sum "$STAGE_DIR/bin/vpp" | awk '{print $1}')"
    echo "localVppctlSha256=$(sha256sum "$STAGE_DIR/bin/vppctl" | awk '{print $1}')"
    echo "localPluginSha256=$(sha256sum "$STAGE_DIR/plugins/nfqueue_live_poc_plugin.so" | awk '{print $1}')"
    echo "queueBase=$QUEUE_BASE"
    echo "ip4Target=$IP4_TARGET"
    echo "ip6Target=$IP6_TARGET"
    echo "rawEvidenceDir=$RESULT_DIR"
    echo "validity=see matrix.tsv and linux-vs-android.tsv"
  } >"$output"
  device_capture device-provenance 'id; uname -a; getprop ro.product.model; getprop ro.build.version.release; getprop ro.build.version.sdk; getprop ro.product.cpu.abi; nsenter -t 1 -m -- getenforce 2>/dev/null || getenforce 2>/dev/null || true; cat /proc/version' || true
  device_capture device-artifacts "sha256sum '$REMOTE_ROOT/bin/vpp' '$REMOTE_ROOT/bin/vppctl' '$REMOTE_ROOT/plugins/nfqueue_live_poc_plugin.so'; cat '$REMOTE_ROOT/runtime/source-provenance.properties'" || true
  device_capture device-commands "echo adb-wrapper '$REPO_ROOT/dev/adb'; echo remote-root '$REMOTE_ROOT'; echo queue-base '$QUEUE_BASE'; echo hooks 'iptables/ip6tables OUTPUT+INPUT with --queue-bypass'; echo traffic 'ping IPv4 and IPv6'; echo lifecycle 'normal duplicate-stale clean-drain process-death fresh-restart'" || true
}

write_comparison() {
  local android_status="PARTIAL"
  if awk -F '\t' 'NR > 1 && $2 == "FAIL" { found=1 } END { exit found ? 0 : 1 }' "$MATRIX_FILE"; then
    android_status="FAIL"
  elif awk -F '\t' 'NR > 1 && $2 == "PASS" { count++ } END { exit count == 4 ? 0 : 1 }' "$MATRIX_FILE"; then
    android_status="PASS"
  fi
  {
    printf 'requirement\tlinux-s79-reference\tandroid-s80\tclassification\n'
    printf 'IPv4 NFQUEUE live-buffer obligation\tPASS (S76/S79 host matrix)\t%s\t%s\n' "$android_status" "$android_status"
    printf 'IPv6 NFQUEUE live-buffer obligation\tPASS (S76/S79 host matrix)\t%s\t%s\n' "$android_status" "$android_status"
    printf 'metadata/copy-count/inline lease\tPASS (host ledger)\t%s\t%s\n' "$android_status" "$android_status"
    printf 'owner mismatch/origin verdict/native return\tPASS (S76 host remote route)\t%s\t%s\n' "$android_status" "$android_status"
    printf 'duplicate/stale completion\tPASS (S77 host matrix)\t%s\t%s\n' "$android_status" "$android_status"
    printf 'queue/process teardown\tPASS (S79 host matrix)\t%s\t%s\n' "$android_status" "$android_status"
    printf 'fresh restart and zero residue\tPASS (S79 host matrix)\t%s\t%s\n' "$android_status" "$android_status"
  } >"$RESULT_DIR/linux-vs-android.tsv"
}

cleanup_on_exit() {
  local rc=$?
  remove_hooks || true
  stop_vpp || true
  if ! residue_summary; then
    rc=1
  fi
  echo "Android S80 final cleanup rc=$rc"
  exit "$rc"
}
trap cleanup_on_exit EXIT

device_preflight
if [[ "$S80_STAGE" = 1 ]]; then
  if [[ "$S80_BUILD" = 1 ]]; then
    "$SCRIPT_DIR/android-configure-vpp-probe.sh"
    BUILD_DIR="$VPP_WORK_ROOT/vpp-android-configure-probe" TARGET=nfqueue_live_poc_plugin \
      "$SCRIPT_DIR/android-build-vpp-probe.sh"
  fi
  "$STAGE_SCRIPT"
fi
[[ -x "$STAGE_DIR/bin/vpp" && -x "$STAGE_DIR/bin/vppctl" && \
   -f "$STAGE_DIR/plugins/nfqueue_live_poc_plugin.so" ]] || {
  echo "S80 stage is incomplete: $STAGE_DIR" >&2
  exit 1
}
if [[ "$S80_PUSH" = 1 ]]; then
  push_stage
fi
capture_provenance

run_case_normal
run_case_duplicate_stale
run_case_clean_drain
run_case_process_death_fresh_restart
write_comparison

echo
echo "# SAKAMOTO-80 matrix"
cat "$MATRIX_FILE"
cat "$RESULT_DIR/linux-vs-android.tsv"
if awk -F '\t' 'NR > 1 && $2 != "PASS" { bad=1 } END { exit bad ? 0 : 1 }' "$MATRIX_FILE"; then
  echo 'S80 Android live-buffer acceptance: FAIL'
  exit 1
fi
echo 'S80 Android live-buffer acceptance: PASS'
