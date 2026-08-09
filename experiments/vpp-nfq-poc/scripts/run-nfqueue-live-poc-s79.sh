#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-79 live teardown runner.
#
# Each invocation owns one disposable netns and one evidence directory.  The
# plugin is exercised through its real NFQUEUE/VPP path; the deterministic
# state model is kept in nfqueue_live_s79_teardown_test.c for cases that need
# to represent a delayed completion after process death.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VPP_WORK_ROOT="${VPP_WORK_ROOT:-$POC_DIR/work}"
VPP_INSTALL_DIR="${VPP_INSTALL_DIR:-$VPP_WORK_ROOT/vpp-s73-install-9258530f3804a152578ce11cc7c8a1e9eab88ed0}"
VPP_BIN="${VPP_BIN:-$VPP_INSTALL_DIR/bin/vpp}"
VPPCTL_BIN="${VPPCTL_BIN:-$VPP_INSTALL_DIR/bin/vppctl}"
VPP_CONFIG_TEMPLATE="${S79_CONFIG_TEMPLATE:-$POC_DIR/configs/nfqueue-live-poc-s79-startup.conf}"
CASE="${S79_CASE:-queue-disable}"
QUEUE_BASE="${S79_QUEUE_BASE:-42}"
RUNTIME_ROOT="${S79_RUNTIME_ROOT:-/tmp/sakamoto-vpp-nfqueue-s79-$CASE}"
EVIDENCE_DIR="${S79_EVIDENCE_DIR:-/tmp/sakamoto-s79-evidence-$CASE}"
NETNS_STATE="${S79_NETNS_STATE:-/tmp/sakamoto-nfqueue-s79-state-$CASE}"
# Linux interface names are limited to 15 bytes.  Keep the case prefix short
# while retaining distinct names when a caller runs cases concurrently.
CASE_IF_TAG="${CASE:0:6}"
HOST_IF="${S79_HOST_IF:-s79-${CASE_IF_TAG}-h}"
PEER_IF="${S79_PEER_IF:-s79-${CASE_IF_TAG}-p}"
HOST4="${S79_HOST4:-10.201.79.1}"
PEER4="${S79_PEER4:-10.201.79.2}"
HOST6="${S79_HOST6:-fd00:201:79::1}"
PEER6="${S79_PEER6:-fd00:201:79::2}"
PING_COUNT="${S79_PING_COUNT:-8}"
ROUND_COUNT="${S79_ROUNDS:-3}"

vpp_pid=""
netns_up=0

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "S79 live runner needs root/CAP_NET_ADMIN (run with rtk unshare -Urn)" >&2
    exit 1
  fi
}

require_binary() {
  for binary in "$VPP_BIN" "$VPPCTL_BIN"; do
    [ -x "$binary" ] || {
      echo "missing executable: $binary (run build-nfqueue-live-poc.sh first)" >&2
      exit 1
    }
  done
  [ -f "$VPP_INSTALL_DIR/s73-provenance.properties" ] || {
    echo "missing pinned provenance: $VPP_INSTALL_DIR/s73-provenance.properties" >&2
    exit 1
  }
  PROVENANCE_PLUGIN_SHA="$(awk -F= '$1 == "pluginSha256" { print $2; exit }' \
    "$VPP_INSTALL_DIR/s73-provenance.properties")"
  [[ "$PROVENANCE_PLUGIN_SHA" =~ ^[0-9a-f]{64}$ ]] || {
    echo "invalid pluginSha256 in pinned provenance" >&2
    exit 1
  }
}

queue_rule_present() {
  local table_output
  table_output="$(iptables-save -t filter 2>/dev/null || true)"
  if grep -Eq -- "-j NFQUEUE.*--queue-num ($QUEUE_BASE|$((QUEUE_BASE + 1)))" \
    <<<"$table_output"; then
    return 0
  fi
  table_output="$(ip6tables-save -t filter 2>/dev/null || true)"
  grep -Eq -- "-j NFQUEUE.*--queue-num ($((QUEUE_BASE + 2))|$((QUEUE_BASE + 3)))" \
    <<<"$table_output"
}

cleanup() {
  local status="$?" cleanup_error=0
  if [ -n "$vpp_pid" ] && kill -0 "$vpp_pid" >/dev/null 2>&1; then
    kill -TERM "$vpp_pid" >/dev/null 2>&1 || true
    wait "$vpp_pid" >/dev/null 2>&1 || true
  fi
  if [ "$netns_up" -eq 1 ]; then
    if ! QUEUE_BASE="$QUEUE_BASE" S76_NETNS_STATE="$NETNS_STATE" \
      S76_HOST_IF="$HOST_IF" S76_PEER_IF="$PEER_IF" \
      S76_HOST4="$HOST4" S76_PEER4="$PEER4" S76_HOST6="$HOST6" S76_PEER6="$PEER6" \
      "$SCRIPT_DIR/setup-netns-s76.sh" down >"$EVIDENCE_DIR/cleanup-netns.log" 2>&1; then
      echo "S79 cleanup: network teardown failed" >&2
      cleanup_error=1
    fi
    netns_up=0
  fi
  if queue_rule_present; then
    echo "S79 cleanup: NFQUEUE hook residue remains after netns teardown" >&2
    cleanup_error=1
  fi
  if [ "$cleanup_error" -ne 0 ] && [ "$status" -eq 0 ]; then
    status=1
  fi
  return "$status"
}

start_vpp() {
  local config="$EVIDENCE_DIR/startup.conf"
  mkdir -p "$RUNTIME_ROOT/plugins" "$EVIDENCE_DIR"
  sed "s#__S79_RUNTIME_ROOT__#$RUNTIME_ROOT#g" "$VPP_CONFIG_TEMPLATE" >"$config"
  cp "$VPP_INSTALL_DIR/lib/vpp_plugins/nfqueue_live_poc_plugin.so" \
    "$RUNTIME_ROOT/plugins/nfqueue_live_poc_plugin.so"
  COPIED_PLUGIN_SHA="$(sha256sum "$RUNTIME_ROOT/plugins/nfqueue_live_poc_plugin.so" | awk '{print $1}')"
  [ "$COPIED_PLUGIN_SHA" = "$PROVENANCE_PLUGIN_SHA" ] || {
    echo "plugin/provenance hash mismatch" >&2
    exit 1
  }
  rm -f "$RUNTIME_ROOT/cli.sock" "$RUNTIME_ROOT/vpp.log" \
    "$RUNTIME_ROOT/vpp.stdout.log"
  SAKAMOTO_S73_REGULAR_MEMFD="${S79_REGULAR_MEMFD:-1}" \
    "$VPP_BIN" -c "$config" >"$RUNTIME_ROOT/vpp.stdout.log" 2>&1 &
  vpp_pid="$!"
  for _ in $(seq 1 100); do
    [ -S "$RUNTIME_ROOT/cli.sock" ] && return 0
    if ! kill -0 "$vpp_pid" >/dev/null 2>&1; then
      cat "$RUNTIME_ROOT/vpp.stdout.log" >&2 || true
      return 1
    fi
    sleep 0.1
  done
  cat "$RUNTIME_ROOT/vpp.stdout.log" >&2 || true
  return 1
}

stop_vpp() {
  if [ -z "$vpp_pid" ]; then
    return 0
  fi
  kill -TERM "$vpp_pid" >/dev/null 2>&1 || true
  wait "$vpp_pid" >/dev/null 2>&1 || true
  vpp_pid=""
}

show_runtime() {
  local destination="$1"
  "$VPPCTL_BIN" -s "$RUNTIME_ROOT/cli.sock" show nfqueue-live-poc \
    >"$destination"
}

value_for() {
  local file="$1" key="$2"
  awk -v key="$key" '{for (i = 1; i <= NF; i++) if ($i == key) { print $(i + 1); exit }}' \
    "$file" | tr -d '\r'
}

require_exact() {
  local file="$1" key="$2" expected="$3" value
  value="$(value_for "$file" "$key")"
  if [ "${value:-missing}" != "$expected" ]; then
    echo "S79 acceptance failure: $key=$value expected=$expected file=$file" >&2
    exit 1
  fi
}

require_at_least() {
  local file="$1" key="$2" minimum="$3" value
  value="$(value_for "$file" "$key")"
  if [ -z "$value" ] || [ "$value" -lt "$minimum" ]; then
    echo "S79 acceptance failure: $key=$value expected>=$minimum file=$file" >&2
    exit 1
  fi
}

assert_transition_order() {
  local file="$1" expected="$2" actual
  actual="$(awk '$1 == "teardown-transition" { print $3 }' "$file" |
    tr -d '\r' | paste -sd ' ' -)"
  if [ "$actual" != "$expected" ]; then
    echo "S79 transition order failure: actual=[$actual] expected=[$expected]" >&2
    exit 1
  fi
}

assert_closed_ledger() {
  local file="$1" baseline="${2:-}"
  require_exact "$file" teardown-state COMPLETE
  require_exact "$file" enabled 0
  require_exact "$file" completion-channel-open 0
  require_exact "$file" ingress-depth 0
  require_exact "$file" completion-depth 0
  require_exact "$file" origin-return-depth 0
  require_exact "$file" late-return-depth 0
  require_exact "$file" held-obligation 0
  require_exact "$file" held-buffer-index 4294967295
  require_exact "$file" outstanding-obligations 0
  require_exact "$file" residue-obligations 0
  require_exact "$file" completion-debt 0
  require_exact "$file" completion-credits-held 0
  require_exact "$file" residue-completion-credits 0
  require_exact "$file" teardown-obligation-residue 0
  require_exact "$file" netlink-fd -1
  require_exact "$file" completion-fd -1
  require_exact "$file" queue-open 0
  require_exact "$file" handle-open 0
  require_exact "$file" enabled-lanes 0
  require_exact "$file" retry-attempts 0
  require_exact "$file" worker-reentries 0
  require_exact "$file" policy-re-evaluations 0
  require_exact "$file" replacement-payloads 0
  require_exact "$file" terminal-intent-rewrites 0
  require_exact "$file" policy-verdict-rewrites 0
  raised="$(value_for "$file" completion-debt-raised)"
  settled="$(value_for "$file" completion-debt-settled)"
  [ "${raised:-missing}" = "${settled:-different}" ] || {
    echo "S79 debt mismatch: raised=$raised settled=$settled" >&2
    exit 1
  }
  acquired="$(value_for "$file" completion-credit-acquired)"
  released="$(value_for "$file" completion-credit-released)"
  [ "${acquired:-missing}" = "${released:-different}" ] || {
    echo "S79 credit mismatch: acquired=$acquired released=$released" >&2
    exit 1
  }
  counter_value() {
    local key="$1" value previous
    value="$(value_for "$file" "$key")"
    if [ -n "$baseline" ]; then
      previous="$(value_for "$baseline" "$key")"
      value="$((value - previous))"
    fi
    printf '%s\n' "$value"
  }
  physical="$(counter_value physical-verdict-attempts)"
  verdicts="$(counter_value verdict-attempts)"
  succeeded="$(value_for "$file" completion-outcome-succeeded)"
  failed="$(value_for "$file" completion-outcome-failed-definite)"
  unknown="$(value_for "$file" completion-outcome-unknown)"
  [ "${physical:-missing}" = "${verdicts:-different}" ] || {
    echo "S79 verdict-attempt mismatch: physical=$physical verdicts=$verdicts" >&2
    exit 1
  }
  [ "$((succeeded + failed + unknown))" -eq "${physical:-0}" ] || {
    echo "S79 outcome partition mismatch: physical=$physical succeeded=$succeeded failed=$failed unknown=$unknown" >&2
    exit 1
  }
  frames="$(counter_value completion-frames)"
  stale="$(counter_value stale)"
  duplicate="$(counter_value duplicate)"
  origin_settlements="$(( $(value_for "$file" teardown-drain-accepts) +
    $(value_for "$file" teardown-deadline-accepts) +
    $(value_for "$file" teardown-deadline-failed-definite) +
    $(value_for "$file" teardown-deadline-unknown) +
    $(value_for "$file" teardown-identity-unrecoverable) ))"
  [ "$((stale + duplicate + physical - origin_settlements))" -eq "${frames:-0}" ] || {
    echo "S79 completion partition mismatch: frames=$frames physical=$physical origin-settlements=$origin_settlements stale=$stale duplicate=$duplicate" >&2
    exit 1
  }
}

wait_for_real_hold() {
  local destination="$1" held outstanding debt credits
  for _ in $(seq 1 100); do
    show_runtime "$destination"
    held="$(value_for "$destination" held-obligation)"
    outstanding="$(value_for "$destination" outstanding-obligations)"
    debt="$(value_for "$destination" completion-debt)"
    credits="$(value_for "$destination" completion-credits-held)"
    if [ "${held:-0}" -eq 1 ] && [ "${outstanding:-0}" -ge 1 ] &&
       [ "${debt:-0}" -ge 1 ] && [ "${credits:-0}" -ge 1 ]; then
      return 0
    fi
    sleep 0.01
  done
  echo "S79 hold gate did not expose a real outstanding obligation" >&2
  cat "$destination" >&2
  exit 1
}

assert_real_hold() {
  local file="$1"
  require_at_least "$file" outstanding-obligations 1
  require_at_least "$file" completion-debt 1
  require_at_least "$file" completion-credits-held 1
  require_exact "$file" held-obligation 1
  held_index="$(value_for "$file" held-buffer-index)"
  [ -n "$held_index" ] && [ "$held_index" -ne 4294967295 ] || {
    echo "S79 hold gate did not expose a concrete buffer index" >&2
    exit 1
  }
}

run_traffic() {
  local peer_pid p4 p6 r4 r6
  peer_pid="$(QUEUE_BASE="$QUEUE_BASE" S76_NETNS_STATE="$NETNS_STATE" \
    "$SCRIPT_DIR/setup-netns-s76.sh" peer-pid)"
  set +e
  nsenter -t "$peer_pid" -n ping -c "$PING_COUNT" -i 0.01 -W 1 "$HOST4" \
    >"$EVIDENCE_DIR/ping-ip4.log" 2>&1 &
  p4="$!"
  nsenter -t "$peer_pid" -n ping -6 -c "$PING_COUNT" -i 0.01 -W 1 "$HOST6" \
    >"$EVIDENCE_DIR/ping-ip6.log" 2>&1 &
  p6="$!"
  wait "$p4"; r4="$?"
  wait "$p6"; r6="$?"
  set -e
  echo "ping4_rc=$r4 ping6_rc=$r6 peer_pid=$peer_pid" >>"$EVIDENCE_DIR/run.log"
}

enable_runtime() {
  local args=(queue-base "$QUEUE_BASE" two-workers owner-mixed)
  if [ "${S79_INJECT_STALE:-0}" = 1 ]; then args+=(inject-stale); fi
  if [ "${S79_INJECT_DUPLICATE:-0}" = 1 ]; then args+=(inject-duplicate); fi
  if [ "${S79_INJECT_COMPLETION_OVERFLOW:-0}" = 1 ]; then
    args+=(inject-completion-overflow)
  fi
  if [ "${S79_HOLD_OBLIGATION:-0}" = 1 ]; then
    args+=(hold-obligation)
  fi
  "$VPPCTL_BIN" -s "$RUNTIME_ROOT/cli.sock" nfqueue-live-poc enable-dual \
    "${args[@]}"
}

disable_runtime() {
  local option="${1:-}"
  if [ -n "$option" ]; then
    "$VPPCTL_BIN" -s "$RUNTIME_ROOT/cli.sock" nfqueue-live-poc disable "$option"
  else
    "$VPPCTL_BIN" -s "$RUNTIME_ROOT/cli.sock" nfqueue-live-poc disable
  fi
}

case_queue_disable() {
  S79_INJECT_STALE=1 S79_INJECT_DUPLICATE=1 enable_runtime
  show_runtime "$EVIDENCE_DIR/show-before-disable.txt"
  run_traffic
  disable_runtime
  show_runtime "$EVIDENCE_DIR/show-after-disable.txt"
  assert_transition_order "$EVIDENCE_DIR/show-after-disable.txt" \
    "ENABLE QUIESCE DRAIN CLOSE_COMPLETION CLOSE_CHANNELS FINISH"
  assert_closed_ledger "$EVIDENCE_DIR/show-after-disable.txt"
  require_at_least "$EVIDENCE_DIR/show-after-disable.txt" stale 1
  require_at_least "$EVIDENCE_DIR/show-after-disable.txt" duplicate 1
  require_at_least "$EVIDENCE_DIR/show-after-disable.txt" teardown-late-completion 1
  echo "queue-disable: ordered-close=1 stale-duplicate-isolated=1 no-replay=1 residue=0 PASS" \
    | tee -a "$EVIDENCE_DIR/run.log"
}

case_clean_stop() {
  enable_runtime
  run_traffic
  disable_runtime
  show_runtime "$EVIDENCE_DIR/show-after-disable.txt"
  assert_transition_order "$EVIDENCE_DIR/show-after-disable.txt" \
    "ENABLE QUIESCE DRAIN CLOSE_COMPLETION CLOSE_CHANNELS FINISH"
  assert_closed_ledger "$EVIDENCE_DIR/show-after-disable.txt"
  stop_vpp
  echo "clean-stop: ordered-close=1 process-exit=1 residue=0 PASS" \
    | tee -a "$EVIDENCE_DIR/run.log"
}

case_drain_deadline() {
  S79_HOLD_OBLIGATION=1 S79_INJECT_COMPLETION_OVERFLOW=1 \
    S79_INJECT_DUPLICATE=1 enable_runtime
  run_traffic &
  traffic_pid="$!"
  wait_for_real_hold "$EVIDENCE_DIR/show-before-disable.txt"
  assert_real_hold "$EVIDENCE_DIR/show-before-disable.txt"
  # The explicit deadline edge is a test-only bounded-drain arm.  It leaves
  # completion frames open while the origin lane identity-completes the held
  # current-generation obligation.
  disable_runtime deadline
  wait "$traffic_pid" || true
  show_runtime "$EVIDENCE_DIR/show-after-disable.txt"
  assert_transition_order "$EVIDENCE_DIR/show-after-disable.txt" \
    "ENABLE QUIESCE DRAIN DRAIN_DEADLINE CLOSE_COMPLETION CLOSE_CHANNELS FINISH"
  assert_closed_ledger "$EVIDENCE_DIR/show-after-disable.txt"
  require_exact "$EVIDENCE_DIR/show-after-disable.txt" teardown-deadline-reached 1
  require_exact "$EVIDENCE_DIR/show-after-disable.txt" teardown-deadline-forced 1
  require_at_least "$EVIDENCE_DIR/show-after-disable.txt" teardown-deadline-accepts 1
  echo "drain-deadline: deadline-classified=1 completion-open-until-close=1 residue=0 PASS" \
    | tee -a "$EVIDENCE_DIR/run.log"
}

case_process_termination() {
  S79_HOLD_OBLIGATION=1 enable_runtime
  run_traffic &
  traffic_pid="$!"
  wait_for_real_hold "$EVIDENCE_DIR/show-before-process-death.txt"
  show_runtime "$EVIDENCE_DIR/show-before-process-death.txt"
  assert_real_hold "$EVIDENCE_DIR/show-before-process-death.txt"
  if ! queue_rule_present; then
    echo "S79 process termination: expected hook before SIGKILL" >&2
    exit 1
  fi
  obligations_before="$(value_for "$EVIDENCE_DIR/show-before-process-death.txt" outstanding-obligations)"
  debt_before="$(value_for "$EVIDENCE_DIR/show-before-process-death.txt" completion-debt)"
  credits_before="$(value_for "$EVIDENCE_DIR/show-before-process-death.txt" completion-credits-held)"
  held_before="$(value_for "$EVIDENCE_DIR/show-before-process-death.txt" held-obligation)"
  held_index_before="$(value_for "$EVIDENCE_DIR/show-before-process-death.txt" held-buffer-index)"
  frames_before="$(value_for "$EVIDENCE_DIR/show-before-process-death.txt" completion-frames)"
  netlink_fd_before="$(value_for "$EVIDENCE_DIR/show-before-process-death.txt" netlink-fd)"
  completion_fd_before="$(value_for "$EVIDENCE_DIR/show-before-process-death.txt" completion-fd)"
  queue_open_before="$(value_for "$EVIDENCE_DIR/show-before-process-death.txt" queue-open)"
  handle_open_before="$(value_for "$EVIDENCE_DIR/show-before-process-death.txt" handle-open)"
  enabled_lanes_before="$(value_for "$EVIDENCE_DIR/show-before-process-death.txt" enabled-lanes)"
  {
    echo "failure-category=PROCESS_TERMINATED_WITH_LIVE_CURRENT_GENERATION_OBLIGATION"
    echo "generation-before=$(value_for "$EVIDENCE_DIR/show-before-process-death.txt" generation)"
    echo "obligations-before=$obligations_before"
    echo "completion-debt-before=$debt_before"
    echo "completion-credits-held-before=$credits_before"
    echo "buffers-before=$held_before"
    echo "held-obligation-before=$held_before"
    echo "held-buffer-index-before=$held_index_before"
    echo "completion-frames-before=$frames_before"
    echo "netlink-fd-before=$netlink_fd_before"
    echo "completion-fd-before=$completion_fd_before"
    echo "queue-count-before=$queue_open_before"
    echo "handle-count-before=$handle_open_before"
    echo "enabled-lanes-before=$enabled_lanes_before"
    echo "hooks-before=PRESENT"
    echo "log=$RUNTIME_ROOT/vpp.stdout.log"
  } | tee "$EVIDENCE_DIR/process-termination-ledger.txt" >>"$EVIDENCE_DIR/run.log"
  if ! kill -KILL "$vpp_pid" >/dev/null 2>&1; then
    echo "S79 process termination: failed to SIGKILL VPP" >&2
    exit 1
  fi
  wait "$vpp_pid" >/dev/null 2>&1 || true
  vpp_pid=""
  wait "$traffic_pid" >/dev/null 2>&1 || true
  [ "$obligations_before" -ge 1 ] && [ "$debt_before" -ge 1 ] &&
    [ "$credits_before" -ge 1 ] || {
      echo "S79 process termination: captured ledger was not nonzero" >&2
      exit 1
    }
  if ! queue_rule_present; then
    echo "S79 process termination: expected hook residue before cleanup" >&2
    exit 1
  fi
  start_vpp
  enable_runtime
  run_traffic
  show_runtime "$EVIDENCE_DIR/process-termination-fresh-before-disable.txt"
  disable_runtime
  show_runtime "$EVIDENCE_DIR/process-termination-fresh-after-disable.txt"
  assert_closed_ledger "$EVIDENCE_DIR/process-termination-fresh-after-disable.txt"
  require_exact "$EVIDENCE_DIR/process-termination-fresh-after-disable.txt" generation 1
  require_exact "$EVIDENCE_DIR/process-termination-fresh-after-disable.txt" stale 0
  require_exact "$EVIDENCE_DIR/process-termination-fresh-after-disable.txt" duplicate 0
  require_exact "$EVIDENCE_DIR/process-termination-fresh-after-disable.txt" teardown-late-completion 0
  stop_vpp
  echo "fresh-generation-after-death=1 old-obligation-replay=0 second-verdict=0" \
    | tee -a "$EVIDENCE_DIR/process-termination-ledger.txt" >>"$EVIDENCE_DIR/run.log"
  echo "process-termination: captured-live-ledger=1 classified=1 fresh-generation=1 pre-cleanup-hook-residue=1 post-cleanup-residue=0 PASS" \
    | tee -a "$EVIDENCE_DIR/run.log"
}

run_generation_round() {
  local round="$1" before="$EVIDENCE_DIR/generation-$round-before.txt" \
    after="$EVIDENCE_DIR/generation-$round-after.txt"
  enable_runtime
  show_runtime "$before"
  run_traffic
  disable_runtime
  show_runtime "$after"
  assert_transition_order "$after" \
    "ENABLE QUIESCE DRAIN CLOSE_COMPLETION CLOSE_CHANNELS FINISH"
  assert_closed_ledger "$after" "$before"
  require_exact "$after" teardown-late-completion 0
  generation="$(value_for "$after" generation)"
  [ -n "$generation" ] || {
    echo "S79 generation $round has no generation evidence" >&2
    exit 1
  }
  echo "$round $generation" >>"$EVIDENCE_DIR/generations.tsv"
}

case_fresh_restart() {
  enable_runtime
  run_traffic
  show_runtime "$EVIDENCE_DIR/fresh-restart-before-disable.txt"
  disable_runtime
  show_runtime "$EVIDENCE_DIR/fresh-restart-first-after-disable.txt"
  assert_closed_ledger "$EVIDENCE_DIR/fresh-restart-first-after-disable.txt"
  stop_vpp
  start_vpp
  enable_runtime
  run_traffic
  show_runtime "$EVIDENCE_DIR/fresh-restart-second-before-disable.txt"
  disable_runtime
  show_runtime "$EVIDENCE_DIR/fresh-restart-second-after-disable.txt"
  assert_closed_ledger "$EVIDENCE_DIR/fresh-restart-second-after-disable.txt"
  first="$(value_for "$EVIDENCE_DIR/fresh-restart-second-after-disable.txt" generation)"
  [ "$first" = 1 ] || {
    echo "S79 fresh restart expected a fresh generation=1, got $first" >&2
    exit 1
  }
  stop_vpp
  echo "fresh-restart: first-clean-stop=1 second-start=1 generation-reset=1 residue=0 PASS" \
    | tee -a "$EVIDENCE_DIR/run.log"
}

case_multiple_generations() {
  : >"$EVIDENCE_DIR/generations.tsv"
  for round in $(seq 1 "$ROUND_COUNT"); do
    run_generation_round "$round"
  done
  previous=0
  while read -r round generation; do
    [ "$generation" -gt "$previous" ] || {
      echo "S79 generation did not advance: round=$round generation=$generation previous=$previous" >&2
      exit 1
    }
    previous="$generation"
  done <"$EVIDENCE_DIR/generations.tsv"
  echo "multiple-generations: rounds=$ROUND_COUNT monotonic-generations=1 per-round-residue=0 PASS" \
    | tee -a "$EVIDENCE_DIR/run.log"
}

need_root
require_binary
mkdir -p "$EVIDENCE_DIR"
trap cleanup EXIT
netns_up=1

QUEUE_BASE="$QUEUE_BASE" S76_NETNS_STATE="$NETNS_STATE" \
  S76_HOST_IF="$HOST_IF" S76_PEER_IF="$PEER_IF" \
  S76_HOST4="$HOST4" S76_PEER4="$PEER4" S76_HOST6="$HOST6" S76_PEER6="$PEER6" \
  "$SCRIPT_DIR/setup-netns-s76.sh" up >"$EVIDENCE_DIR/setup-netns.log" 2>&1
start_vpp

{
  echo "# SAKAMOTO-79 live teardown evidence"
  echo "case=$CASE"
  echo "command=$0"
  echo "vpp=$VPP_BIN"
  echo "provenance=$VPP_INSTALL_DIR/s73-provenance.properties"
  echo "pluginSha256=$PROVENANCE_PLUGIN_SHA"
  echo "queue-base=$QUEUE_BASE"
  echo "runtime=$RUNTIME_ROOT"
  echo "netns=$NETNS_STATE"
} >"$EVIDENCE_DIR/run.log"

case "$CASE" in
  queue-disable) case_queue_disable ;;
  clean-stop) case_clean_stop ;;
  drain-deadline) case_drain_deadline ;;
  process-termination) case_process_termination ;;
  fresh-restart) case_fresh_restart ;;
  multiple-generations) case_multiple_generations ;;
  *)
    echo "S79_CASE must be queue-disable, clean-stop, drain-deadline, process-termination, fresh-restart, or multiple-generations" >&2
    exit 2
    ;;
esac

echo "S79 live teardown case=$CASE: PASS"
