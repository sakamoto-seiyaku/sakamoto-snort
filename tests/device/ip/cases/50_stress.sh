#!/bin/bash

set -euo pipefail

CASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$CASE_DIR/../lib.sh"

log_section "ip stress (control-plane + traffic; tier1; vNext-only)"

IPTEST_STRESS_SECONDS="${IPTEST_STRESS_SECONDS:-10}"
IPTEST_STRESS_WORKERS="${IPTEST_STRESS_WORKERS:-8}"
IPTEST_STRESS_CONN_BYTES="${IPTEST_STRESS_CONN_BYTES:-64}"
IPTEST_STRESS_PORT_BASE="${IPTEST_STRESS_PORT_BASE:-18100}"
IPTEST_STRESS_PORT_COUNT="${IPTEST_STRESS_PORT_COUNT:-4}"

is_json() {
  printf '%s\n' "$1" | python3 -c 'import sys,json; json.load(sys.stdin)' >/dev/null 2>&1
}

vnext_try_cmd() {
  local cmd="$1"
  local args_json="${2:-}"

  set +e
  local out rc
  if [[ -n "$args_json" ]]; then
    out="$(vnext_ctl_cmd "$cmd" "$args_json" 2>/dev/null)"
  else
    out="$(vnext_ctl_cmd "$cmd" 2>/dev/null)"
  fi
  rc=$?
  set -e

  if ! is_json "$out"; then
    return 2
  fi
  return $rc
}

main() {
  if ! vnext_preflight; then
    exit 77
  fi

  if ! iptest_require_tier1_prereqs; then
    echo "SKIP: tier1 prereqs missing (need root + ip/netns/veth + ping + nc)"
    exit 10
  fi

  if [[ "$IPTEST_STRESS_SECONDS" -lt 1 ]]; then
    echo "SKIP: IPTEST_STRESS_SECONDS must be >= 1 (got $IPTEST_STRESS_SECONDS)"
    exit 10
  fi

  table=""
  cleanup() {
    if [[ -n "$table" ]]; then
      iptest_tier1_teardown "$table" || true
    fi
  }
  trap cleanup EXIT

  table="$(iptest_tier1_setup)" || exit $?

  iptest_reset_baseline

  snort_pid_before="$(iptest_snort_pid 2>/dev/null | tr -d '\r\n' || true)"
  if [[ ! "$snort_pid_before" =~ ^[0-9]+$ || "$snort_pid_before" -le 0 ]]; then
    log_fail "locate snort pid"
    exit 3
  fi
  log_info "snort_pid_before=$snort_pid_before"

  # Start a small set of TCP servers for short-connection traffic.
  ports=()
  for ((i = 0; i < IPTEST_STRESS_PORT_COUNT; i++)); do
    ports+=("$((IPTEST_STRESS_PORT_BASE + i))")
  done
  ports_csv="$(IFS=,; printf '%s' "${ports[*]}")"

  server_pids="$(iptest_tier1_start_tcp_zero_servers "$ports_csv" | tr -d '\r' || true)"
  server_count="$(printf '%s\n' "$server_pids" | sed '/^$/d' | wc -l | tr -d '[:space:]')"
  if [[ ! "$server_count" =~ ^[0-9]+$ || "$server_count" -lt "${#ports[@]}" ]]; then
    log_fail "start tier1 tcp servers"
    echo "ports=$ports_csv"
    echo "server_pids=$server_pids"
    exit 4
  fi
  log_info "tier1 tcp servers ports=$ports_csv pids=$(printf '%s' "$server_pids" | tr '\n' ',')"

  # Baseline rule: allow one port (re-apply will be used for churn).
  rule_allow_on="{\"clientRuleId\":\"stress:r1\",\"family\":\"ipv4\",\"action\":\"allow\",\"priority\":10,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"tcp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${IPTEST_PEER_IP}/32\",\"sport\":\"any\",\"dport\":\"${ports[0]}\"}"
  rule_allow_off="{\"clientRuleId\":\"stress:r1\",\"family\":\"ipv4\",\"action\":\"allow\",\"priority\":10,\"enabled\":0,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"tcp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${IPTEST_PEER_IP}/32\",\"sport\":\"any\",\"dport\":\"${ports[0]}\"}"

  apply_json="$(vnext_ctl_cmd IPRULES.APPLY "{\"app\":{\"uid\":${IPTEST_UID}},\"rules\":[${rule_allow_on}]}" 2>/dev/null)" || {
    echo "BLOCKED: IPRULES.APPLY failed" >&2
    exit 77
  }
  if ! is_json "$apply_json"; then
    echo "BLOCKED: IPRULES.APPLY returned non-JSON" >&2
    exit 77
  fi

  tmpdir="$(mktemp -d)"
  traffic_out="$tmpdir/traffic.txt"
  (
    iptest_tier1_tcp_mix_count_bytes \
      "$IPTEST_STRESS_SECONDS" \
      "$IPTEST_UID" \
      "$IPTEST_STRESS_CONN_BYTES" \
      "$IPTEST_STRESS_WORKERS" \
      "$IPTEST_HOST_IP" \
      "$IPTEST_PEER_IP" \
      "$ports_csv" \
      >"$traffic_out" 2>/dev/null || true
  ) &
  traffic_pid=$!

  errors=0

  try_or_count_error() {
    local cmd="$1"
    local args="${2:-}"
    set +e
    vnext_try_cmd "$cmd" "$args"
    local rc=$?
    set -e
    if [[ $rc -ne 0 ]]; then
      errors=$((errors + 1))
    fi
  }

  until=$((SECONDS + IPTEST_STRESS_SECONDS))
  iter=0
  while [[ $SECONDS -lt $until ]]; do
    if [[ $((iter % 2)) -eq 0 ]]; then
      try_or_count_error IPRULES.APPLY "{\"app\":{\"uid\":${IPTEST_UID}},\"rules\":[${rule_allow_off}]}"
    else
      try_or_count_error IPRULES.APPLY "{\"app\":{\"uid\":${IPTEST_UID}},\"rules\":[${rule_allow_on}]}"
    fi
    try_or_count_error IPRULES.PREFLIGHT

    if [[ $((iter % 10)) -eq 0 ]]; then
      try_or_count_error METRICS.RESET '{"name":"reasons"}'
    fi

    iter=$((iter + 1))
  done

  wait "$traffic_pid" >/dev/null 2>&1 || true

  bytes_actual=0
  connections_actual=0
  if [[ -f "$traffic_out" ]]; then
    set -- $(cat "$traffic_out" 2>/dev/null || true)
    bytes_actual="${1:-0}"
    connections_actual="${2:-0}"
  fi
  rm -rf "$tmpdir" >/dev/null 2>&1 || true

  if [[ ! "$bytes_actual" =~ ^[0-9]+$ ]]; then
    bytes_actual=0
  fi
  if [[ ! "$connections_actual" =~ ^[0-9]+$ ]]; then
    connections_actual=0
  fi

  if [[ "$bytes_actual" -le 0 ]]; then
    log_fail "stress traffic must transfer some bytes"
    echo "bytes_actual=$bytes_actual connections_actual=$connections_actual"
    exit 5
  fi
  log_info "traffic bytes_actual=$bytes_actual connections_actual=$connections_actual"

  snort_pid_after="$(iptest_snort_pid 2>/dev/null | tr -d '\r\n' || true)"
  if [[ ! "$snort_pid_after" =~ ^[0-9]+$ || "$snort_pid_after" -le 0 ]]; then
    log_fail "locate snort pid after stress"
    exit 6
  fi
  if [[ "$snort_pid_after" == "$snort_pid_before" ]]; then
    log_pass "snort pid stable (pid=$snort_pid_after)"
  else
    log_fail "snort pid changed (before=$snort_pid_before after=$snort_pid_after)"
    exit 7
  fi

  if vnext_try_cmd HELLO; then
    log_pass "daemon still responds to HELLO"
  else
    log_fail "daemon not responding to HELLO after stress"
    exit 8
  fi

  reasons_json="$(vnext_ctl_cmd METRICS.GET '{"name":"reasons"}' 2>/dev/null || true)"
  if is_json "$reasons_json"; then
    log_pass "METRICS.GET(reasons) still parseable"
  else
    log_fail "METRICS.GET(reasons) not parseable after stress"
    echo "$reasons_json" | head -c 400 || true
    exit 9
  fi

  # Best-effort: stream output should be parseable JSON frames (response+events).
  set +e
  pkt_sample="$(timeout 2s "$SNORT_CTL" --tcp "127.0.0.1:${VNEXT_PORT}" --compact --follow --max-frames 5 STREAM.START '{"type":"pkt","horizonSec":0,"minSize":0}' 2>/dev/null)"
  rc=$?
  set -e
  if [[ $rc -eq 0 || $rc -eq 124 ]]; then
    if echo "$pkt_sample" | python3 -c 'import sys,json; [json.loads(l) for l in sys.stdin if l.strip()]' >/dev/null 2>&1; then
      log_pass "STREAM.START(pkt) sample still parseable"
    else
      log_fail "STREAM.START(pkt) sample not parseable"
      echo "$pkt_sample" | head -n 5 || true
      exit 10
    fi
  else
    log_fail "STREAM.START(pkt) capture failed (rc=$rc)"
    exit 10
  fi

  if [[ "$errors" -eq 0 ]]; then
    log_pass "stress ok (control-plane errors=0)"
  else
    log_fail "stress saw control-plane errors (errors=$errors)"
    exit 11
  fi

  exit 0
}

main "$@"
