#!/bin/bash

set -euo pipefail
umask 077

CASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IPMOD_DIR="$(cd "$CASE_DIR/.." && pwd)"
source "$IPMOD_DIR/lib.sh"

log_section "ip longrun (tier1; record-first; vNext-only)"

IPTEST_LONGRUN_SECONDS="${IPTEST_LONGRUN_SECONDS:-600}"
IPTEST_LONGRUN_HEALTH_EVERY="${IPTEST_LONGRUN_HEALTH_EVERY:-30}"
IPTEST_LONGRUN_WORKERS="${IPTEST_LONGRUN_WORKERS:-8}"
IPTEST_LONGRUN_CONN_BYTES="${IPTEST_LONGRUN_CONN_BYTES:-256}"
IPTEST_LONGRUN_PORT_BASE="${IPTEST_LONGRUN_PORT_BASE:-18200}"
IPTEST_LONGRUN_PORT_COUNT="${IPTEST_LONGRUN_PORT_COUNT:-4}"

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

rule_id_from_apply() {
  local apply_json="$1"
  local client_rule_id="$2"
  APPLY_JSON="$apply_json" CLIENT_RULE_ID="$client_rule_id" python3 - <<'PY'
import os, json
j = json.loads(os.environ["APPLY_JSON"])
cid = os.environ["CLIENT_RULE_ID"]
for r in j.get("result", {}).get("rules", []):
    if r.get("clientRuleId") == cid:
        print(r.get("ruleId", ""))
        raise SystemExit(0)
print("")
PY
}

for v in IPTEST_LONGRUN_SECONDS IPTEST_LONGRUN_HEALTH_EVERY IPTEST_LONGRUN_WORKERS IPTEST_LONGRUN_CONN_BYTES IPTEST_LONGRUN_PORT_BASE IPTEST_LONGRUN_PORT_COUNT; do
  if ! [[ "${!v}" =~ ^[0-9]+$ ]]; then
    echo "SKIP: ${v} must be a non-negative integer (got: ${!v})"
    exit 10
  fi
done

if [[ "$IPTEST_LONGRUN_SECONDS" -lt 30 ]]; then
  echo "SKIP: IPTEST_LONGRUN_SECONDS must be >= 30 (got $IPTEST_LONGRUN_SECONDS)"
  exit 10
fi
if [[ "$IPTEST_LONGRUN_HEALTH_EVERY" -lt 5 ]]; then
  echo "SKIP: IPTEST_LONGRUN_HEALTH_EVERY must be >= 5 (got $IPTEST_LONGRUN_HEALTH_EVERY)"
  exit 10
fi
if [[ "$IPTEST_LONGRUN_WORKERS" -lt 1 || "$IPTEST_LONGRUN_CONN_BYTES" -lt 1 || "$IPTEST_LONGRUN_PORT_COUNT" -lt 1 ]]; then
  echo "SKIP: LONGRUN_WORKERS/CONN_BYTES/PORT_COUNT must all be >= 1"
  exit 10
fi

main() {
  if ! vnext_preflight; then
    exit 77
  fi

  if ! iptest_require_tier1_prereqs; then
    echo "SKIP: tier1 prereqs missing (need root + ip/netns/veth + ping + nc)"
    exit 10
  fi

  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  serial="$(adb_target_desc 2>/dev/null | tr -d '\r\n' || true)"
  serial="${serial:-unknown}"
  out_dir="$IPMOD_DIR/records/ip-longrun-${ts}_${serial}"
  mkdir -p "$out_dir"
  log_path="$out_dir/longrun.log"

  exec > >(tee -a "$log_path") 2>&1

  cat >"$out_dir/meta.txt" <<EOF
timestamp=${ts}
serial=${serial}
uid=${IPTEST_UID}
seconds=${IPTEST_LONGRUN_SECONDS}
health_every=${IPTEST_LONGRUN_HEALTH_EVERY}
workers=${IPTEST_LONGRUN_WORKERS}
conn_bytes=${IPTEST_LONGRUN_CONN_BYTES}
port_base=${IPTEST_LONGRUN_PORT_BASE}
port_count=${IPTEST_LONGRUN_PORT_COUNT}
EOF

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

  proc_before="$out_dir/snort_proc_before.txt"
  proc_after="$out_dir/snort_proc_after.txt"
  proc_delta="$out_dir/snort_proc_delta.txt"
  iptest_capture_snort_proc_snapshot >"$proc_before" || true

  ports=()
  for ((i = 0; i < IPTEST_LONGRUN_PORT_COUNT; i++)); do
    ports+=("$((IPTEST_LONGRUN_PORT_BASE + i))")
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

  # Baseline rule (used for churn by re-applying enabled=0/1).
  rule_on="{\"clientRuleId\":\"longrun:r1\",\"family\":\"ipv4\",\"action\":\"allow\",\"priority\":10,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"tcp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${IPTEST_PEER_IP}/32\",\"sport\":\"any\",\"dport\":\"${ports[0]}\"}"
  rule_off="{\"clientRuleId\":\"longrun:r1\",\"family\":\"ipv4\",\"action\":\"allow\",\"priority\":10,\"enabled\":0,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"tcp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${IPTEST_PEER_IP}/32\",\"sport\":\"any\",\"dport\":\"${ports[0]}\"}"

  apply="$(vnext_ctl_cmd IPRULES.APPLY "{\"app\":{\"uid\":${IPTEST_UID}},\"rules\":[${rule_on}]}" 2>/dev/null)" || {
    echo "BLOCKED: IPRULES.APPLY failed" >&2
    exit 77
  }
  if ! is_json "$apply"; then
    echo "BLOCKED: IPRULES.APPLY returned non-JSON" >&2
    exit 77
  fi
  rid="$(rule_id_from_apply "$apply" "longrun:r1" | tr -d '\r\n')"
  log_info "baseline ruleId=$rid port=${ports[0]}"

  traffic_out="$out_dir/traffic.txt"
  (
    iptest_tier1_tcp_mix_count_bytes \
      "$IPTEST_LONGRUN_SECONDS" \
      "$IPTEST_UID" \
      "$IPTEST_LONGRUN_CONN_BYTES" \
      "$IPTEST_LONGRUN_WORKERS" \
      "$IPTEST_HOST_IP" \
      "$IPTEST_PEER_IP" \
      "$ports_csv" \
      >"$traffic_out" 2>/dev/null || true
  ) &
  traffic_pid=$!

  errors=0
  try_cmd() {
    local cmd="$1"
    local args="${2:-}"
    set +e
    vnext_try_cmd "$cmd" "$args"
    local rc=$?
    set -e
    if [[ $rc -ne 0 ]]; then
      errors=$((errors + 1))
      echo "WARN: cmd failed (rc=$rc): $cmd" >&2
    fi
  }

  health_fail() {
    local reason="$1"
    errors=$((errors + 1))
    echo "HEALTH_FAIL: $reason" >&2
  }

  health_check() {
    local now_pid reasons_json

    now_pid="$(iptest_snort_pid 2>/dev/null | tr -d '\r\n' || true)"
    if [[ ! "$now_pid" =~ ^[0-9]+$ || "$now_pid" -le 0 ]]; then
      health_fail "snort pid missing"
      return 1
    fi
    if [[ "$now_pid" != "$snort_pid_before" ]]; then
      health_fail "snort pid changed (before=$snort_pid_before now=$now_pid)"
      return 1
    fi

    set +e
    vnext_try_cmd HELLO
    local hello_rc=$?
    set -e
    if [[ $hello_rc -ne 0 ]]; then
      health_fail "HELLO not ok (rc=$hello_rc)"
      return 1
    fi

    set +e
    reasons_json="$(vnext_ctl_cmd METRICS.GET '{"name":"reasons"}' 2>/dev/null)"
    local reasons_rc=$?
    set -e
    if [[ $reasons_rc -ne 0 ]] || ! is_json "$reasons_json"; then
      health_fail "METRICS.GET(reasons) failed (rc=$reasons_rc)"
      return 1
    fi

    return 0
  }

  start_s="$(date +%s)"
  until_s=$((start_s + IPTEST_LONGRUN_SECONDS))
  next_health_s=$((start_s + IPTEST_LONGRUN_HEALTH_EVERY))
  iter=0

  while [[ "$(date +%s)" -lt "$until_s" ]]; do
    if [[ $((iter % 2)) -eq 0 ]]; then
      try_cmd IPRULES.APPLY "{\"app\":{\"uid\":${IPTEST_UID}},\"rules\":[${rule_off}]}"
    else
      try_cmd IPRULES.APPLY "{\"app\":{\"uid\":${IPTEST_UID}},\"rules\":[${rule_on}]}"
    fi

    if [[ $((iter % 10)) -eq 0 ]]; then
      try_cmd IPRULES.PREFLIGHT
      try_cmd METRICS.RESET '{"name":"reasons"}'
    fi

    now_s="$(date +%s)"
    if [[ "$now_s" -ge "$next_health_s" ]]; then
      if health_check; then
        log_info "health ok (t=$((now_s - start_s))s)"
      else
        log_fail "health check failed (t=$((now_s - start_s))s)"
      fi
      next_health_s=$((now_s + IPTEST_LONGRUN_HEALTH_EVERY))
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

  if [[ ! "$bytes_actual" =~ ^[0-9]+$ ]]; then
    bytes_actual=0
  fi
  if [[ ! "$connections_actual" =~ ^[0-9]+$ ]]; then
    connections_actual=0
  fi

  if [[ "$bytes_actual" -le 0 ]]; then
    log_fail "longrun traffic must transfer some bytes"
    echo "bytes_actual=$bytes_actual connections_actual=$connections_actual"
    exit 5
  fi
  log_info "traffic bytes_actual=$bytes_actual connections_actual=$connections_actual"

  iptest_capture_snort_proc_snapshot >"$proc_after" || true
  iptest_snort_proc_delta_summary "$proc_before" "$proc_after" >"$proc_delta" || true

  if [[ "$errors" -eq 0 ]]; then
    log_pass "longrun ok (errors=0; records_dir=$out_dir)"
    exit 0
  fi

  log_fail "longrun finished with errors=$errors (records_dir=$out_dir)"
  exit 11
}

main "$@"
