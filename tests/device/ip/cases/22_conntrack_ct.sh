#!/bin/bash

set -euo pipefail

CASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$CASE_DIR/../lib.sh"

log_section "conntrack ct.* (tier1; vNext-only)"

IPTEST_CT_PORT="${IPTEST_CT_PORT:-18081}"
IPTEST_CT_BYTES="${IPTEST_CT_BYTES:-65536}"

is_json() {
  printf '%s\n' "$1" | python3 -c 'import sys,json; json.load(sys.stdin)' >/dev/null 2>&1
}

vnext_rpc_ok() {
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
    echo "BLOCKED: vNext $cmd transport failed (rc=$rc)" >&2
    return 77
  fi
  if [[ $rc -ne 0 ]]; then
    log_fail "vNext $cmd returns ok"
    printf '%s\n' "$out" | head -n 3 | sed 's/^/    /'
    return 1
  fi
  printf '%s\n' "$out"
  return 0
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

rule_hit_packets() {
  local print_json="$1"
  local rule_id="$2"
  PRINT_JSON="$print_json" RULE_ID="$rule_id" python3 - <<'PY'
import os, json
j = json.loads(os.environ["PRINT_JSON"])
rid = int(os.environ["RULE_ID"])
for r in j.get("result", {}).get("rules", []):
    if int(r.get("ruleId", -1)) == rid:
        print(int(r.get("stats", {}).get("hitPackets", 0)))
        raise SystemExit(0)
print(0)
PY
}

print_rules() {
  vnext_rpc_ok IPRULES.PRINT "{\"app\":{\"uid\":${IPTEST_UID}}}"
}

get_reasons() {
  vnext_rpc_ok METRICS.GET '{"name":"reasons"}'
}

main() {
  if ! vnext_preflight; then
    exit 77
  fi

  if ! iptest_require_tier1_prereqs; then
    echo "SKIP: tier1 prereqs missing (need root + ip/netns/veth + ping + nc)"
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

  server_pid="$(iptest_tier1_start_tcp_zero_server "$IPTEST_CT_PORT" | tr -d '\r\n' || true)"
  if [[ ! "$server_pid" =~ ^[0-9]+$ ]]; then
    log_fail "start tier1 tcp server for ct"
    echo "server_pid=$server_pid"
    exit 3
  fi
  log_info "tier1 tcp server pid=$server_pid port=$IPTEST_CT_PORT"

  iptest_reset_baseline

  rules_allow="[{\"clientRuleId\":\"ct:new-orig\",\"action\":\"allow\",\"priority\":200,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"tcp\",\"ct\":{\"state\":\"new\",\"direction\":\"orig\"},\"src\":\"any\",\"dst\":\"${IPTEST_PEER_IP}/32\",\"sport\":\"any\",\"dport\":\"${IPTEST_CT_PORT}\"},{\"clientRuleId\":\"ct:est-reply\",\"action\":\"allow\",\"priority\":200,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"in\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"tcp\",\"ct\":{\"state\":\"established\",\"direction\":\"reply\"},\"src\":\"${IPTEST_PEER_IP}/32\",\"dst\":\"any\",\"sport\":\"${IPTEST_CT_PORT}\",\"dport\":\"any\"}]"
  apply="$(vnext_rpc_ok IPRULES.APPLY "{\"app\":{\"uid\":${IPTEST_UID}},\"rules\":${rules_allow}}")" || exit $?
  rid_new="$(rule_id_from_apply "$apply" "ct:new-orig" | tr -d '\r\n')"
  rid_est="$(rule_id_from_apply "$apply" "ct:est-reply" | tr -d '\r\n')"

  count="$(iptest_tier1_tcp_count_bytes "$IPTEST_CT_PORT" "$IPTEST_CT_BYTES" "$IPTEST_UID" | tr -d '\r\n' || true)"
  if [[ ! "$count" =~ ^[0-9]+$ || "$count" -le 0 ]]; then
    echo "SKIP: tier1 tcp traffic unavailable for uid=$IPTEST_UID (count=$count); try setting IPTEST_APP_UID to a network-capable app uid"
    exit 10
  fi
  log_pass "tcp read produces bytes (count=$count)"

  printed="$(print_rules)" || exit $?
  hit_new="$(rule_hit_packets "$printed" "$rid_new")"
  hit_est="$(rule_hit_packets "$printed" "$rid_est")"
  if [[ "${hit_new:-0}" -ge 1 ]]; then
    log_pass "ct.new+orig rule hitPackets increments (hitPackets=$hit_new)"
  else
    log_fail "ct.new+orig rule hitPackets increments (hitPackets=$hit_new)"
    exit 5
  fi
  if [[ "${hit_est:-0}" -ge 1 ]]; then
    log_pass "ct.established+reply rule hitPackets increments (hitPackets=$hit_est)"
  else
    log_fail "ct.established+reply rule hitPackets increments (hitPackets=$hit_est)"
    exit 6
  fi

  # Now verify enforce verdict: BLOCK new outbound packets and observe drop.
  iptest_reset_baseline

  rules_block="[{\"clientRuleId\":\"ct:block-new\",\"action\":\"block\",\"priority\":500,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"tcp\",\"ct\":{\"state\":\"new\",\"direction\":\"orig\"},\"src\":\"any\",\"dst\":\"${IPTEST_PEER_IP}/32\",\"sport\":\"any\",\"dport\":\"${IPTEST_CT_PORT}\"}]"
  apply2="$(vnext_rpc_ok IPRULES.APPLY "{\"app\":{\"uid\":${IPTEST_UID}},\"rules\":${rules_block}}")" || exit $?
  rid_block="$(rule_id_from_apply "$apply2" "ct:block-new" | tr -d '\r\n')"

  count2="$(iptest_tier1_tcp_count_bytes "$IPTEST_CT_PORT" "$IPTEST_CT_BYTES" "$IPTEST_UID" | tr -d '\r\n' || true)"
  if [[ ! "$count2" =~ ^[0-9]+$ ]]; then
    log_fail "tcp read returns numeric count under block"
    echo "count=$count2"
    exit 7
  fi
  if [[ "$count2" -ne 0 ]]; then
    log_fail "ct.new+orig block rule drops tcp (expected 0 bytes)"
    echo "count=$count2"
    exit 8
  fi
  log_pass "ct.new+orig block rule drops tcp (count=$count2)"

  reasons="$(get_reasons)" || exit $?
  blocked_pkts="$(vnext_json_get "$reasons" "result.reasons.IP_RULE_BLOCK.packets")"
  if [[ ! "$blocked_pkts" =~ ^[0-9]+$ || "$blocked_pkts" -lt 1 ]]; then
    log_fail "METRICS.GET(reasons) shows IP_RULE_BLOCK packets"
    echo "blocked_pkts=$blocked_pkts"
    exit 9
  fi
  log_pass "METRICS.GET(reasons) shows IP_RULE_BLOCK packets (packets=$blocked_pkts)"

  printed="$(print_rules)" || exit $?
  hit_block="$(rule_hit_packets "$printed" "$rid_block")"
  if [[ ! "$hit_block" =~ ^[0-9]+$ || "$hit_block" -lt 1 ]]; then
    log_fail "ct.new+orig block rule hitPackets increments"
    echo "hitPackets=$hit_block"
    exit 10
  fi
  log_pass "ct.new+orig block rule hitPackets increments (hitPackets=$hit_block)"

  log_pass "conntrack ct.* ok"
  exit 0
}

main "$@"
