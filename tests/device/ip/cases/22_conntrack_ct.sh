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

get_conntrack_metrics() {
  vnext_rpc_ok METRICS.GET '{"name":"conntrack"}'
}

assert_json_pred() {
  local desc="$1"
  local json="$2"
  local py="$3"
  if printf '%s\n' "$json" | python3 -c "$py" >/dev/null 2>&1; then
    log_pass "$desc"
    return 0
  fi
  log_fail "$desc"
  printf '%s\n' "$json" | head -n 20 | sed 's/^/    /'
  return 1
}

assert_conntrack_fields_numeric() {
  local desc="$1"
  local json="$2"
  assert_json_pred "$desc" "$json" \
    'import sys,json; j=json.load(sys.stdin); c=j["result"]["conntrack"]; required=("totalEntries","creates","expiredRetires","overflowDrops"); assert j["ok"] is True; assert all(isinstance(c.get(k), int) for k in required)'
}

conntrack_metric() {
  local json="$1"
  local field="$2"
  CT_JSON="$json" CT_FIELD="$field" python3 - <<'PY'
import os, json
j = json.loads(os.environ["CT_JSON"])
print(int(j.get("result", {}).get("conntrack", {}).get(os.environ["CT_FIELD"], 0)))
PY
}

assert_conntrack_metric_eq() {
  local desc="$1"
  local json="$2"
  local field="$3"
  local expected="$4"
  local value
  value="$(conntrack_metric "$json" "$field")"
  if [[ "$value" =~ ^[0-9]+$ && "$value" -eq "$expected" ]]; then
    log_pass "$desc ($field=$value)"
    return 0
  fi
  log_fail "$desc"
  echo "    $field expected=$expected actual=$value"
  printf '%s\n' "$json" | head -n 20 | sed 's/^/    /'
  return 1
}

assert_conntrack_metric_ge() {
  local desc="$1"
  local json="$2"
  local field="$3"
  local min="$4"
  local value
  value="$(conntrack_metric "$json" "$field")"
  if [[ "$value" =~ ^[0-9]+$ && "$value" -ge "$min" ]]; then
    log_pass "$desc ($field=$value)"
    return 0
  fi
  log_fail "$desc"
  echo "    $field min=$min actual=$value"
  printf '%s\n' "$json" | head -n 20 | sed 's/^/    /'
  return 1
}

assert_rule_id() {
  local desc="$1"
  local rule_id="$2"
  if [[ "$rule_id" =~ ^[0-9]+$ ]]; then
    log_pass "$desc (ruleId=$rule_id)"
    return 0
  fi
  log_fail "$desc"
  echo "    ruleId=$rule_id"
  return 1
}

rule_stat_from_print() {
  local print_json="$1"
  local rule_id="$2"
  local stat_name="$3"
  PRINT_JSON="$print_json" RULE_ID="$rule_id" STAT_NAME="$stat_name" python3 - <<'PY'
import os, json
j = json.loads(os.environ["PRINT_JSON"])
rid = int(os.environ["RULE_ID"])
stat = os.environ["STAT_NAME"]
for r in j.get("result", {}).get("rules", []):
    if int(r.get("ruleId", -1)) == rid:
        print(int(r.get("stats", {}).get(stat, 0)))
        raise SystemExit(0)
print(0)
PY
}

assert_rule_stat_ge_from_print() {
  local desc="$1"
  local print_json="$2"
  local rule_id="$3"
  local stat_name="$4"
  local min="$5"
  local value
  value="$(rule_stat_from_print "$print_json" "$rule_id" "$stat_name")"
  if [[ "$value" =~ ^[0-9]+$ && "$value" -ge "$min" ]]; then
    log_pass "$desc ($stat_name=$value)"
    return 0
  fi
  log_fail "$desc"
  echo "    ruleId=$rule_id $stat_name min=$min actual=$value"
  printf '%s\n' "$print_json" | head -n 40 | sed 's/^/    /'
  return 1
}

assert_preflight_ct_active() {
  local desc="$1"
  local preflight_json
  preflight_json="$(vnext_rpc_ok IPRULES.PREFLIGHT)" || return $?
  assert_json_pred "$desc" "$preflight_json" \
    'import sys,json; j=json.load(sys.stdin); s=j["result"]["summary"]; assert j["ok"] is True; assert int(s["ctRulesTotal"]) >= 1; assert int(s["ctUidsTotal"]) >= 1'
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
    iptest_reset_baseline >/dev/null 2>&1 || true
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
  conntrack="$(get_conntrack_metrics)" || exit $?
  assert_conntrack_fields_numeric "VNXCT-01 METRICS.GET(conntrack) shape after RESETALL" "$conntrack" || exit 1
  assert_conntrack_metric_eq "VNXCT-01b conntrack totalEntries reset before allow" "$conntrack" totalEntries 0 || exit 1
  assert_conntrack_metric_eq "VNXCT-01c conntrack creates reset before allow" "$conntrack" creates 0 || exit 1

  rules_allow="[{\"clientRuleId\":\"ct:new-orig\",\"action\":\"allow\",\"priority\":200,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"tcp\",\"ct\":{\"state\":\"new\",\"direction\":\"orig\"},\"src\":\"any\",\"dst\":\"${IPTEST_PEER_IP}/32\",\"sport\":\"any\",\"dport\":\"${IPTEST_CT_PORT}\"},{\"clientRuleId\":\"ct:est-reply\",\"action\":\"allow\",\"priority\":200,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"in\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"tcp\",\"ct\":{\"state\":\"established\",\"direction\":\"reply\"},\"src\":\"${IPTEST_PEER_IP}/32\",\"dst\":\"any\",\"sport\":\"${IPTEST_CT_PORT}\",\"dport\":\"any\"}]"
  apply="$(vnext_rpc_ok IPRULES.APPLY "{\"app\":{\"uid\":${IPTEST_UID}},\"rules\":${rules_allow}}")" || exit $?
  rid_new="$(rule_id_from_apply "$apply" "ct:new-orig" | tr -d '\r\n')"
  rid_est="$(rule_id_from_apply "$apply" "ct:est-reply" | tr -d '\r\n')"
  assert_rule_id "VNXCT-02 IPRULES.APPLY returns ct.new+orig ruleId" "$rid_new" || exit 1
  assert_rule_id "VNXCT-02b IPRULES.APPLY returns ct.established+reply ruleId" "$rid_est" || exit 1
  assert_preflight_ct_active "VNXCT-03 IPRULES.PREFLIGHT reports active ct consumers" || exit $?

  count="$(iptest_tier1_tcp_count_bytes "$IPTEST_CT_PORT" "$IPTEST_CT_BYTES" "$IPTEST_UID" | tr -d '\r\n ' || true)"
  if [[ ! "$count" =~ ^[0-9]+$ || "$count" -le 0 ]]; then
    echo "SKIP: tier1 tcp traffic unavailable for uid=$IPTEST_UID (count=$count); try setting IPTEST_APP_UID to a network-capable app uid"
    exit 10
  fi
  if [[ "$count" -ne "$IPTEST_CT_BYTES" ]]; then
    log_fail "VNXCT-04 TCP payload read returns expected bytes"
    echo "    expected=$IPTEST_CT_BYTES actual=$count"
    exit 4
  fi
  log_pass "VNXCT-04 TCP payload read returns expected bytes (count=$count)"

  printed="$(print_rules)" || exit $?
  assert_rule_stat_ge_from_print "VNXCT-05 ct.new+orig rule hitPackets increments" "$printed" "$rid_new" hitPackets 1 || exit 5
  assert_rule_stat_ge_from_print "VNXCT-05b ct.established+reply rule hitPackets increments" "$printed" "$rid_est" hitPackets 1 || exit 6

  conntrack="$(get_conntrack_metrics)" || exit $?
  assert_conntrack_fields_numeric "VNXCT-06 METRICS.GET(conntrack) shape after allow" "$conntrack" || exit 1
  assert_conntrack_metric_ge "VNXCT-06b conntrack creates after allow" "$conntrack" creates 1 || exit 1
  assert_conntrack_metric_ge "VNXCT-06c conntrack totalEntries after allow" "$conntrack" totalEntries 1 || exit 1

  # Now verify enforce verdict: BLOCK new outbound packets and observe drop.
  iptest_reset_baseline
  conntrack="$(get_conntrack_metrics)" || exit $?
  assert_conntrack_fields_numeric "VNXCT-07 METRICS.GET(conntrack) shape after block RESETALL" "$conntrack" || exit 1
  assert_conntrack_metric_eq "VNXCT-07b conntrack totalEntries reset before block" "$conntrack" totalEntries 0 || exit 1
  assert_conntrack_metric_eq "VNXCT-07c conntrack creates reset before block" "$conntrack" creates 0 || exit 1

  rules_block="[{\"clientRuleId\":\"ct:block-new\",\"action\":\"block\",\"priority\":500,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"tcp\",\"ct\":{\"state\":\"new\",\"direction\":\"orig\"},\"src\":\"any\",\"dst\":\"${IPTEST_PEER_IP}/32\",\"sport\":\"any\",\"dport\":\"${IPTEST_CT_PORT}\"}]"
  apply2="$(vnext_rpc_ok IPRULES.APPLY "{\"app\":{\"uid\":${IPTEST_UID}},\"rules\":${rules_block}}")" || exit $?
  rid_block="$(rule_id_from_apply "$apply2" "ct:block-new" | tr -d '\r\n')"
  assert_rule_id "VNXCT-08 IPRULES.APPLY returns ct.block-new ruleId" "$rid_block" || exit 1
  assert_preflight_ct_active "VNXCT-08b IPRULES.PREFLIGHT reports block ct consumer" || exit $?

  count2="$(iptest_tier1_tcp_count_bytes "$IPTEST_CT_PORT" "$IPTEST_CT_BYTES" "$IPTEST_UID" | tr -d '\r\n ' || true)"
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
  log_pass "VNXCT-09 ct.new+orig block rule drops tcp (count=$count2)"

  reasons="$(get_reasons)" || exit $?
  blocked_pkts="$(vnext_json_get "$reasons" "result.reasons.IP_RULE_BLOCK.packets")"
  if [[ ! "$blocked_pkts" =~ ^[0-9]+$ || "$blocked_pkts" -lt 1 ]]; then
    log_fail "VNXCT-10 METRICS.GET(reasons) shows IP_RULE_BLOCK packets"
    echo "blocked_pkts=$blocked_pkts"
    exit 9
  fi
  log_pass "VNXCT-10 METRICS.GET(reasons) shows IP_RULE_BLOCK packets (packets=$blocked_pkts)"

  printed="$(print_rules)" || exit $?
  assert_rule_stat_ge_from_print "VNXCT-11 ct.new+orig block rule hitPackets increments" "$printed" "$rid_block" hitPackets 1 || exit 10

  conntrack="$(get_conntrack_metrics)" || exit $?
  assert_conntrack_fields_numeric "VNXCT-12 METRICS.GET(conntrack) shape after block" "$conntrack" || exit 1
  assert_conntrack_metric_eq "VNXCT-12b conntrack creates stays zero after block" "$conntrack" creates 0 || exit 1
  assert_conntrack_metric_eq "VNXCT-12c conntrack totalEntries stays zero after block" "$conntrack" totalEntries 0 || exit 1

  log_pass "conntrack ct.* ok"
  exit 0
}

main "$@"
