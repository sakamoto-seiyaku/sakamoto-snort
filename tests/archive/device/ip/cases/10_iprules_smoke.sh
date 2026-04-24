#!/bin/bash

set -euo pipefail

CASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$CASE_DIR/../lib_legacy.sh"

log_section "iprules smoke (tier1)"

if ! init_test_env; then
  exit 2
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

iptest_reset_baseline_legacy

rid="$(send_cmd "IPRULES.ADD ${IPTEST_UID} action=allow priority=100 dir=out proto=icmp dst=${IPTEST_PEER_IP}/32")"
if [[ ! "$rid" =~ ^[0-9]+$ ]]; then
  log_fail "ADD enforce allow rule"
  echo "got: $rid"
  exit 3
fi
log_info "ruleId=$rid"

# Capture a pktstream sample while triggering a ping.
adb_cmd shell "sh -c $(shell_single_quote "sleep 1; ping -c 1 -W 1 \"$IPTEST_PEER_IP\" >/dev/null 2>&1 || true")" >/dev/null 2>&1 &
ping_pid=$!
sample="$(stream_sample "PKTSTREAM.START 0 0" "PKTSTREAM.STOP" 3)"
wait "$ping_pid" >/dev/null 2>&1 || true

set +e
RID="$rid" PKT_UID="$IPTEST_UID" PEER="$IPTEST_PEER_IP" python3 -c '
import json, os, sys
rid = int(os.environ["RID"])
uid = int(os.environ["PKT_UID"])
peer = os.environ["PEER"]
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        obj = json.loads(line)
    except Exception:
        continue
    if obj.get("uid") != uid:
        continue
    if obj.get("direction") != "out":
        continue
    if obj.get("dstIp") != peer:
        continue
    if obj.get("reasonId") != "IP_RULE_ALLOW":
        continue
    if int(obj.get("ruleId", -1)) != rid:
        continue
    raise SystemExit(0)
raise SystemExit(2)
' <<<"$sample"
rc=$?
set -e
if [[ $rc -ne 0 ]]; then
  log_fail "pktstream contains IP_RULE_ALLOW + ruleId for tier1 ping"
  echo "$sample" | rg -n "\"dstIp\":\"${IPTEST_PEER_IP}\"" | head -n 10 || true
  exit 4
fi
log_pass "pktstream contains IP_RULE_ALLOW + ruleId"

hit_before="$(json_get "$(send_cmd "IPRULES.PRINT RULE ${rid}")" "rules.0.stats.hitPackets")"
if [[ ! "$hit_before" =~ ^[0-9]+$ || "$hit_before" -lt 1 ]]; then
  log_fail "per-rule stats hitPackets increments"
  echo "hitPackets=$hit_before"
  exit 5
fi
log_pass "per-rule stats hitPackets increments (hitPackets=$hit_before)"

# Disable IPRULES and ensure the same traffic no longer hits the rule.
assert_ok "IPRULES 0" "IPRULES=0"
adb_cmd shell "sh -c $(shell_single_quote "ping -c 1 -W 1 \"$IPTEST_PEER_IP\" >/dev/null 2>&1 || true")" >/dev/null 2>&1

hit_after="$(json_get "$(send_cmd "IPRULES.PRINT RULE ${rid}")" "rules.0.stats.hitPackets")"
if [[ "$hit_after" != "$hit_before" ]]; then
  log_fail "IPRULES=0 must bypass (no stats growth)"
  echo "hitPackets before=$hit_before after=$hit_after"
  exit 6
fi
log_pass "IPRULES=0 bypass (no stats growth)"

log_pass "iprules smoke ok"
exit 0
