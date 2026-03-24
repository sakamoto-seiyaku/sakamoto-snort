#!/bin/bash

set -euo pipefail

CASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$CASE_DIR/../lib.sh"

log_section "ip-leak (best-effort)"

resolve_ipv4_via_ping() {
  local host="$1"
  local line
  line="$(adb_cmd shell "ping -4 -c 1 -W 1 \"$host\" 2>/dev/null | head -n 1" 2>/dev/null || true)"
  echo "$line" | sed -n 's/.*(\([0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+\)).*/\1/p' | head -n 1
}

get_reason_packets() {
  local reason="$1"
  json_get "$(send_cmd "METRICS.REASONS")" "reasons.${reason}.packets"
}

get_rule_stat() {
  local rid="$1"
  local stat="$2"
  json_get "$(send_cmd "IPRULES.PRINT RULE ${rid}")" "rules.0.stats.${stat}"
}

if ! init_test_env; then
  exit 2
fi

if ! adb_cmd shell "command -v ping >/dev/null 2>&1"; then
  echo "SKIP: device missing ping"
  exit 10
fi

leakDomain="${IPTEST_LEAK_DOMAIN:-example.com}"
leakIp="$(resolve_ipv4_via_ping "$leakDomain" | tr -d '\r\n' || true)"
if [[ -z "$leakIp" ]]; then
  echo "SKIP: could not resolve $leakDomain to IPv4"
  exit 10
fi
log_info "leakDomain=$leakDomain leakIp=$leakIp uid=$IPTEST_UID"

# Warm DNS mapping for leakIp -> leakDomain so legacy ip-leak path can trigger validIP.
iptest_reset_baseline
expect_ok "BLOCKIPLEAKS 0" "BLOCKIPLEAKS off (warm mapping)"
adb_cmd shell "ping -c 1 -W 1 \"$leakDomain\" >/dev/null 2>&1 || true" >/dev/null 2>&1
sleep 1

expect_ok "CUSTOMLIST.ON ${IPTEST_UID}" "CUSTOMLIST.ON"
expect_ok "BLACKLIST.ADD ${IPTEST_UID} ${leakDomain}" "BLACKLIST.ADD app-specific (ip-leak)"
expect_ok "BLOCKIPLEAKS 1" "BLOCKIPLEAKS on"

wouldDropRid="$(expect_uint "IPRULES.ADD ${IPTEST_UID} action=block priority=10 enforce=0 log=1 proto=icmp" "ADD would-block rule (drop case)")"

expect_ok "METRICS.REASONS.RESET" "METRICS.REASONS.RESET (drop case)"
adb_cmd shell "sh -c $(shell_single_quote "sleep 1; ping -c 1 -W 1 \"$leakIp\" >/dev/null 2>&1 || true")" >/dev/null 2>&1 &
ping_pid=$!
pktSample="$(stream_sample "PKTSTREAM.START 0 0" "PKTSTREAM.STOP" 3)"
wait "$ping_pid" >/dev/null 2>&1 || true

ipLeakPackets="$(get_reason_packets "IP_LEAK_BLOCK" | tr -d '\r\n' || true)"
if [[ "${ipLeakPackets:-0}" -lt 1 ]]; then
  echo "SKIP: IP_LEAK_BLOCK not observed; environment may not provide valid DNS->IP mapping"
  exit 10
fi
log_pass "IP_LEAK_BLOCK observed (packets=$ipLeakPackets)"

wouldDropHits="$(get_rule_stat "$wouldDropRid" "wouldHitPackets")"
if [[ "${wouldDropHits:-0}" -eq 0 ]]; then
  log_pass "wouldHitPackets stays 0 when final verdict is DROP"
else
  log_fail "wouldHitPackets grew unexpectedly on DROP (wouldHitPackets=$wouldDropHits)"
  exit 4
fi

if echo "$pktSample" | python3 -c '
import json
import sys

uid = int(sys.argv[1])
target = sys.argv[2]

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        obj = json.loads(line)
    except Exception:
        continue
    if obj.get("uid") != uid or obj.get("direction") != "out" or obj.get("dstIp") != target:
        continue
    if obj.get("protocol") != "icmp":
        continue
    assert bool(obj.get("accepted")) is False
    assert obj.get("reasonId") == "IP_LEAK_BLOCK"
    assert "wouldRuleId" not in obj
    assert "wouldDrop" not in obj
    raise SystemExit(0)
raise SystemExit(2)
' "$IPTEST_UID" "$leakIp"
then
  log_pass "PKTSTREAM suppresses wouldRuleId overlay when final verdict is DROP"
else
  log_fail "PKTSTREAM incorrectly emitted wouldRuleId overlay on DROP"
  exit 5
fi

log_pass "ip-leak ok"
exit 0
