#!/bin/bash

set -euo pipefail

CASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$CASE_DIR/../lib.sh"

log_section "iface block (tier1)"

get_reason_packets() {
  local reason="$1"
  json_get "$(send_cmd "METRICS.REASONS")" "reasons.${reason}.packets"
}

get_rule_stat() {
  local rid="$1"
  local stat="$2"
  json_get "$(send_cmd "IPRULES.PRINT RULE ${rid}")" "rules.0.stats.${stat}"
}

iface_kind_of() {
  local iface_name="$1"
  local ifaces_json
  ifaces_json="$(send_cmd "IFACES.PRINT" 10 || true)"
  printf '%s' "$ifaces_json" | python3 -c '
import json
import sys

name = sys.argv[1]
try:
    data = json.load(sys.stdin)
except Exception:
    print("")
    raise SystemExit(0)
for it in data.get("ifaces", []):
    if it.get("name") == name:
        print(it.get("kind", ""))
        raise SystemExit(0)
print("")
' "$iface_name"
}

iface_kind_mask() {
  local kind="$1"
  case "$kind" in
    wifi) echo 1 ;;
    data) echo 2 ;;
    vpn) echo 4 ;;
    unmanaged) echo 128 ;;
    *) echo 0 ;;
  esac
}

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

kind="$(iface_kind_of "$IPTEST_VETH0" | tr -d '\r\n' || true)"
if [[ -z "$kind" && "$IPTEST_VETH0" == iptest_veth* ]]; then
  kind="unmanaged"
  log_info "IFACES.PRINT kind unavailable; fallback kind=${kind} for ${IPTEST_VETH0}"
fi
mask="$(iface_kind_mask "$kind" | tr -d '\r\n' || true)"
if [[ ! "$mask" =~ ^[0-9]+$ || "$mask" -le 0 ]]; then
  echo "SKIP: could not derive iface kind mask for $IPTEST_VETH0 (kind='$kind')"
  exit 10
fi
log_info "iface=$IPTEST_VETH0 kind=$kind mask=$mask uid=$IPTEST_UID"

# ----------------------------------------------------------------------
# IFACE_BLOCK takes precedence and does not attribute ruleId/wouldRuleId
# ----------------------------------------------------------------------
iptest_reset_baseline
expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"

rid="$(expect_uint "IPRULES.ADD ${IPTEST_UID} action=allow priority=100 proto=icmp dir=out dst=${IPTEST_PEER_IP}/32" "ADD enforce allow (should be suppressed by IFACE_BLOCK)")"
expect_ok "BLOCKIFACE ${IPTEST_UID} ${mask}" "BLOCKIFACE set"

tmp_pkt="$(mktemp)"
stream_sample "PKTSTREAM.START 0 0" "PKTSTREAM.STOP" 6 >"$tmp_pkt" &
pkt_pid=$!
sleep 2
iptest_tier1_ping_once
sleep 0.2
iptest_tier1_ping_once
sleep 0.2
iptest_tier1_ping_once
wait "$pkt_pid" >/dev/null 2>&1 || true

ifacePackets="$(get_reason_packets "IFACE_BLOCK" | tr -d '\r\n' || true)"
if [[ "${ifacePackets:-0}" -ge 1 ]]; then
  log_pass "IFACE_BLOCK observed (packets=$ifacePackets)"
else
  log_fail "IFACE_BLOCK not observed (packets=$ifacePackets)"
  exit 3
fi

if [[ "$(get_rule_stat "$rid" "hitPackets")" -eq 0 ]]; then
  log_pass "IFACE_BLOCK bypasses iprules evaluation (rule hitPackets stays 0)"
else
  log_fail "iprules stats grew under IFACE_BLOCK (hitPackets=$(get_rule_stat "$rid" "hitPackets"))"
  exit 4
fi

if python3 - "$tmp_pkt" "$IPTEST_UID" "$IPTEST_PEER_IP" <<'PY'
import json
import sys

path = sys.argv[1]
uid = int(sys.argv[2])
peer = sys.argv[3]

with open(path, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if obj.get("uid") != uid or obj.get("direction") != "out" or obj.get("dstIp") != peer:
            continue
        if obj.get("protocol") != "icmp":
            continue
        assert bool(obj.get("accepted")) is False
        assert obj.get("reasonId") == "IFACE_BLOCK"
        assert "ruleId" not in obj
        assert "wouldRuleId" not in obj
        raise SystemExit(0)
raise SystemExit(2)
PY
then
  log_pass "PKTSTREAM carries IFACE_BLOCK without ruleId/wouldRuleId"
  rm -f "$tmp_pkt" >/dev/null 2>&1 || true
else
  log_fail "PKTSTREAM missing/incorrect IFACE_BLOCK attribution"
  rg -n "\"reasonId\":\"IFACE_BLOCK\"" "$tmp_pkt" | head -n 10 || true
  rg -n "\"dstIp\":\"${IPTEST_PEER_IP}\"" "$tmp_pkt" | head -n 10 || true
  rm -f "$tmp_pkt" >/dev/null 2>&1 || true
  exit 5
fi

# Best-effort: ensure host cache not polluted by IFACE_BLOCK traffic.
hostsJson="$(send_cmd "HOSTS")"
if echo "$hostsJson" | rg -n "\"${IPTEST_PEER_IP}\"" >/dev/null 2>&1; then
  log_fail "IFACE_BLOCK traffic polluted HOSTS cache (unexpected remote IP present)"
  exit 6
fi
log_pass "IFACE_BLOCK does not pollute HOSTS cache (best-effort)"

# ----------------------------------------------------------------------
# BLOCK=0 bypasses all processing (no reason counters growth)
# ----------------------------------------------------------------------
expect_ok "RESETALL" "RESETALL (BLOCK=0 bypass)"
expect_ok "BLOCK 0" "BLOCK disable"
expect_ok "IPRULES 1" "IPRULES enabled while BLOCK=0"
expect_ok "BLOCKIFACE ${IPTEST_UID} ${mask}" "BLOCKIFACE set while BLOCK=0"
expect_ok "METRICS.REASONS.RESET" "METRICS.REASONS.RESET"

iptest_tier1_ping_once

reasonsJson="$(send_cmd "METRICS.REASONS")"
total="$(echo "$reasonsJson" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(sum(int(v.get("packets",0)) for v in d.get("reasons",{}).values()))' 2>/dev/null || echo 0)"
if [[ "${total:-0}" -eq 0 ]]; then
  log_pass "METRICS.REASONS does not grow under traffic when BLOCK=0"
else
  log_fail "METRICS.REASONS grew under traffic when BLOCK=0 (totalPackets=$total)"
  exit 7
fi

log_pass "iface block ok"
exit 0
