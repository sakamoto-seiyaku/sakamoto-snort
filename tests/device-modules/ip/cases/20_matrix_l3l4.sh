#!/bin/bash

set -euo pipefail

CASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$CASE_DIR/../lib.sh"

log_section "iprules matrix (tier1)"

DEVICE_BUSYBOX=""

detect_busybox_nc() {
  if adb_cmd shell "[ -x /data/local/tmp/busybox ] && /data/local/tmp/busybox nc --help >/dev/null 2>&1"; then
    DEVICE_BUSYBOX="/data/local/tmp/busybox"
    log_info "device busybox detected: $DEVICE_BUSYBOX (will use for nc when needed)"
  fi
}

ping_once() {
  iptest_adb_shell "ping -c 1 -W 1 \"$IPTEST_PEER_IP\" >/dev/null 2>&1 || true" >/dev/null 2>&1
}

tcp_probe_once() {
  local port="$1"
  local sport="${2:-}"
  local sportFlag=""
  if [[ -n "$sport" ]]; then
    sportFlag="-p $sport"
  fi
  if [[ -n "$DEVICE_BUSYBOX" ]]; then
    iptest_adb_as_uid "$IPTEST_UID" "$DEVICE_BUSYBOX nc -n -z -w 2 $sportFlag \"$IPTEST_PEER_IP\" \"$port\" >/dev/null 2>&1 || true" >/dev/null 2>&1
  else
    iptest_adb_as_uid "$IPTEST_UID" "nc -n -z -w 2 $sportFlag \"$IPTEST_PEER_IP\" \"$port\" >/dev/null 2>&1 || true" >/dev/null 2>&1
  fi
}

udp_send_once() {
  local port="$1"
  local sport="${2:-}"
  local sportFlag=""
  if [[ -n "$sport" ]]; then
    sportFlag="-p $sport"
  fi
  if [[ -n "$DEVICE_BUSYBOX" ]]; then
    iptest_adb_as_uid "$IPTEST_UID" "printf x | $DEVICE_BUSYBOX nc -n -u -w 1 $sportFlag \"$IPTEST_PEER_IP\" \"$port\" >/dev/null 2>&1 || true" >/dev/null 2>&1
  else
    # toybox nc requires -q >= 1
    iptest_adb_as_uid "$IPTEST_UID" "printf x | nc -n -u -w 1 -q 1 $sportFlag \"$IPTEST_PEER_IP\" \"$port\" >/dev/null 2>&1 || true" >/dev/null 2>&1
  fi
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

pick_wrong_iface_kind() {
  local actual="$1"
  local k
  for k in wifi data vpn unmanaged; do
    if [[ "$k" != "$actual" ]]; then
      printf '%s\n' "$k"
      return 0
    fi
  done
  printf '%s\n' "wifi"
  return 0
}

case_assert_enforce_hit() {
  local rid="$1"
  local reason="$2"
  local desc="$3"

  rp="$(get_reason_packets "$reason")"
  hp="$(get_rule_stat "$rid" "hitPackets")"
  if [[ "${rp:-0}" -ge 1 && "${hp:-0}" -ge 1 ]]; then
    log_pass "$desc"
    return 0
  fi
  log_fail "$desc (reasonPackets=${rp:-0} hitPackets=${hp:-0})"
  return 1
}

case_assert_no_enforce_match() {
  local rid="$1"
  local desc="$2"

  hp="$(get_rule_stat "$rid" "hitPackets")"
  if [[ "${hp:-0}" -eq 0 ]]; then
    log_pass "$desc"
    return 0
  fi
  log_fail "$desc (unexpected hitPackets=${hp:-0})"
  return 1
}

if ! init_test_env; then
  exit 2
fi

if ! iptest_require_tier1_prereqs; then
  echo "SKIP: tier1 prereqs missing (need root + ip/netns/veth + ping + nc)"
  exit 10
fi

detect_busybox_nc

table=""
cleanup() {
  if [[ -n "$table" ]]; then
    iptest_tier1_teardown "$table" || true
  fi
}
trap cleanup EXIT

table="$(iptest_tier1_setup)" || exit $?

TCP_PORT="${IPTEST_MATRIX_TCP_PORT:-18080}"
UDP_PORT="${IPTEST_MATRIX_UDP_PORT:-18082}"
FIXED_SPORT="${IPTEST_MATRIX_FIXED_SPORT:-40000}"

server_pid="$(iptest_tier1_start_tcp_zero_server "$TCP_PORT" | tr -d '\r\n' || true)"
if [[ ! "$server_pid" =~ ^[0-9]+$ ]]; then
  log_fail "start tier1 tcp server"
  echo "server_pid=$server_pid"
  exit 3
fi
log_info "tier1 tcp server pid=$server_pid port=$TCP_PORT"

# ----------------------------------------------------------------------
# ICMP enforce: out allow/block + dir=any
# ----------------------------------------------------------------------
log_section "ICMP enforce (dir out/any)"

iptest_reset_baseline
rid="$(expect_uint "IPRULES.ADD ${IPTEST_UID} action=allow priority=10 proto=icmp dir=out dst=${IPTEST_PEER_IP}/32" "ADD icmp allow(out)")"
expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
ping_once
case_assert_enforce_hit "$rid" "IP_RULE_ALLOW" "ICMP out allow matches"

iptest_reset_baseline
rid="$(expect_uint "IPRULES.ADD ${IPTEST_UID} action=block priority=10 proto=icmp dir=out dst=${IPTEST_PEER_IP}/32" "ADD icmp block(out)")"
expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
ping_once
case_assert_enforce_hit "$rid" "IP_RULE_BLOCK" "ICMP out block matches"

iptest_reset_baseline
rid="$(expect_uint "IPRULES.ADD ${IPTEST_UID} action=allow priority=10 proto=icmp dir=any dst=${IPTEST_PEER_IP}/32" "ADD icmp allow(dir=any)")"
expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
ping_once
case_assert_enforce_hit "$rid" "IP_RULE_ALLOW" "dir=any matches outbound icmp request"

# ----------------------------------------------------------------------
# TCP enforce: dport exact/range + sport exact + mismatch
# ----------------------------------------------------------------------
log_section "TCP enforce (ports)"

iptest_reset_baseline
rid="$(expect_uint "IPRULES.ADD ${IPTEST_UID} action=allow priority=10 proto=tcp dir=out dst=${IPTEST_PEER_IP}/32 dport=${TCP_PORT}" "ADD tcp allow dport exact")"
expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
tcp_probe_once "$TCP_PORT"
case_assert_enforce_hit "$rid" "IP_RULE_ALLOW" "TCP out allow (dport exact) matches"

iptest_reset_baseline
rid="$(expect_uint "IPRULES.ADD ${IPTEST_UID} action=allow priority=10 proto=tcp dir=out dst=${IPTEST_PEER_IP}/32 dport=$((TCP_PORT - 5))-$((TCP_PORT + 5))" "ADD tcp allow dport range")"
expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
tcp_probe_once "$TCP_PORT"
case_assert_enforce_hit "$rid" "IP_RULE_ALLOW" "TCP out allow (dport range includes port) matches"

iptest_reset_baseline
rid="$(expect_uint "IPRULES.ADD ${IPTEST_UID} action=allow priority=10 proto=tcp dir=out dst=${IPTEST_PEER_IP}/32 dport=$((TCP_PORT + 1))-$((TCP_PORT + 2))" "ADD tcp allow dport mismatch")"
expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
tcp_probe_once "$TCP_PORT"
case_assert_no_enforce_match "$rid" "TCP out no-match when dport range excludes"

iptest_reset_baseline
rid="$(expect_uint "IPRULES.ADD ${IPTEST_UID} action=allow priority=10 proto=tcp dir=out dst=${IPTEST_PEER_IP}/32 sport=${FIXED_SPORT} dport=${TCP_PORT}" "ADD tcp allow sport exact")"
expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
tcp_probe_once "$TCP_PORT" "$FIXED_SPORT"
case_assert_enforce_hit "$rid" "IP_RULE_ALLOW" "TCP out allow (sport exact) matches"

# ----------------------------------------------------------------------
# UDP enforce: dport exact + range + mismatch
# ----------------------------------------------------------------------
log_section "UDP enforce (ports)"

iptest_reset_baseline
rid="$(expect_uint "IPRULES.ADD ${IPTEST_UID} action=allow priority=10 proto=udp dir=out dst=${IPTEST_PEER_IP}/32 dport=${UDP_PORT}" "ADD udp allow dport exact")"
expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
udp_send_once "$UDP_PORT"
case_assert_enforce_hit "$rid" "IP_RULE_ALLOW" "UDP out allow matches"

iptest_reset_baseline
rid="$(expect_uint "IPRULES.ADD ${IPTEST_UID} action=allow priority=10 proto=udp dir=out dst=${IPTEST_PEER_IP}/32 dport=$((UDP_PORT - 5))-$((UDP_PORT + 5))" "ADD udp allow dport range")"
expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
udp_send_once "$UDP_PORT"
case_assert_enforce_hit "$rid" "IP_RULE_ALLOW" "UDP out allow (dport range includes) matches"

iptest_reset_baseline
rid="$(expect_uint "IPRULES.ADD ${IPTEST_UID} action=allow priority=10 proto=udp dir=out dst=${IPTEST_PEER_IP}/32 dport=$((UDP_PORT + 1))-$((UDP_PORT + 2))" "ADD udp allow dport mismatch")"
expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
udp_send_once "$UDP_PORT"
case_assert_no_enforce_match "$rid" "UDP out no-match when dport range excludes"

# ----------------------------------------------------------------------
# CIDR variants: /24 match + no-match
# ----------------------------------------------------------------------
log_section "CIDR variants (/24 match/no-match)"

iptest_reset_baseline
rid="$(expect_uint "IPRULES.ADD ${IPTEST_UID} action=allow priority=10 proto=icmp dir=out dst=${IPTEST_NET_CIDR}" "ADD icmp allow dst /24 match")"
expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
ping_once
case_assert_enforce_hit "$rid" "IP_RULE_ALLOW" "dst /24 matches"

iptest_reset_baseline
rid="$(expect_uint "IPRULES.ADD ${IPTEST_UID} action=allow priority=10 proto=icmp dir=out dst=10.200.2.0/24" "ADD icmp allow dst /24 no-match")"
expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
ping_once
case_assert_no_enforce_match "$rid" "dst /24 no-match does not hit"

# ----------------------------------------------------------------------
# iface/ifindex: match + mismatch
# ----------------------------------------------------------------------
log_section "iface/ifindex match"

iptest_reset_baseline
ifaceIfindex="$(iptest_iface_ifindex "$IPTEST_VETH0" 2>/dev/null || true)"
ifacesJson="$(send_cmd "IFACES.PRINT" 10 || true)"
ifaceKind="$(
  printf '%s' "$ifacesJson" | python3 -c '
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
' "$IPTEST_VETH0"
)"
ifaceKind="$(printf '%s' "$ifaceKind" | tr -d '\r\n')"
if [[ -z "$ifaceKind" && "$IPTEST_VETH0" == iptest_veth* ]]; then
  ifaceKind="unmanaged"
  log_info "IFACES.PRINT kind unavailable; fallback ifaceKind=${ifaceKind} for ${IPTEST_VETH0}"
fi
wrongKind="$(pick_wrong_iface_kind "$ifaceKind")"

if [[ ! "$ifaceIfindex" =~ ^[0-9]+$ || -z "$ifaceKind" ]]; then
  log_skip "could not derive iface kind/ifindex for $IPTEST_VETH0; skip iface/ifindex tests"
else
  rid="$(expect_uint "IPRULES.ADD ${IPTEST_UID} action=allow priority=10 proto=icmp dir=out dst=${IPTEST_PEER_IP}/32 iface=${ifaceKind} ifindex=${ifaceIfindex}" "ADD icmp allow (iface+ifindex)")"
  expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
  ping_once
  case_assert_enforce_hit "$rid" "IP_RULE_ALLOW" "iface+ifindex exact matches"

  iptest_reset_baseline
  rid="$(expect_uint "IPRULES.ADD ${IPTEST_UID} action=allow priority=10 proto=icmp dir=out dst=${IPTEST_PEER_IP}/32 iface=any ifindex=${ifaceIfindex}" "ADD icmp allow (iface=any + ifindex)")"
  expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
  ping_once
  case_assert_enforce_hit "$rid" "IP_RULE_ALLOW" "iface=any + ifindex exact matches"

  iptest_reset_baseline
  rid="$(expect_uint "IPRULES.ADD ${IPTEST_UID} action=allow priority=10 proto=icmp dir=out dst=${IPTEST_PEER_IP}/32 iface=${ifaceKind} ifindex=0" "ADD icmp allow (ifindex=0 any)")"
  expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
  ping_once
  case_assert_enforce_hit "$rid" "IP_RULE_ALLOW" "ifindex=0(any) matches"

  iptest_reset_baseline
  rid="$(expect_uint "IPRULES.ADD ${IPTEST_UID} action=allow priority=10 proto=icmp dir=out dst=${IPTEST_PEER_IP}/32 iface=${ifaceKind} ifindex=$((ifaceIfindex + 1))" "ADD icmp allow (wrong ifindex)")"
  expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
  ping_once
  case_assert_no_enforce_match "$rid" "wrong ifindex does not match"

  iptest_reset_baseline
  rid="$(expect_uint "IPRULES.ADD ${IPTEST_UID} action=allow priority=10 proto=icmp dir=out dst=${IPTEST_PEER_IP}/32 iface=${wrongKind} ifindex=${ifaceIfindex}" "ADD icmp allow (wrong iface kind)")"
  expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
  ping_once
  case_assert_no_enforce_match "$rid" "wrong iface kind does not match"
fi

# ----------------------------------------------------------------------
# priority and tie-break
# ----------------------------------------------------------------------
log_section "priority and tie-break"

iptest_reset_baseline
allowRid="$(expect_uint "IPRULES.ADD ${IPTEST_UID} action=allow priority=10 proto=icmp dir=out dst=${IPTEST_PEER_IP}/32" "ADD allow p10")"
blockRid="$(expect_uint "IPRULES.ADD ${IPTEST_UID} action=block priority=20 proto=icmp dir=out dst=${IPTEST_PEER_IP}/32" "ADD block p20")"
expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
ping_once
case_assert_enforce_hit "$blockRid" "IP_RULE_BLOCK" "higher priority wins (block p20 over allow p10)"

iptest_reset_baseline
allowRid="$(expect_uint "IPRULES.ADD ${IPTEST_UID} action=allow priority=10 proto=icmp dir=out dst=${IPTEST_PEER_IP}/32" "ADD allow p10 (tie)")"
blockRid="$(expect_uint "IPRULES.ADD ${IPTEST_UID} action=block priority=10 proto=icmp dir=out dst=${IPTEST_PEER_IP}/32" "ADD block p10 (tie)")"
expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
ping_once
case_assert_enforce_hit "$allowRid" "IP_RULE_ALLOW" "tie-break stable: first-added wins"

# ----------------------------------------------------------------------
# enabled=0 / enable toggling
# ----------------------------------------------------------------------
log_section "enabled toggle"

iptest_reset_baseline
rid="$(expect_uint "IPRULES.ADD ${IPTEST_UID} action=allow priority=10 enabled=0 proto=icmp dir=out dst=${IPTEST_PEER_IP}/32" "ADD disabled rule")"
expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
ping_once
case_assert_no_enforce_match "$rid" "enabled=0 does not match"
expect_ok "IPRULES.ENABLE ${rid} 1" "ENABLE 0->1"
expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
ping_once
case_assert_enforce_hit "$rid" "IP_RULE_ALLOW" "ENABLE makes rule match"

# ----------------------------------------------------------------------
# would-block overlay + enforce-first suppression
# ----------------------------------------------------------------------
log_section "would-block overlay + enforce-first suppression"

iptest_reset_baseline
wouldRid="$(expect_uint "IPRULES.ADD ${IPTEST_UID} action=block priority=10 enforce=0 log=1 proto=icmp dir=out dst=${IPTEST_PEER_IP}/32" "ADD would-block icmp")"
expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
tmp_pkt="$(mktemp)"
stream_sample "PKTSTREAM.START 0 0" "PKTSTREAM.STOP" 6 >"$tmp_pkt" &
pkt_pid=$!
sleep 2
ping_once
sleep 0.2
ping_once
sleep 0.2
ping_once
wait "$pkt_pid" >/dev/null 2>&1 || true
wouldHits="$(get_rule_stat "$wouldRid" "wouldHitPackets")"
if [[ "${wouldHits:-0}" -ge 1 ]]; then
  log_pass "wouldHitPackets grows when accepted (wouldHitPackets=$wouldHits)"
else
  log_fail "wouldHitPackets did not grow when accepted (wouldHitPackets=$wouldHits)"
  rm -f "$tmp_pkt" >/dev/null 2>&1 || true
  exit 8
fi
if python3 - "$tmp_pkt" "$IPTEST_UID" "$IPTEST_PEER_IP" "$wouldRid" <<'PY'
import json
import sys

path = sys.argv[1]
uid = int(sys.argv[2])
peer = sys.argv[3]
rid = int(sys.argv[4])

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
        assert bool(obj.get("accepted")) is True
        assert obj.get("reasonId") == "ALLOW_DEFAULT"
        assert int(obj.get("wouldRuleId", -1)) == rid
        assert int(obj.get("wouldDrop", 0)) == 1
        assert "ruleId" not in obj
        raise SystemExit(0)
raise SystemExit(2)
PY
then
  log_pass "PKTSTREAM carries wouldRuleId/wouldDrop overlay when accepted"
  rm -f "$tmp_pkt" >/dev/null 2>&1 || true
else
  log_fail "PKTSTREAM missing/incorrect wouldRuleId overlay (accept-only)"
  rg -n "\"dstIp\":\"${IPTEST_PEER_IP}\"" "$tmp_pkt" | head -n 10 || true
  rg -n "\"wouldRuleId\"" "$tmp_pkt" | head -n 10 || true
  rm -f "$tmp_pkt" >/dev/null 2>&1 || true
  exit 9
fi

iptest_reset_baseline
enforceRid="$(expect_uint "IPRULES.ADD ${IPTEST_UID} action=allow priority=10 proto=icmp dir=out dst=${IPTEST_PEER_IP}/32" "ADD enforce allow icmp")"
wouldRid2="$(expect_uint "IPRULES.ADD ${IPTEST_UID} action=block priority=100 enforce=0 log=1 proto=icmp dir=out dst=${IPTEST_PEER_IP}/32" "ADD would-block icmp (suppressed)")"
expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
ping_once
if [[ "$(get_rule_stat "$enforceRid" "hitPackets")" -ge 1 && "$(get_rule_stat "$wouldRid2" "wouldHitPackets")" -eq 0 ]]; then
  log_pass "enforce-first suppresses would-hit"
else
  log_fail "enforce-first did not suppress would-hit"
  echo "enforce.hitPackets=$(get_rule_stat "$enforceRid" "hitPackets") would.wouldHitPackets=$(get_rule_stat "$wouldRid2" "wouldHitPackets")"
  exit 10
fi

# ----------------------------------------------------------------------
# IPRULES=0 bypass
# ----------------------------------------------------------------------
log_section "IPRULES=0 bypass"

iptest_reset_baseline
rid="$(expect_uint "IPRULES.ADD ${IPTEST_UID} action=block priority=10 proto=icmp dir=out dst=${IPTEST_PEER_IP}/32" "ADD icmp block (for bypass)")"
expect_ok "IPRULES 0" "IPRULES=0"
expect_ok "METRICS.REASONS.RESET" "REASONS.RESET"
ping_once
case_assert_no_enforce_match "$rid" "IPRULES=0 bypasses rule evaluation"

log_pass "iprules matrix ok"
exit 0
