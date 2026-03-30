#!/bin/bash

set -euo pipefail

CASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$CASE_DIR/../lib.sh"

log_section "conntrack ct.* (tier1)"

IPTEST_CT_PORT="${IPTEST_CT_PORT:-18081}"
IPTEST_CT_BYTES="${IPTEST_CT_BYTES:-65536}"

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

server_pid="$(iptest_tier1_start_tcp_zero_server "$IPTEST_CT_PORT" | tr -d '\r\n' || true)"
if [[ ! "$server_pid" =~ ^[0-9]+$ ]]; then
  log_fail "start tier1 tcp server for ct"
  echo "server_pid=$server_pid"
  exit 3
fi
log_info "tier1 tcp server pid=$server_pid port=$IPTEST_CT_PORT"

iptest_reset_baseline

rid_new="$(expect_uint "IPRULES.ADD ${IPTEST_UID} action=allow priority=200 dir=out proto=tcp dst=${IPTEST_PEER_IP}/32 dport=${IPTEST_CT_PORT} ct.state=new ct.direction=orig" "ADD ct.new+orig allow rule")" || exit 4
rid_est_reply="$(expect_uint "IPRULES.ADD ${IPTEST_UID} action=allow priority=200 dir=in proto=tcp src=${IPTEST_PEER_IP}/32 sport=${IPTEST_CT_PORT} ct.state=established ct.direction=reply" "ADD ct.established+reply allow rule")" || exit 4

count="$(iptest_tier1_tcp_count_bytes "$IPTEST_CT_PORT" "$IPTEST_CT_BYTES" "$IPTEST_UID" | tr -d '\r\n' || true)"
if [[ ! "$count" =~ ^[0-9]+$ || "$count" -le 0 ]]; then
  log_fail "tcp read produces bytes (ct allow rules active)"
  echo "count=$count"
  exit 5
fi
log_pass "tcp read produces bytes (count=$count)"

hit_new="$(json_get "$(send_cmd "IPRULES.PRINT RULE ${rid_new}")" "rules.0.stats.hitPackets")"
hit_est_reply="$(json_get "$(send_cmd "IPRULES.PRINT RULE ${rid_est_reply}")" "rules.0.stats.hitPackets")"
if [[ ! "$hit_new" =~ ^[0-9]+$ || "$hit_new" -lt 1 ]]; then
  log_fail "ct.new+orig rule hitPackets increments"
  echo "hitPackets=$hit_new"
  exit 6
fi
log_pass "ct.new+orig rule hitPackets increments (hitPackets=$hit_new)"
if [[ ! "$hit_est_reply" =~ ^[0-9]+$ || "$hit_est_reply" -lt 1 ]]; then
  log_fail "ct.established+reply rule hitPackets increments"
  echo "hitPackets=$hit_est_reply"
  exit 7
fi
log_pass "ct.established+reply rule hitPackets increments (hitPackets=$hit_est_reply)"

# Now verify enforce verdict: BLOCK new outbound packets and observe drop.
iptest_reset_baseline
expect_ok "METRICS.REASONS.RESET" "METRICS.REASONS.RESET"

rid_block_new="$(expect_uint "IPRULES.ADD ${IPTEST_UID} action=block priority=500 dir=out proto=tcp dst=${IPTEST_PEER_IP}/32 dport=${IPTEST_CT_PORT} ct.state=new ct.direction=orig" "ADD ct.new+orig block rule")" || exit 8

count2="$(iptest_tier1_tcp_count_bytes "$IPTEST_CT_PORT" "$IPTEST_CT_BYTES" "$IPTEST_UID" | tr -d '\r\n' || true)"
if [[ ! "$count2" =~ ^[0-9]+$ ]]; then
  log_fail "tcp read returns numeric count under block"
  echo "count=$count2"
  exit 9
fi
if [[ "$count2" -ne 0 ]]; then
  log_fail "ct.new+orig block rule drops tcp (expected 0 bytes)"
  echo "count=$count2"
  exit 10
fi
log_pass "ct.new+orig block rule drops tcp (count=$count2)"

blocked_pkts="$(json_get "$(send_cmd "METRICS.REASONS")" "reasons.IP_RULE_BLOCK.packets")"
if [[ ! "$blocked_pkts" =~ ^[0-9]+$ || "$blocked_pkts" -lt 1 ]]; then
  log_fail "METRICS.REASONS shows IP_RULE_BLOCK packets"
  echo "blocked_pkts=$blocked_pkts"
  exit 11
fi
log_pass "METRICS.REASONS shows IP_RULE_BLOCK packets (packets=$blocked_pkts)"

hit_block="$(json_get "$(send_cmd "IPRULES.PRINT RULE ${rid_block_new}")" "rules.0.stats.hitPackets")"
if [[ ! "$hit_block" =~ ^[0-9]+$ || "$hit_block" -lt 1 ]]; then
  log_fail "ct.new+orig block rule hitPackets increments"
  echo "hitPackets=$hit_block"
  exit 12
fi
log_pass "ct.new+orig block rule hitPackets increments (hitPackets=$hit_block)"

log_pass "conntrack ct.* ok"
exit 0

