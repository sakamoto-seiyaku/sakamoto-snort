#!/bin/bash

set -euo pipefail

CASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$CASE_DIR/../lib.sh"

log_section "policy checkpoint vNext smoke"

ctl_or_block() {
  local out_var="$1"
  local cmd="$2"
  local args_json="${3:-}"
  local block_msg="${4:-$cmd failed}"
  local result st

  set +e
  if [[ -n "$args_json" ]]; then
    result="$(vnext_ctl_cmd "$cmd" "$args_json" 2>/dev/null)"
  else
    result="$(vnext_ctl_cmd "$cmd" 2>/dev/null)"
  fi
  st=$?
  set -e
  if [[ $st -ne 0 ]]; then
    echo "BLOCKED: $block_msg" >&2
    return 77
  fi
  printf -v "$out_var" '%s' "$result"
  return 0
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
  printf '%s\n' "$json" | head -n 3 | sed 's/^/    /'
  exit 1
}

assert_ok() {
  assert_json_pred "$1" "$2" 'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True'
}

domain_blocked() {
  local domain="$1"
  local out
  ctl_or_block out DEV.DOMAIN.QUERY "{\"app\":{\"uid\":${IPTEST_UID}},\"domain\":\"${domain}\"}" \
    "DEV.DOMAIN.QUERY failed" || return $?
  QUERY_JSON="$out" python3 - <<'PY'
import json, os
j = json.loads(os.environ["QUERY_JSON"])
print("1" if j.get("ok") is True and j.get("result", {}).get("blocked") is True else "0")
PY
}

tcp_count_bytes() {
  local port="$1"
  local out
  out="$(iptest_tier1_tcp_count_bytes "$port" 512 "$IPTEST_UID" | tr -d '\r\n')" || out="0"
  [[ "$out" =~ ^[0-9]+$ ]] || out="0"
  printf '%s\n' "$out"
}

assert_tcp_allows() {
  local desc="$1"
  local port="$2"
  local bytes
  bytes="$(tcp_count_bytes "$port")"
  if [[ "$bytes" -gt 0 ]]; then
    log_pass "$desc (bytes=$bytes)"
    return 0
  fi
  log_fail "$desc"
  echo "    bytes=$bytes"
  exit 1
}

assert_tcp_blocks() {
  local desc="$1"
  local port="$2"
  local bytes
  bytes="$(tcp_count_bytes "$port")"
  if [[ "$bytes" -eq 0 ]]; then
    log_pass "$desc"
    return 0
  fi
  log_fail "$desc"
  echo "    unexpected bytes=$bytes"
  exit 1
}

if ! vnext_preflight; then
  exit 77
fi

IPTEST_UID="${IPTEST_APP_UID:-${IPTEST_UID:-2000}}"
export IPTEST_UID
log_info "target uid=$IPTEST_UID"

ctl_or_block reset RESETALL "" "RESETALL failed" || exit $?
assert_ok "CP-00 RESETALL ok" "$reset"

ctl_or_block list0 CHECKPOINT.LIST "" "CHECKPOINT.LIST failed" || exit $?
assert_json_pred "CP-01 LIST exposes fixed slots" "$list0" \
  'import sys,json; j=json.load(sys.stdin); slots=j["result"]["slots"]; assert j["ok"] is True; assert [s["slot"] for s in slots]==[0,1,2]'

domain="checkpoint-$(date +%s).example.com"
policy_block="{\"scope\":\"device\",\"policy\":{\"allow\":{\"domains\":[],\"ruleIds\":[]},\"block\":{\"domains\":[\"${domain}\"],\"ruleIds\":[]}}}"
policy_allow="{\"scope\":\"device\",\"policy\":{\"allow\":{\"domains\":[\"${domain}\"],\"ruleIds\":[]},\"block\":{\"domains\":[],\"ruleIds\":[]}}}"

ctl_or_block policy0 DOMAINPOLICY.APPLY "$policy_block" "DOMAINPOLICY.APPLY baseline failed" || exit $?
assert_ok "CP-02 baseline domain policy blocks" "$policy0"
[[ "$(domain_blocked "$domain")" == "1" ]] || {
  log_fail "CP-03 baseline domain verdict blocked"
  exit 1
}
log_pass "CP-03 baseline domain verdict blocked"

ctl_or_block save0 CHECKPOINT.SAVE '{"slot":0}' "CHECKPOINT.SAVE slot0 failed" || exit $?
assert_ok "CP-04 SAVE slot0 ok" "$save0"

ctl_or_block policy1 DOMAINPOLICY.APPLY "$policy_allow" "DOMAINPOLICY.APPLY mutation failed" || exit $?
assert_ok "CP-05 mutated domain policy allows" "$policy1"
[[ "$(domain_blocked "$domain")" == "0" ]] || {
  log_fail "CP-06 mutated domain verdict allowed"
  exit 1
}
log_pass "CP-06 mutated domain verdict allowed"

"$SNORT_CTL" --tcp "127.0.0.1:${VNEXT_PORT}" --compact --follow STREAM.START \
  '{"type":"dns","horizonSec":0,"minSize":0}' >/tmp/checkpoint_stream.$$ 2>&1 &
stream_pid=$!
sleep 0.5

ctl_or_block restore0 CHECKPOINT.RESTORE '{"slot":0}' "CHECKPOINT.RESTORE slot0 failed" || {
  kill "$stream_pid" >/dev/null 2>&1 || true
  exit 77
}
assert_ok "CP-07 RESTORE slot0 ok" "$restore0"
[[ "$(domain_blocked "$domain")" == "1" ]] || {
  log_fail "CP-08 restored domain verdict blocked"
  kill "$stream_pid" >/dev/null 2>&1 || true
  exit 1
}
log_pass "CP-08 restored domain verdict blocked"

set +e
STREAM_PID="$stream_pid" python3 - <<'PY'
import os
import signal
import time

pid = int(os.environ["STREAM_PID"])
deadline = time.monotonic() + 5.0
while time.monotonic() < deadline:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        raise SystemExit(0)
    stat_path = f"/proc/{pid}/stat"
    try:
        stat = open(stat_path, "r", encoding="utf-8").read().split()
        if len(stat) > 2 and stat[2] == "Z":
            raise SystemExit(0)
    except FileNotFoundError:
        raise SystemExit(0)
    time.sleep(0.1)
raise SystemExit(1)
PY
stream_wait=$?
wait "$stream_pid" >/dev/null 2>&1 || true
set -e
if [[ $stream_wait -eq 0 ]]; then
  log_pass "CP-09 restore invalidated active stream consumer"
else
  log_fail "CP-09 restore invalidated active stream consumer"
  kill "$stream_pid" >/dev/null 2>&1 || true
  sed -n '1,20p' "/tmp/checkpoint_stream.$$" | sed 's/^/    /'
  exit 1
fi
rm -f "/tmp/checkpoint_stream.$$"

"$SNORT_CTL" --tcp "127.0.0.1:${VNEXT_PORT}" --compact --follow STREAM.START \
  '{"type":"dns","horizonSec":0,"minSize":0}' >/tmp/checkpoint_stream_reopen.$$ 2>&1 &
stream_reopen_pid=$!
sleep 0.5
if kill -0 "$stream_reopen_pid" >/dev/null 2>&1; then
  log_pass "CP-09b restore allows stream consumer reopen"
  kill "$stream_reopen_pid" >/dev/null 2>&1 || true
  wait "$stream_reopen_pid" >/dev/null 2>&1 || true
else
  log_fail "CP-09b restore allows stream consumer reopen"
  sed -n '1,20p' "/tmp/checkpoint_stream_reopen.$$" | sed 's/^/    /'
  wait "$stream_reopen_pid" >/dev/null 2>&1 || true
  exit 1
fi
rm -f "/tmp/checkpoint_stream_reopen.$$"

if ! iptest_require_tier1_prereqs; then
  echo "BLOCKED: tier1 prereqs missing (need root + ip/netns/veth + ping + nc)" >&2
  exit 77
fi

set +e
table="$(iptest_tier1_setup)"
setup_rc=$?
set -e
if [[ $setup_rc -eq 10 ]]; then
  exit 10
fi
if [[ $setup_rc -ne 0 ]]; then
  echo "BLOCKED: tier1 setup failed" >&2
  exit 77
fi
trap 'iptest_tier1_teardown "$table" >/dev/null 2>&1 || true' EXIT

tcp_port=4447
iptest_tier1_start_tcp_zero_server "$tcp_port" >/dev/null 2>&1 || {
  echo "BLOCKED: failed to start tier1 tcp server" >&2
  exit 77
}

ctl_or_block cfg CONFIG.SET "{\"scope\":\"app\",\"app\":{\"uid\":${IPTEST_UID}},\"set\":{\"tracked\":1,\"block.ifaceKindMask\":0}}" \
  "CONFIG.SET app failed" || exit $?
assert_ok "CP-10 CONFIG.SET app ok" "$cfg"

ctl_or_block ipclear IPRULES.APPLY "{\"app\":{\"uid\":${IPTEST_UID}},\"rules\":[]}" \
  "IPRULES.APPLY clear failed" || exit $?
assert_ok "CP-11 clear IPRULES baseline ok" "$ipclear"
assert_tcp_allows "CP-12 baseline packet verdict allows" "$tcp_port"

ctl_or_block save1 CHECKPOINT.SAVE '{"slot":1}' "CHECKPOINT.SAVE slot1 failed" || exit $?
assert_ok "CP-13 SAVE slot1 ok" "$save1"

block_rule="{\"app\":{\"uid\":${IPTEST_UID}},\"rules\":[{\"clientRuleId\":\"checkpoint:block\",\"family\":\"ipv4\",\"action\":\"block\",\"priority\":100,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"tcp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${IPTEST_PEER_IP}/32\",\"sport\":\"any\",\"dport\":\"${tcp_port}\"}]}"
ctl_or_block ipblock IPRULES.APPLY "$block_rule" "IPRULES.APPLY block failed" || exit $?
assert_ok "CP-14 mutated IPRULES block ok" "$ipblock"
assert_tcp_blocks "CP-15 mutated packet verdict blocks" "$tcp_port"

ctl_or_block restore1 CHECKPOINT.RESTORE '{"slot":1}' "CHECKPOINT.RESTORE slot1 failed" || exit $?
assert_ok "CP-16 RESTORE slot1 ok" "$restore1"
assert_tcp_allows "CP-17 restored packet verdict allows" "$tcp_port"

ctl_or_block clear0 CHECKPOINT.CLEAR '{"slot":0}' "CHECKPOINT.CLEAR slot0 failed" || exit $?
assert_json_pred "CP-18 CLEAR slot0 present=false" "$clear0" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True; assert j["result"]["slot"]["present"] is False'

log_pass "policy checkpoint vNext smoke ok"
