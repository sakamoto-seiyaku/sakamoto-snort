#!/bin/bash

set -euo pipefail

CASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$CASE_DIR/../lib.sh"

log_section "iface block (tier1; vNext-only)"

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

capture_pkt_stream() {
  local out_path="$1"
  local duration_sec="${2:-6}"
  local max_frames="${3:-200}"

  set +e
  timeout "${duration_sec}s" stdbuf -oL -eL "$SNORT_CTL" \
    --tcp "127.0.0.1:${VNEXT_PORT}" \
    --compact \
    --follow \
    --max-frames "$max_frames" \
    STREAM.START '{"type":"pkt","horizonSec":0,"minSize":0}' \
    >"$out_path" 2>/dev/null
  local rc=$?
  set -e
  if [[ $rc -ne 0 && $rc -ne 124 ]]; then
    log_fail "STREAM.START(pkt) capture (rc=$rc)"
    return 1
  fi
  return 0
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
    set +e

    # Best-effort cleanup: IFACE_BLOCK changes app state and can poison subsequent runs.
    vnext_ctl_cmd RESETALL >/dev/null 2>&1 || true

    if [[ -n "$table" ]]; then
      iptest_tier1_teardown "$table" || true
    fi
  }
  trap cleanup EXIT

  table="$(iptest_tier1_setup)" || exit $?

  ifaces="$(vnext_rpc_ok IFACES.LIST)" || exit $?
  kind="$(IFACES_JSON="$ifaces" IFACE="$IPTEST_VETH0" python3 - <<'PY'
import os, json
j = json.loads(os.environ["IFACES_JSON"])
name = os.environ["IFACE"]
for it in j.get("result", {}).get("ifaces", []):
    if it.get("name") == name:
        print(it.get("kind", ""))
        raise SystemExit(0)
print("")
PY
)" || kind=""
  kind="$(printf '%s' "$kind" | tr -d '\r\n')"
  if [[ -z "$kind" && "$IPTEST_VETH0" == iptest_veth* ]]; then
    kind="unmanaged"
    log_info "IFACES.LIST kind unavailable; fallback kind=${kind} for ${IPTEST_VETH0}"
  fi

  mask="$(iface_kind_mask "$kind" | tr -d '\r\n')"
  if [[ ! "$mask" =~ ^[0-9]+$ || "$mask" -le 0 ]]; then
    echo "SKIP: could not derive iface kind mask for $IPTEST_VETH0 (kind='$kind')"
    exit 10
  fi
  log_info "iface=$IPTEST_VETH0 kind=$kind mask=$mask uid=$IPTEST_UID"

  set +e
  iptest_adb_as_uid "$IPTEST_UID" "ping -c 1 -W 1 \"$IPTEST_PEER_IP\" >/dev/null 2>&1"
  ping_rc=$?
  set -e
  if [[ $ping_rc -ne 0 ]]; then
    echo "SKIP: ICMP ping not permitted as uid=$IPTEST_UID (rc=$ping_rc); cannot validate iface-block on ICMP traffic"
    exit 10
  fi

  tmp_pkt="$(mktemp)"
  trap 'rm -f "$tmp_pkt" 2>/dev/null || true; cleanup' EXIT

  # ----------------------------------------------------------------------
  # IFACE_BLOCK takes precedence and does not attribute ruleId/wouldRuleId
  # ----------------------------------------------------------------------
  iptest_reset_baseline

  apply="$(vnext_rpc_ok IPRULES.APPLY "{\"app\":{\"uid\":${IPTEST_UID}},\"rules\":[{\"clientRuleId\":\"iface:allow\",\"family\":\"ipv4\",\"action\":\"allow\",\"priority\":100,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"icmp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${IPTEST_PEER_IP}/32\",\"sport\":\"any\",\"dport\":\"any\"}]}")" || exit $?
  rid_allow="$(rule_id_from_apply "$apply" "iface:allow" | tr -d '\r\n')"

  vnext_rpc_ok CONFIG.SET "{\"scope\":\"app\",\"app\":{\"uid\":${IPTEST_UID}},\"set\":{\"block.ifaceKindMask\":${mask}}}" >/dev/null || exit $?
  vnext_rpc_ok METRICS.RESET '{"name":"reasons"}' >/dev/null || exit $?

  capture_pkt_stream "$tmp_pkt" 6 200 || exit 1 &
  cap_pid=$!
  sleep 2
  iptest_adb_as_uid "$IPTEST_UID" "ping -c 1 -W 1 \"$IPTEST_PEER_IP\" >/dev/null 2>&1 || true" >/dev/null 2>&1
  sleep 0.2
  iptest_adb_as_uid "$IPTEST_UID" "ping -c 1 -W 1 \"$IPTEST_PEER_IP\" >/dev/null 2>&1 || true" >/dev/null 2>&1
  sleep 0.2
  iptest_adb_as_uid "$IPTEST_UID" "ping -c 1 -W 1 \"$IPTEST_PEER_IP\" >/dev/null 2>&1 || true" >/dev/null 2>&1
  set +e
  wait "$cap_pid"
  set -e

  reasons="$(vnext_rpc_ok METRICS.GET '{"name":"reasons"}')" || exit $?
  iface_packets="$(vnext_json_get "$reasons" "result.reasons.IFACE_BLOCK.packets")"
  if [[ "${iface_packets:-0}" -ge 1 ]]; then
    log_pass "IFACE_BLOCK observed (packets=$iface_packets)"
  else
    log_fail "IFACE_BLOCK not observed (packets=$iface_packets)"
    exit 3
  fi

  printed="$(vnext_rpc_ok IPRULES.PRINT "{\"app\":{\"uid\":${IPTEST_UID}}}")" || exit $?
  hit_allow="$(rule_hit_packets "$printed" "$rid_allow")"
  if [[ "${hit_allow:-0}" -eq 0 ]]; then
    log_pass "IFACE_BLOCK bypasses iprules evaluation (rule hitPackets stays 0)"
  else
    log_fail "iprules stats grew under IFACE_BLOCK (hitPackets=$hit_allow)"
    exit 4
  fi

  if python3 - "$tmp_pkt" "$IPTEST_UID" "$IPTEST_PEER_IP" <<'PY' >/dev/null 2>&1
import json
import sys

path = sys.argv[1]
uid = int(sys.argv[2])
peer = sys.argv[3]

for line in open(path, "r", encoding="utf-8", errors="ignore"):
    line = line.strip()
    if not line:
        continue
    obj = json.loads(line)
    if obj.get("type") != "pkt":
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
    log_pass "PKT stream carries IFACE_BLOCK without ruleId/wouldRuleId"
  else
    log_fail "PKT stream missing/incorrect IFACE_BLOCK attribution"
    rg -n "\"reasonId\":\"IFACE_BLOCK\"" "$tmp_pkt" | head -n 10 || true
    exit 5
  fi

  # ----------------------------------------------------------------------
  # block.enabled=0 bypasses all processing (no reason counters growth)
  # ----------------------------------------------------------------------
  vnext_rpc_ok RESETALL >/dev/null || exit $?
  vnext_rpc_ok CONFIG.SET '{"scope":"device","set":{"block.enabled":0,"iprules.enabled":1}}' >/dev/null || exit $?
  vnext_rpc_ok CONFIG.SET "{\"scope\":\"app\",\"app\":{\"uid\":${IPTEST_UID}},\"set\":{\"block.ifaceKindMask\":${mask}}}" >/dev/null || exit $?
  vnext_rpc_ok METRICS.RESET '{"name":"reasons"}' >/dev/null || exit $?

  iptest_adb_as_uid "$IPTEST_UID" "ping -c 1 -W 1 \"$IPTEST_PEER_IP\" >/dev/null 2>&1 || true" >/dev/null 2>&1

  reasons2="$(vnext_rpc_ok METRICS.GET '{"name":"reasons"}')" || exit $?
  total="$(printf '%s\n' "$reasons2" | python3 -c 'import sys,json; j=json.load(sys.stdin); r=j.get("result",{}).get("reasons",{}); print(sum(int(v.get("packets",0)) for v in r.values()))' 2>/dev/null || echo 0)"
  if [[ "${total:-0}" -eq 0 ]]; then
    log_pass "METRICS.GET(reasons) does not grow under traffic when block.enabled=0"
  else
    log_fail "METRICS.GET(reasons) grew under traffic when block.enabled=0 (totalPackets=$total)"
    exit 6
  fi

  log_pass "iface block ok"
  exit 0
}

main "$@"
