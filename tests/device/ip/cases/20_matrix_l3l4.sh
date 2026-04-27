#!/bin/bash

set -euo pipefail

CASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$CASE_DIR/../lib.sh"

log_section "iprules matrix (tier1; vNext-only)"

DEVICE_BUSYBOX=""

TCP_PORT="${IPTEST_MATRIX_TCP_PORT:-18080}"
UDP_PORT="${IPTEST_MATRIX_UDP_PORT:-18082}"
FIXED_SPORT="${IPTEST_MATRIX_FIXED_SPORT:-40000}"

detect_busybox_nc() {
  if adb_cmd shell "[ -x /data/local/tmp/busybox ] && /data/local/tmp/busybox nc --help >/dev/null 2>&1"; then
    DEVICE_BUSYBOX="/data/local/tmp/busybox"
    log_info "device busybox detected: $DEVICE_BUSYBOX (will use for nc when needed)"
  fi
}

ping_once() {
  iptest_adb_as_uid "$IPTEST_UID" "ping -c 1 -W 1 \"$IPTEST_PEER_IP\" >/dev/null 2>&1 || true" >/dev/null 2>&1
}

ping6_once() {
  iptest_detect_ping6_cmd >/dev/null 2>&1 || return 1
  iptest_adb_as_uid "$IPTEST_UID" "$IPTEST_PING6_CMD -c 1 -W 1 \"$IPTEST_PEER_IP6\" >/dev/null 2>&1 || true" >/dev/null 2>&1
}

ping6_large_once() {
  local size="$1"
  iptest_detect_ping6_cmd >/dev/null 2>&1 || return 1
  iptest_adb_as_uid "$IPTEST_UID" "$IPTEST_PING6_CMD -s \"$size\" -c 1 -W 2 \"$IPTEST_PEER_IP6\" >/dev/null 2>&1 || true" >/dev/null 2>&1
}

tcp_probe_once() {
  local port="$1"
  local sport="${2:-}"
  local sport_flag=""
  if [[ -n "$sport" ]]; then
    sport_flag="-p $sport"
  fi
  if [[ -n "$DEVICE_BUSYBOX" ]]; then
    iptest_adb_as_uid "$IPTEST_UID" "$DEVICE_BUSYBOX nc -n -z -w 2 $sport_flag \"$IPTEST_PEER_IP\" \"$port\" >/dev/null 2>&1 || true" >/dev/null 2>&1
  else
    iptest_adb_as_uid "$IPTEST_UID" "nc -n -z -w 2 $sport_flag \"$IPTEST_PEER_IP\" \"$port\" >/dev/null 2>&1 || true" >/dev/null 2>&1
  fi
}

udp_send_once() {
  local port="$1"
  local sport="${2:-}"
  local sport_flag=""
  if [[ -n "$sport" ]]; then
    sport_flag="-p $sport"
  fi
  if [[ -n "$DEVICE_BUSYBOX" ]]; then
    iptest_adb_as_uid "$IPTEST_UID" "printf x | $DEVICE_BUSYBOX nc -n -u -w 1 $sport_flag \"$IPTEST_PEER_IP\" \"$port\" >/dev/null 2>&1 || true" >/dev/null 2>&1
  else
    # toybox nc requires -q >= 1
    iptest_adb_as_uid "$IPTEST_UID" "printf x | nc -n -u -w 1 -q 1 $sport_flag \"$IPTEST_PEER_IP\" \"$port\" >/dev/null 2>&1 || true" >/dev/null 2>&1
  fi
}

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
  echo "$out"
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

rule_stat_from_print() {
  local print_json="$1"
  local rule_id="$2"
  local stat="$3"
  PRINT_JSON="$print_json" RULE_ID="$rule_id" STAT="$stat" python3 - <<'PY'
import os, json
j = json.loads(os.environ["PRINT_JSON"])
rid = int(os.environ["RULE_ID"])
stat = os.environ["STAT"]
for r in j.get("result", {}).get("rules", []):
    if int(r.get("ruleId", -1)) == rid:
        print(int(r.get("stats", {}).get(stat, 0)))
        raise SystemExit(0)
print(0)
PY
}

reasons_packets() {
  local reasons_json="$1"
  local reason="$2"
  vnext_json_get "$reasons_json" "result.reasons.${reason}.packets"
}

apply_rules() {
  local rules_json="$1"
  local args_json="{\"app\":{\"uid\":${IPTEST_UID}},\"rules\":${rules_json}}"
  local out
  out="$(vnext_rpc_ok IPRULES.APPLY "$args_json")" || return $?
  if ! printf '%s\n' "$out" | python3 -c 'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True' >/dev/null 2>&1; then
    log_fail "IPRULES.APPLY ok"
    printf '%s\n' "$out" | head -n 3 | sed 's/^/    /'
    return 1
  fi
  printf '%s\n' "$out"
  return 0
}

print_rules() {
  local out
  out="$(vnext_rpc_ok IPRULES.PRINT "{\"app\":{\"uid\":${IPTEST_UID}}}")" || return $?
  if ! printf '%s\n' "$out" | python3 -c 'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True' >/dev/null 2>&1; then
    log_fail "IPRULES.PRINT ok"
    printf '%s\n' "$out" | head -n 3 | sed 's/^/    /'
    return 1
  fi
  printf '%s\n' "$out"
  return 0
}

reset_reasons() {
  vnext_rpc_ok METRICS.RESET '{"name":"reasons"}' >/dev/null || return $?
  return 0
}

get_reasons() {
  local out
  out="$(vnext_rpc_ok METRICS.GET '{"name":"reasons"}')" || return $?
  if ! printf '%s\n' "$out" | python3 -c 'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True' >/dev/null 2>&1; then
    log_fail "METRICS.GET(reasons) ok"
    printf '%s\n' "$out" | head -n 3 | sed 's/^/    /'
    return 1
  fi
  printf '%s\n' "$out"
  return 0
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

assert_pkt_event() {
  local path="$1"
  local py="$2"
  if python3 - "$path" <<PY >/dev/null 2>&1
import sys
path = sys.argv[1]
lines = open(path, "r", encoding="utf-8", errors="ignore").read().splitlines()
$py
PY
  then
    return 0
  fi
  return 1
}

main() {
  if ! vnext_preflight; then
    exit 77
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

  server_pid="$(iptest_tier1_start_tcp_zero_server "$TCP_PORT" | tr -d '\r\n' || true)"
  if [[ ! "$server_pid" =~ ^[0-9]+$ ]]; then
    log_fail "start tier1 tcp server"
    echo "server_pid=$server_pid"
    exit 3
  fi
  log_info "tier1 tcp server pid=$server_pid port=$TCP_PORT"

  # Start from a clean baseline before probes: previous failures may have left
  # per-app IFACE_BLOCK active, making connectivity probes time out.
  iptest_reset_baseline

  probe_bytes="$(iptest_tier1_tcp_count_bytes "$TCP_PORT" 4096 "$IPTEST_UID" | tr -d '\r\n' || true)"
  if [[ ! "$probe_bytes" =~ ^[0-9]+$ || "$probe_bytes" -le 0 ]]; then
    echo "SKIP: tier1 tcp probe failed (uid=$IPTEST_UID port=$TCP_PORT bytes=$probe_bytes); try setting IPTEST_APP_UID to a network-capable app uid"
    exit 10
  fi
  log_info "tier1 tcp probe ok (bytes=$probe_bytes)"

  set +e
  iptest_adb_as_uid "$IPTEST_UID" "ping -c 1 -W 1 \"$IPTEST_PEER_IP\" >/dev/null 2>&1"
  ping_rc=$?
  set -e
  if [[ $ping_rc -ne 0 ]]; then
    echo "SKIP: ICMP ping not permitted as uid=$IPTEST_UID (rc=$ping_rc); cannot run ICMP-heavy matrix"
    exit 10
  fi

  # ----------------------------------------------------------------------
  # ICMP allow/block + dir=any
  # ----------------------------------------------------------------------
  log_section "ICMP enforce"

  iptest_reset_baseline
  apply="$(apply_rules "[{\"clientRuleId\":\"m:icmp-allow\",\"family\":\"ipv4\",\"action\":\"allow\",\"priority\":10,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"icmp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${IPTEST_PEER_IP}/32\",\"sport\":\"any\",\"dport\":\"any\"}]")"
  rid_allow="$(rule_id_from_apply "$apply" "m:icmp-allow" | tr -d '\r\n')"
  reset_reasons
  ping_once
  reasons="$(get_reasons)"
  printed="$(print_rules)"
  rp="$(reasons_packets "$reasons" "IP_RULE_ALLOW")"
  hp="$(rule_stat_from_print "$printed" "$rid_allow" "hitPackets")"
  if [[ "${rp:-0}" -ge 1 && "${hp:-0}" -ge 1 ]]; then
    log_pass "ICMP allow matches (reasonPackets=$rp hitPackets=$hp)"
  else
    log_fail "ICMP allow matches (reasonPackets=$rp hitPackets=$hp)"
    exit 4
  fi

  iptest_reset_baseline
  apply="$(apply_rules "[{\"clientRuleId\":\"m:icmp-block\",\"family\":\"ipv4\",\"action\":\"block\",\"priority\":10,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"icmp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${IPTEST_PEER_IP}/32\",\"sport\":\"any\",\"dport\":\"any\"}]")"
  rid_block="$(rule_id_from_apply "$apply" "m:icmp-block" | tr -d '\r\n')"
  reset_reasons
  ping_once
  reasons="$(get_reasons)"
  printed="$(print_rules)"
  rp="$(reasons_packets "$reasons" "IP_RULE_BLOCK")"
  hp="$(rule_stat_from_print "$printed" "$rid_block" "hitPackets")"
  if [[ "${rp:-0}" -ge 1 && "${hp:-0}" -ge 1 ]]; then
    log_pass "ICMP block matches (reasonPackets=$rp hitPackets=$hp)"
  else
    log_fail "ICMP block matches (reasonPackets=$rp hitPackets=$hp)"
    exit 5
  fi

  iptest_reset_baseline
  apply="$(apply_rules "[{\"clientRuleId\":\"m:icmp-anydir\",\"family\":\"ipv4\",\"action\":\"allow\",\"priority\":10,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"any\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"icmp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${IPTEST_PEER_IP}/32\",\"sport\":\"any\",\"dport\":\"any\"}]")"
  rid_anydir="$(rule_id_from_apply "$apply" "m:icmp-anydir" | tr -d '\r\n')"
  reset_reasons
  ping_once
  reasons="$(get_reasons)"
  printed="$(print_rules)"
  rp="$(reasons_packets "$reasons" "IP_RULE_ALLOW")"
  hp="$(rule_stat_from_print "$printed" "$rid_anydir" "hitPackets")"
  if [[ "${rp:-0}" -ge 1 && "${hp:-0}" -ge 1 ]]; then
    log_pass "ICMP dir=any matches out (reasonPackets=$rp hitPackets=$hp)"
  else
    log_fail "ICMP dir=any matches out (reasonPackets=$rp hitPackets=$hp)"
    exit 6
  fi

  # ----------------------------------------------------------------------
  # TCP / UDP ports
  # ----------------------------------------------------------------------
  log_section "TCP/UDP enforce (ports)"

  iptest_reset_baseline
  apply="$(apply_rules "[{\"clientRuleId\":\"m:tcp-dport-exact\",\"family\":\"ipv4\",\"action\":\"allow\",\"priority\":10,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"tcp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${IPTEST_PEER_IP}/32\",\"sport\":\"any\",\"dport\":\"${TCP_PORT}\"}]")"
  rid_tcp_exact="$(rule_id_from_apply "$apply" "m:tcp-dport-exact" | tr -d '\r\n')"
  reset_reasons
  tcp_probe_once "$TCP_PORT"
  reasons="$(get_reasons)"
  printed="$(print_rules)"
  rp="$(reasons_packets "$reasons" "IP_RULE_ALLOW")"
  hp="$(rule_stat_from_print "$printed" "$rid_tcp_exact" "hitPackets")"
  if [[ "${rp:-0}" -ge 1 && "${hp:-0}" -ge 1 ]]; then
    log_pass "TCP dport exact matches (reasonPackets=$rp hitPackets=$hp)"
  else
    log_fail "TCP dport exact matches (reasonPackets=$rp hitPackets=$hp)"
    exit 7
  fi

  iptest_reset_baseline
  dport_lo=$((TCP_PORT - 5))
  dport_hi=$((TCP_PORT + 5))
  apply="$(apply_rules "[{\"clientRuleId\":\"m:tcp-dport-range\",\"family\":\"ipv4\",\"action\":\"allow\",\"priority\":10,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"tcp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${IPTEST_PEER_IP}/32\",\"sport\":\"any\",\"dport\":\"${dport_lo}-${dport_hi}\"}]")"
  rid_tcp_range="$(rule_id_from_apply "$apply" "m:tcp-dport-range" | tr -d '\r\n')"
  reset_reasons
  tcp_probe_once "$TCP_PORT"
  reasons="$(get_reasons)"
  printed="$(print_rules)"
  rp="$(reasons_packets "$reasons" "IP_RULE_ALLOW")"
  hp="$(rule_stat_from_print "$printed" "$rid_tcp_range" "hitPackets")"
  if [[ "${rp:-0}" -ge 1 && "${hp:-0}" -ge 1 ]]; then
    log_pass "TCP dport range matches (reasonPackets=$rp hitPackets=$hp)"
  else
    log_fail "TCP dport range matches (reasonPackets=$rp hitPackets=$hp)"
    exit 8
  fi

  iptest_reset_baseline
  miss_lo=$((TCP_PORT + 1))
  miss_hi=$((TCP_PORT + 2))
  apply="$(apply_rules "[{\"clientRuleId\":\"m:tcp-dport-miss\",\"family\":\"ipv4\",\"action\":\"allow\",\"priority\":10,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"tcp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${IPTEST_PEER_IP}/32\",\"sport\":\"any\",\"dport\":\"${miss_lo}-${miss_hi}\"}]")"
  rid_tcp_miss="$(rule_id_from_apply "$apply" "m:tcp-dport-miss" | tr -d '\r\n')"
  reset_reasons
  tcp_probe_once "$TCP_PORT"
  reasons="$(get_reasons)"
  printed="$(print_rules)"
  rp_allow="$(reasons_packets "$reasons" "IP_RULE_ALLOW")"
  rp_def="$(reasons_packets "$reasons" "ALLOW_DEFAULT")"
  hp="$(rule_stat_from_print "$printed" "$rid_tcp_miss" "hitPackets")"
  if [[ "${hp:-0}" -eq 0 && "${rp_allow:-0}" -eq 0 && "${rp_def:-0}" -ge 1 ]]; then
    log_pass "TCP mismatch falls back to ALLOW_DEFAULT (default=$rp_def)"
  else
    log_fail "TCP mismatch falls back to ALLOW_DEFAULT (hitPackets=$hp allow=$rp_allow default=$rp_def)"
    exit 9
  fi

  iptest_reset_baseline
  apply="$(apply_rules "[{\"clientRuleId\":\"m:udp-dport\",\"family\":\"ipv4\",\"action\":\"allow\",\"priority\":10,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"udp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${IPTEST_PEER_IP}/32\",\"sport\":\"any\",\"dport\":\"${UDP_PORT}\"}]")"
  rid_udp="$(rule_id_from_apply "$apply" "m:udp-dport" | tr -d '\r\n')"
  reset_reasons
  udp_send_once "$UDP_PORT" "$FIXED_SPORT"
  reasons="$(get_reasons)"
  printed="$(print_rules)"
  rp="$(reasons_packets "$reasons" "IP_RULE_ALLOW")"
  hp="$(rule_stat_from_print "$printed" "$rid_udp" "hitPackets")"
  if [[ "${rp:-0}" -ge 1 && "${hp:-0}" -ge 1 ]]; then
    log_pass "UDP dport matches (reasonPackets=$rp hitPackets=$hp)"
  else
    log_fail "UDP dport matches (reasonPackets=$rp hitPackets=$hp)"
    exit 10
  fi

  # ----------------------------------------------------------------------
  # CIDR canonicalization (/24)
  # ----------------------------------------------------------------------
  log_section "CIDR canonicalization"
  iptest_reset_baseline
  apply="$(apply_rules "[{\"clientRuleId\":\"m:cidr24\",\"family\":\"ipv4\",\"action\":\"allow\",\"priority\":10,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"icmp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${IPTEST_PEER_IP}/24\",\"sport\":\"any\",\"dport\":\"any\"}]")"
  rid_cidr="$(rule_id_from_apply "$apply" "m:cidr24" | tr -d '\r\n')"
  printed="$(print_rules)"
  expected_cidr="${IPTEST_PEER_IP%.*}.0/24"
  if PRINTED_JSON="$printed" EXPECTED_CIDR="$expected_cidr" python3 - <<'PY' >/dev/null 2>&1
import os, json
j = json.loads(os.environ["PRINTED_JSON"])
expected = os.environ["EXPECTED_CIDR"]
rules = j.get("result", {}).get("rules", [])
assert any(r.get("dst") == expected for r in rules)
PY
  then
    log_pass "IPRULES.PRINT canonicalizes dst=/24"
  else
    log_fail "IPRULES.PRINT canonicalizes dst=/24"
    exit 11
  fi
  reset_reasons
  ping_once
  reasons="$(get_reasons)"
  printed="$(print_rules)"
  rp="$(reasons_packets "$reasons" "IP_RULE_ALLOW")"
  hp="$(rule_stat_from_print "$printed" "$rid_cidr" "hitPackets")"
  if [[ "${rp:-0}" -ge 1 && "${hp:-0}" -ge 1 ]]; then
    log_pass "CIDR /24 rule matches traffic (reasonPackets=$rp hitPackets=$hp)"
  else
    log_fail "CIDR /24 rule matches traffic (reasonPackets=$rp hitPackets=$hp)"
    exit 12
  fi

  # ----------------------------------------------------------------------
  # IFACES.LIST + iface/ifindex match/mismatch
  # ----------------------------------------------------------------------
  log_section "iface/ifindex match"

  ifaces="$(vnext_rpc_ok IFACES.LIST)" || exit $?
  iface_kind="$(IFACES_JSON="$ifaces" IFACE="$IPTEST_VETH0" python3 - <<'PY'
import os, json
j = json.loads(os.environ["IFACES_JSON"])
name = os.environ["IFACE"]
for it in j.get("result", {}).get("ifaces", []):
    if it.get("name") == name:
        print(it.get("kind", ""))
        raise SystemExit(0)
print("")
PY
)" || iface_kind=""
  iface_kind="$(printf '%s' "$iface_kind" | tr -d '\r\n')"
  iface_ifindex="$(IFACES_JSON="$ifaces" IFACE="$IPTEST_VETH0" python3 - <<'PY'
import os, json
j = json.loads(os.environ["IFACES_JSON"])
name = os.environ["IFACE"]
for it in j.get("result", {}).get("ifaces", []):
    if it.get("name") == name:
        print(int(it.get("ifindex", 0)))
        raise SystemExit(0)
print(0)
PY
)" || iface_ifindex="0"
  iface_ifindex="$(printf '%s' "$iface_ifindex" | tr -d '\r\n')"

  if [[ -z "$iface_kind" || ! "$iface_ifindex" =~ ^[0-9]+$ || "$iface_ifindex" -le 0 ]]; then
    log_skip "IFACES.LIST missing $IPTEST_VETH0 kind/ifindex; skip iface tests"
  else
    wrong_kind="wifi"
    if [[ "$iface_kind" == "wifi" ]]; then
      wrong_kind="data"
    fi

    iptest_reset_baseline
    apply="$(apply_rules "[{\"clientRuleId\":\"m:iface-hit\",\"family\":\"ipv4\",\"action\":\"allow\",\"priority\":10,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"${iface_kind}\",\"ifindex\":${iface_ifindex},\"proto\":\"icmp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${IPTEST_PEER_IP}/32\",\"sport\":\"any\",\"dport\":\"any\"}]")"
    rid_iface_hit="$(rule_id_from_apply "$apply" "m:iface-hit" | tr -d '\r\n')"
    reset_reasons
    ping_once
    reasons="$(get_reasons)"
    printed="$(print_rules)"
    rp="$(reasons_packets "$reasons" "IP_RULE_ALLOW")"
    hp="$(rule_stat_from_print "$printed" "$rid_iface_hit" "hitPackets")"
    if [[ "${rp:-0}" -ge 1 && "${hp:-0}" -ge 1 ]]; then
      log_pass "iface+ifindex matches (kind=$iface_kind ifindex=$iface_ifindex)"
    else
      log_fail "iface+ifindex matches (kind=$iface_kind ifindex=$iface_ifindex)"
      exit 13
    fi

    iptest_reset_baseline
    apply="$(apply_rules "[{\"clientRuleId\":\"m:iface-miss\",\"family\":\"ipv4\",\"action\":\"allow\",\"priority\":10,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"${wrong_kind}\",\"ifindex\":${iface_ifindex},\"proto\":\"icmp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${IPTEST_PEER_IP}/32\",\"sport\":\"any\",\"dport\":\"any\"}]")"
    rid_iface_miss="$(rule_id_from_apply "$apply" "m:iface-miss" | tr -d '\r\n')"
    reset_reasons
    ping_once
    reasons="$(get_reasons)"
    printed="$(print_rules)"
    rp_def="$(reasons_packets "$reasons" "ALLOW_DEFAULT")"
    hp="$(rule_stat_from_print "$printed" "$rid_iface_miss" "hitPackets")"
    if [[ "${hp:-0}" -eq 0 && "${rp_def:-0}" -ge 1 ]]; then
      log_pass "wrong iface kind does not match (kind=$wrong_kind)"
    else
      log_fail "wrong iface kind does not match (hitPackets=$hp default=$rp_def)"
      exit 14
    fi
  fi

  # ----------------------------------------------------------------------
  # Priority wins
  # ----------------------------------------------------------------------
  log_section "priority wins"
  iptest_reset_baseline
  peer_24="${IPTEST_PEER_IP%.*}.0/24"
  rules_prio="[{\"clientRuleId\":\"m:p10-allow\",\"family\":\"ipv4\",\"action\":\"allow\",\"priority\":10,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"icmp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${peer_24}\",\"sport\":\"any\",\"dport\":\"any\"},{\"clientRuleId\":\"m:p20-block\",\"family\":\"ipv4\",\"action\":\"block\",\"priority\":20,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"icmp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${IPTEST_PEER_IP}/32\",\"sport\":\"any\",\"dport\":\"any\"}]"
  apply="$(apply_rules "$rules_prio")"
  rid_p20="$(rule_id_from_apply "$apply" "m:p20-block" | tr -d '\r\n')"
  reset_reasons
  ping_once
  reasons="$(get_reasons)"
  printed="$(print_rules)"
  rp="$(reasons_packets "$reasons" "IP_RULE_BLOCK")"
  hp="$(rule_stat_from_print "$printed" "$rid_p20" "hitPackets")"
  if [[ "${rp:-0}" -ge 1 && "${hp:-0}" -ge 1 ]]; then
    log_pass "higher priority wins (block p20)"
  else
    log_fail "higher priority wins (block p20) (reasonPackets=$rp hitPackets=$hp)"
    exit 15
  fi

  # ----------------------------------------------------------------------
  # enabled=0 then enable
  # ----------------------------------------------------------------------
  log_section "enabled toggle"
  iptest_reset_baseline
  apply="$(apply_rules "[{\"clientRuleId\":\"m:disabled\",\"family\":\"ipv4\",\"action\":\"allow\",\"priority\":10,\"enabled\":0,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"icmp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${IPTEST_PEER_IP}/32\",\"sport\":\"any\",\"dport\":\"any\"}]")"
  rid_dis="$(rule_id_from_apply "$apply" "m:disabled" | tr -d '\r\n')"
  reset_reasons
  ping_once
  reasons="$(get_reasons)"
  printed="$(print_rules)"
  hp="$(rule_stat_from_print "$printed" "$rid_dis" "hitPackets")"
  rp_def="$(reasons_packets "$reasons" "ALLOW_DEFAULT")"
  if [[ "${hp:-0}" -eq 0 && "${rp_def:-0}" -ge 1 ]]; then
    log_pass "enabled=0 does not match (default=$rp_def)"
  else
    log_fail "enabled=0 does not match (hitPackets=$hp default=$rp_def)"
    exit 16
  fi

  # Re-apply with enabled=1 using the same clientRuleId.
  apply="$(apply_rules "[{\"clientRuleId\":\"m:disabled\",\"family\":\"ipv4\",\"action\":\"allow\",\"priority\":10,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"icmp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${IPTEST_PEER_IP}/32\",\"sport\":\"any\",\"dport\":\"any\"}]")"
  rid_en="$(rule_id_from_apply "$apply" "m:disabled" | tr -d '\r\n')"
  reset_reasons
  ping_once
  reasons="$(get_reasons)"
  printed="$(print_rules)"
  hp="$(rule_stat_from_print "$printed" "$rid_en" "hitPackets")"
  rp="$(reasons_packets "$reasons" "IP_RULE_ALLOW")"
  if [[ "${rp:-0}" -ge 1 && "${hp:-0}" -ge 1 ]]; then
    log_pass "enabled=1 matches (reasonPackets=$rp hitPackets=$hp)"
  else
    log_fail "enabled=1 matches (reasonPackets=$rp hitPackets=$hp)"
    exit 17
  fi

  # ----------------------------------------------------------------------
  # would-block overlay (STREAM.START pkt)
  # ----------------------------------------------------------------------
  log_section "would-block overlay (accept vs drop)"
  tmp_pkt="$(mktemp)"
  tmp_pkt2="$(mktemp)"
  trap 'rm -f "$tmp_pkt" "$tmp_pkt2" 2>/dev/null || true; cleanup' EXIT

  iptest_reset_baseline
  apply="$(apply_rules "[{\"clientRuleId\":\"m:would\",\"family\":\"ipv4\",\"action\":\"block\",\"priority\":10,\"enabled\":1,\"enforce\":0,\"log\":1,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"icmp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${IPTEST_PEER_IP}/32\",\"sport\":\"any\",\"dport\":\"any\"}]")"
  rid_would="$(rule_id_from_apply "$apply" "m:would" | tr -d '\r\n')"
  reset_reasons
  capture_pkt_stream "$tmp_pkt" 6 200 || exit 1 &
  cap_pid=$!
  sleep 2
  ping_once
  sleep 0.2
  ping_once
  sleep 0.2
  ping_once
  set +e
  wait "$cap_pid"
  set -e
  printed="$(print_rules)"
  would_hits="$(rule_stat_from_print "$printed" "$rid_would" "wouldHitPackets")"
  if [[ "${would_hits:-0}" -ge 1 ]]; then
    log_pass "wouldHitPackets grows under accepted traffic (wouldHitPackets=$would_hits)"
  else
    log_fail "wouldHitPackets grows under accepted traffic (wouldHitPackets=$would_hits)"
    exit 18
  fi
  if assert_pkt_event "$tmp_pkt" "
import json
uid = int('${IPTEST_UID}')
peer = '${IPTEST_PEER_IP}'
rid = int('${rid_would}')
for line in lines:
    if not line.strip():
        continue
    obj = json.loads(line)
    if obj.get('type') != 'pkt':
        continue
    if obj.get('uid') != uid or obj.get('dstIp') != peer or obj.get('protocol') != 'icmp':
        continue
    if bool(obj.get('accepted')) is not True:
        continue
    if obj.get('reasonId') != 'ALLOW_DEFAULT':
        continue
    if int(obj.get('wouldRuleId', -1)) != rid:
        continue
    assert 'ruleId' not in obj
    raise SystemExit(0)
raise SystemExit(2)
"; then
    log_pass "PKT stream carries wouldRuleId on ACCEPT (reason=ALLOW_DEFAULT)"
  else
    log_fail "PKT stream carries wouldRuleId on ACCEPT"
    rg -n "\"wouldRuleId\"" "$tmp_pkt" | head -n 10 || true
    exit 19
  fi

  iptest_reset_baseline
  peer_24="${IPTEST_PEER_IP%.*}.0/24"
  rules_drop="[{\"clientRuleId\":\"m:drop\",\"family\":\"ipv4\",\"action\":\"block\",\"priority\":20,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"icmp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${IPTEST_PEER_IP}/32\",\"sport\":\"any\",\"dport\":\"any\"},{\"clientRuleId\":\"m:would\",\"family\":\"ipv4\",\"action\":\"block\",\"priority\":10,\"enabled\":1,\"enforce\":0,\"log\":1,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"icmp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${peer_24}\",\"sport\":\"any\",\"dport\":\"any\"}]"
  apply="$(apply_rules "$rules_drop")"
  rid_drop="$(rule_id_from_apply "$apply" "m:drop" | tr -d '\r\n')"
  reset_reasons
  capture_pkt_stream "$tmp_pkt2" 6 200 || exit 1 &
  cap_pid=$!
  sleep 2
  ping_once
  sleep 0.2
  ping_once
  set +e
  wait "$cap_pid"
  set -e
  if assert_pkt_event "$tmp_pkt2" "
import json
uid = int('${IPTEST_UID}')
peer = '${IPTEST_PEER_IP}'
rid = int('${rid_drop}')
for line in lines:
    if not line.strip():
        continue
    obj = json.loads(line)
    if obj.get('type') != 'pkt':
        continue
    if obj.get('uid') != uid or obj.get('dstIp') != peer or obj.get('protocol') != 'icmp':
        continue
    if bool(obj.get('accepted')) is not False:
        continue
    if obj.get('reasonId') != 'IP_RULE_BLOCK':
        continue
    assert int(obj.get('ruleId', -1)) == rid
    assert 'wouldRuleId' not in obj
    raise SystemExit(0)
raise SystemExit(2)
"; then
    log_pass "PKT stream does not carry wouldRuleId on DROP (reason=IP_RULE_BLOCK)"
  else
    log_fail "PKT stream does not carry wouldRuleId on DROP"
    rg -n "\"reasonId\":\"IP_RULE_BLOCK\"" "$tmp_pkt2" | head -n 10 || true
    exit 20
  fi

  # ----------------------------------------------------------------------
  # IPv6 rows (Tier-1 dual-stack): CIDR match/no-match, ICMPv6 validation,
  # and fragment classification when feasible.
  # ----------------------------------------------------------------------
  log_section "IPv6 CIDR + ICMPv6"

  set +e
  ping6_once
  ping6_rc=$?
  set -e
  if [[ $ping6_rc -ne 0 ]]; then
    echo "SKIP: ICMPv6 ping not permitted as uid=$IPTEST_UID (rc=$ping6_rc); cannot run IPv6 matrix rows"
    exit 10
  fi

  iptest_reset_baseline
  apply="$(apply_rules "[{\"clientRuleId\":\"m6:icmp-allow\",\"family\":\"ipv6\",\"action\":\"allow\",\"priority\":10,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"icmp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${IPTEST_PEER_IP6}/128\",\"sport\":\"any\",\"dport\":\"any\"}]")"
  rid6_allow="$(rule_id_from_apply "$apply" "m6:icmp-allow" | tr -d '\r\n')"
  reset_reasons
  ping6_once
  reasons="$(get_reasons)"
  printed="$(print_rules)"
  rp="$(reasons_packets "$reasons" "IP_RULE_ALLOW")"
  hp="$(rule_stat_from_print "$printed" "$rid6_allow" "hitPackets")"
  if [[ "${rp:-0}" -ge 1 && "${hp:-0}" -ge 1 ]]; then
    log_pass "IPv6 ICMP allow matches (reasonPackets=$rp hitPackets=$hp)"
  else
    log_fail "IPv6 ICMP allow matches (reasonPackets=$rp hitPackets=$hp)"
    exit 21
  fi

  iptest_reset_baseline
  apply="$(apply_rules "[{\"clientRuleId\":\"m6:cidr-miss\",\"family\":\"ipv6\",\"action\":\"allow\",\"priority\":10,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"icmp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"2001:db8::/64\",\"sport\":\"any\",\"dport\":\"any\"}]")"
  rid6_miss="$(rule_id_from_apply "$apply" "m6:cidr-miss" | tr -d '\r\n')"
  reset_reasons
  ping6_once
  reasons="$(get_reasons)"
  printed="$(print_rules)"
  rp_allow="$(reasons_packets "$reasons" "IP_RULE_ALLOW")"
  rp_def="$(reasons_packets "$reasons" "ALLOW_DEFAULT")"
  hp="$(rule_stat_from_print "$printed" "$rid6_miss" "hitPackets")"
  if [[ "${hp:-0}" -eq 0 && "${rp_allow:-0}" -eq 0 && "${rp_def:-0}" -ge 1 ]]; then
    log_pass "IPv6 CIDR mismatch falls back to ALLOW_DEFAULT (default=$rp_def)"
  else
    log_fail "IPv6 CIDR mismatch falls back to ALLOW_DEFAULT (hitPackets=$hp allow=$rp_allow default=$rp_def)"
    exit 22
  fi

  iptest_reset_baseline
  bad_args="{\"app\":{\"uid\":${IPTEST_UID}},\"rules\":[{\"clientRuleId\":\"m6:icmp-bad-ports\",\"family\":\"ipv6\",\"action\":\"allow\",\"priority\":10,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"icmp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${IPTEST_PEER_IP6}/128\",\"sport\":\"any\",\"dport\":\"443\"}]}"
  # NOTE: This is a negative test (expected ok:false). The control tool may
  # return non-zero rc on app-level validation failure, so we must not use
  # vnext_rpc_ok() here.
  set +e
  bad_apply="$(vnext_ctl_cmd IPRULES.APPLY "$bad_args" 2>/dev/null)"
  bad_rc=$?
  set -e
  if ! is_json "$bad_apply"; then
    echo "BLOCKED: vNext IPRULES.APPLY transport failed (rc=$bad_rc)" >&2
    exit 77
  fi
  if printf '%s\n' "$bad_apply" | python3 -c 'import sys,json; j=json.load(sys.stdin); assert j["ok"] is False' >/dev/null 2>&1; then
    log_pass "IPv6 proto=icmp rejects port constraints"
  else
    log_fail "IPv6 proto=icmp rejects port constraints"
    printf '%s\n' "$bad_apply" | head -n 3 | sed 's/^/    /'
    exit 23
  fi

  # Best-effort fragment classification: send a large ICMPv6 echo and look for l4Status=fragment.
  iptest_reset_baseline
  tmp_frag="$(mktemp /tmp/ipmatrix-v6frag.XXXXXX)"
  capture_pkt_stream "$tmp_frag" 6 200 || exit 1 &
  cap_pid=$!
  sleep 2
  ping6_large_once 4000 || true
  set +e
  wait "$cap_pid"
  set -e
  if assert_pkt_event "$tmp_frag" "
import json
uid = int('${IPTEST_UID}')
peer = '${IPTEST_PEER_IP6}'
for line in lines:
    if not line.strip():
        continue
    obj = json.loads(line)
    if obj.get('type') != 'pkt':
        continue
    if obj.get('uid') != uid or obj.get('dstIp') != peer:
        continue
    if obj.get('l4Status') != 'fragment':
        continue
    assert int(obj.get('srcPort', -1)) == 0
    assert int(obj.get('dstPort', -1)) == 0
    raise SystemExit(0)
raise SystemExit(2)
"; then
    log_pass "IPv6 fragment classification observed in pkt stream"
  else
    log_skip "IPv6 fragment classification not observed (best-effort)"
  fi
  rm -f "$tmp_frag" >/dev/null 2>&1 || true

  log_pass "matrix ok"
  exit 0
}

main "$@"
