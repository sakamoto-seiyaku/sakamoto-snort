#!/bin/bash

set -euo pipefail

CASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$CASE_DIR/../lib.sh"

log_section "flow telemetry matrix (tier1; FLOW + DNS_DECISION)"

CONSUMER_TIMEOUT_SEC="${IPTEST_TELEMETRY_TIMEOUT_SEC:-20}"
CONSUMER_POLL_MS="${IPTEST_TELEMETRY_POLL_MS:-80}"
CONSUMER_COLLECT_MS="${IPTEST_TELEMETRY_COLLECT_MS:-12000}"
GAP_COLLECT_MS="${IPTEST_TELEMETRY_GAP_COLLECT_MS:-3500}"
GAP_POLL_MS="${IPTEST_TELEMETRY_GAP_POLL_MS:-350}"

export IPTEST_UID="${IPTEST_UID:-2000}"

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

assert_json_ok() {
  local desc="$1"
  local json="$2"
  if printf '%s\n' "$json" | python3 -c 'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True' >/dev/null 2>&1; then
    log_pass "$desc"
    return 0
  fi
  log_fail "$desc"
  printf '%s\n' "$json" | head -n 3 | sed 's/^/    /'
  exit 1
}

start_consumer() {
  local out_path="$1"
  local collect_ms="$2"
  local want_flow="$3"
  local want_dns="$4"
  local extra_args="${5:-}"
  local consumer_bin="${IPTEST_TELEMETRY_CONSUMER_DEVICE_BIN:-/data/local/tmp/sucre-snort-telemetry-consumer}"
  local cmd
  cmd="$consumer_bin --timeoutSec ${CONSUMER_TIMEOUT_SEC} --pollMs ${CONSUMER_POLL_MS} --collectMs ${collect_ms} --wantFlow ${want_flow} --wantDns ${want_dns} --jsonl --packetsThreshold 1 --bytesThreshold 1 --maxExportIntervalMs 1 ${extra_args}"

  set +e
  adb_cmd shell "su 0 sh -c \"$cmd\"" >"$out_path" 2>&1 &
  CONSUMER_PID=$!
  set -e
  sleep 0.5
}

wait_consumer() {
  local desc="$1"
  local out_path="$2"
  local rc

  set +e
  wait "$CONSUMER_PID"
  rc=$?
  set -e
  CONSUMER_PID=""

  if [[ $rc -ne 0 ]]; then
    log_fail "$desc"
    echo "    consumer_rc=$rc"
    sed -n '1,160p' "$out_path" | sed 's/^/    /'
    exit 1
  fi
  log_pass "$desc"
}

apply_single_rule() {
  local label="$1"
  local family="$2"
  local action="$3"
  local proto="$4"
  local dst="$5"
  local dport="$6"
  local priority="$7"
  local out
  local args
  args="{\"app\":{\"uid\":${IPTEST_UID}},\"rules\":[{\"clientRuleId\":\"ft:${label}\",\"family\":\"${family}\",\"action\":\"${action}\",\"priority\":${priority},\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"${proto}\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${dst}\",\"sport\":\"any\",\"dport\":\"${dport}\"}]}"
  ctl_or_block out IPRULES.APPLY "$args" "IPRULES.APPLY($label) failed" || return $?
  assert_json_ok "FT-RULE $label apply ok" "$out"
}

iface_kind_bit_for_tier1() {
  local iface_index ifaces_json iface_kind
  iface_index="$(iptest_iface_ifindex "$IPTEST_VETH0" 2>/dev/null || true)"
  if [[ "$iface_index" =~ ^[0-9]+$ ]]; then
    ifaces_json="$(vnext_ctl_cmd IFACES.LIST 2>/dev/null || true)"
    iface_kind="$(IFACES_JSON="$ifaces_json" IFINDEX="$iface_index" python3 - <<'PY'
import os, json
j = json.loads(os.environ.get("IFACES_JSON") or "{}")
want = int(os.environ["IFINDEX"])
for it in j.get("result", {}).get("ifaces", []):
    try:
        if int(it.get("ifindex", -1)) == want:
            print(it.get("kind", ""))
            raise SystemExit(0)
    except Exception:
        pass
print("")
PY
    )" || iface_kind=""
    case "$iface_kind" in
      wifi) printf '1\n'; return 0 ;;
      data) printf '2\n'; return 0 ;;
      vpn) printf '4\n'; return 0 ;;
      unmanaged) printf '128\n'; return 0 ;;
    esac
  fi
  printf '128\n'
}

udp4_send_once() {
  local port="$1"
  iptest_adb_as_uid "$IPTEST_UID" "timeout 2 sh -c 'printf x | nc -u -w 1 \"$IPTEST_PEER_IP\" \"$port\" >/dev/null 2>&1' || true" >/dev/null 2>&1
}

udp6_send_once() {
  local port="$1"
  iptest_adb_as_uid "$IPTEST_UID" "timeout 2 sh -c 'printf x | nc ${IPTEST_NC6_FLAG} -u -w 1 \"$IPTEST_PEER_IP6\" \"$port\" >/dev/null 2>&1' || true" >/dev/null 2>&1
}

ping4_large_once() {
  local size="$1"
  iptest_adb_as_uid "$IPTEST_UID" "ping -s \"$size\" -c 1 -W 2 \"$IPTEST_PEER_IP\" >/dev/null 2>&1 || true" >/dev/null 2>&1
}

ping6_large_once() {
  local size="$1"
  iptest_detect_ping6_cmd >/dev/null 2>&1 || return 1
  iptest_adb_as_uid "$IPTEST_UID" "$IPTEST_PING6_CMD -s \"$size\" -c 1 -W 2 \"$IPTEST_PEER_IP6\" >/dev/null 2>&1 || true" >/dev/null 2>&1
}

other4_send() {
  iptest_adb_as_uid "$IPTEST_UID" "\"$IPTEST_RAW_PROTO_DEVICE_BIN\" --family 4 --dst \"$IPTEST_PEER_IP\" --proto 136 --count 3 --payloadBytes 32 >/dev/null 2>&1 || true" >/dev/null 2>&1
}

other6_send() {
  iptest_adb_as_uid "$IPTEST_UID" "\"$IPTEST_RAW_PROTO_DEVICE_BIN\" --family 6 --dst \"$IPTEST_PEER_IP6\" --proto 136 --count 3 --payloadBytes 32 >/dev/null 2>&1 || true" >/dev/null 2>&1
}

invalid4_send() {
  adb_su "\"$IPTEST_RAW_PROTO_DEVICE_BIN\" --family 4 --dst \"$IPTEST_PEER_IP\" --proto 6 --count 2 --payloadBytes 20 >/dev/null 2>&1 || true" >/dev/null 2>&1
}

invalid6_send() {
  adb_su "\"$IPTEST_RAW_PROTO_DEVICE_BIN\" --family 6 --dst \"$IPTEST_PEER_IP6\" --proto 6 --count 2 --payloadBytes 1 >/dev/null 2>&1 || true" >/dev/null 2>&1
}

fragment4_send() {
  adb_su "\"$IPTEST_RAW_PROTO_DEVICE_BIN\" --family 4 --src \"$IPTEST_HOST_IP\" --dst \"$IPTEST_PEER_IP\" --ipv4Fragment --count 2 --payloadBytes 16 >/dev/null 2>&1 || true" >/dev/null 2>&1
}

assert_matrix_output() {
  local out_path="$1"
  local blocked_domain="$2"
  local allowed_domain="$3"
  OUT_PATH="$out_path" BLOCKED_DOMAIN="$blocked_domain" ALLOWED_DOMAIN="$allowed_domain" python3 - <<'PY'
import json
import os
import sys
from pathlib import Path

path = Path(os.environ["OUT_PATH"])
records = []
for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
    line = line.strip()
    if not line.startswith("{"):
        continue
    try:
        records.append(json.loads(line))
    except json.JSONDecodeError:
        pass

flows = [r for r in records if r.get("type") == "FLOW"]
dns = [r for r in records if r.get("type") == "DNS_DECISION"]
summary = next((r for r in reversed(records) if r.get("type") == "summary"), {})

def need(ok: bool, msg: str) -> None:
    if not ok:
        print(f"missing: {msg}", file=sys.stderr)
        print(f"flow_count={len(flows)} dns_count={len(dns)} summary={summary}", file=sys.stderr)
        dist = {}
        for flow in flows:
            key = (bool(flow.get("isIpv6")), flow.get("proto"), flow.get("reason"), flow.get("verdict"))
            dist[key] = dist.get(key, 0) + 1
        for key, count in sorted(dist.items(), key=lambda item: (str(item[0]), item[1]))[:40]:
            print(f"flow_dist {key} count={count}", file=sys.stderr)
        for flow in flows[:20]:
            print("flow_sample " + json.dumps(flow, ensure_ascii=False, sort_keys=True), file=sys.stderr)
        raise SystemExit(1)

def has_flow(**want) -> bool:
    for flow in flows:
        ok = True
        for key, value in want.items():
            if flow.get(key) != value:
                ok = False
                break
        if ok:
            return True
    return False

need(has_flow(isIpv6=False, proto=6), "IPv4 TCP FLOW")
need(has_flow(isIpv6=False, proto=17), "IPv4 UDP FLOW")
need(has_flow(isIpv6=False, proto=1), "IPv4 ICMP FLOW")
need(has_flow(isIpv6=False, proto=136), "IPv4 other-proto FLOW")
need(has_flow(isIpv6=True, proto=6), "IPv6 TCP FLOW")
need(has_flow(isIpv6=True, proto=17), "IPv6 UDP FLOW")
need(has_flow(isIpv6=True, proto=58), "IPv6 ICMP FLOW")
need(has_flow(isIpv6=True, proto=136), "IPv6 other-proto FLOW")

family_by_flow_id = {}
for flow in flows:
    flow_id = flow.get("flowInstanceId")
    if not isinstance(flow_id, int):
        continue
    family = bool(flow.get("isIpv6"))
    if flow_id in family_by_flow_id:
        need(family_by_flow_id[flow_id] == family, f"flowInstanceId {flow_id} reused across IPv4/IPv6")
    else:
        family_by_flow_id[flow_id] = family

for reason in ("ALLOW_DEFAULT", "IP_RULE_ALLOW", "IP_RULE_BLOCK", "IFACE_BLOCK"):
    need(any(f.get("reason") == reason for f in flows), f"{reason} FLOW")

for flow in flows:
    need(int(flow.get("payloadSize", 0)) >= 160, "replacement FLOW payload size")
    need(flow.get("observationKind") in ("NORMAL", "L3_OBSERVATION"), "observationKind exported")
    need(flow.get("packetDir") in ("in", "out", "unknown"), "packetDir exported")
    need(flow.get("flowOriginDir") in ("in", "out", "unknown"), "flowOriginDir exported")
    need(flow.get("verdict") in ("allow", "block", "unknown"), "explicit verdict exported")
    need(isinstance(flow.get("firstSeenNs"), int), "firstSeenNs exported")
    need(isinstance(flow.get("lastSeenNs"), int), "lastSeenNs exported")
    need(flow.get("firstSeenNs") > 0, "firstSeenNs non-zero")
    need(flow.get("lastSeenNs") >= flow.get("firstSeenNs"), "lastSeenNs >= firstSeenNs")
    if flow.get("packetDir") in ("in", "out"):
        need(flow.get("flowOriginDir") in ("in", "out"), "flowOriginDir known for directed packet")
    total_pk = int(flow.get("totalPackets", -1))
    in_pk = int(flow.get("inPackets", -1))
    out_pk = int(flow.get("outPackets", -1))
    need(total_pk == in_pk + out_pk, "direction packet counters sum to total")
    need(isinstance(flow.get("uidKnown"), bool), "uidKnown exported")
    need(isinstance(flow.get("ifindexKnown"), bool), "ifindexKnown exported")
    need(isinstance(flow.get("portsAvailable"), bool), "portsAvailable exported")

for reason, verdict in (("IP_RULE_ALLOW", "allow"), ("IP_RULE_BLOCK", "block"), ("IFACE_BLOCK", "block")):
    need(any(f.get("reason") == reason and f.get("verdict") == verdict for f in flows),
         f"{reason} explicit {verdict} verdict")

need(any(f.get("proto") in (1, 58) and isinstance(f.get("icmpType"), int)
         and isinstance(f.get("icmpCode"), int) and isinstance(f.get("icmpId"), int)
         and f.get("portsAvailable") is False
         for f in flows), "ICMP facts without ports")

need(any(f.get("proto") in (6, 17) and f.get("portsAvailable") is True
         for f in flows), "TCP/UDP portsAvailable true")

fragment_observed = any(f.get("observationKind") == "L3_OBSERVATION" and int(f.get("l4Status", -1)) == 2
                        and f.get("portsAvailable") is False and int(f.get("srcPort", -1)) == 0
                        and int(f.get("dstPort", -1)) == 0
                        for f in flows)
if os.environ.get("IPTEST_REQUIRE_FLOW_FRAGMENT", "0") == "1":
    need(fragment_observed, "fragment L3 observation")
elif not fragment_observed:
    print("note: fragment L3 observation not observed; Android NFQUEUE may defrag or bypass raw fragments",
          file=sys.stderr)

need(any(f.get("observationKind") == "L3_OBSERVATION" and int(f.get("l4Status", -1)) == 3
         and f.get("portsAvailable") is False and int(f.get("srcPort", -1)) == 0
         and int(f.get("dstPort", -1)) == 0
         for f in flows), "invalid L4 L3 observation")

blocked = os.environ["BLOCKED_DOMAIN"]
allowed = os.environ["ALLOWED_DOMAIN"]
need(any(d.get("queryName") == blocked for d in dns), "blocked DNS_DECISION")
need(not any(d.get("queryName") == allowed for d in dns), "allowed DNS must not emit DNS_DECISION")
print("matrix ok")
PY
}

assert_gap_output() {
  local out_path="$1"
  OUT_PATH="$out_path" python3 - <<'PY'
import json
import os
import sys
from pathlib import Path

records = []
for line in Path(os.environ["OUT_PATH"]).read_text(encoding="utf-8", errors="replace").splitlines():
    line = line.strip()
    if line.startswith("{"):
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            pass

flows = [r for r in records if r.get("type") == "FLOW"]
summary = next((r for r in reversed(records) if r.get("type") == "summary"), {})
if not any(f.get("recordSeqGap") is True for f in flows) and int(summary.get("recordSeqGaps", 0)) < 1:
    print(f"missing recordSeq gap visibility: flow_count={len(flows)} summary={summary}", file=sys.stderr)
    raise SystemExit(1)
print("gap ok")
PY
}

if ! iptest_require_tier1_prereqs; then
  echo "BLOCKED: tier1 prereqs missing (need root + ip/netns/veth + ping + nc)" >&2
  exit 77
fi

if ! vnext_preflight; then
  exit 77
fi

for stage_fn in iptest_stage_telemetry_consumer iptest_stage_raw_proto_binary iptest_stage_dx_netd_injector; do
  set +e
  "$stage_fn"
  rc=$?
  set -e
  if [[ $rc -eq 10 ]]; then
    echo "SKIP: $stage_fn unavailable" >&2
    exit 10
  fi
  if [[ $rc -ne 0 ]]; then
    exit "$rc"
  fi
done

tmp_dir="$(mktemp -d)"
table=""
CONSUMER_PID=""
cleanup() {
  set +e
  if [[ -n "$CONSUMER_PID" ]]; then
    kill "$CONSUMER_PID" >/dev/null 2>&1 || true
    wait "$CONSUMER_PID" >/dev/null 2>&1 || true
  fi
  vnext_ctl_cmd CONFIG.SET "{\"scope\":\"app\",\"app\":{\"uid\":${IPTEST_UID}},\"set\":{\"block.ifaceKindMask\":0}}" >/dev/null 2>&1 || true
  if [[ -n "$table" ]]; then
    iptest_tier1_teardown "$table" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

ctl_or_block resetall RESETALL "" "vNext RESETALL failed" || exit $?
assert_json_ok "FT-00 RESETALL ok" "$resetall"
ctl_or_block cfg_dev CONFIG.SET '{"scope":"device","set":{"block.enabled":1,"iprules.enabled":1}}' "CONFIG.SET(device) failed" || exit $?
assert_json_ok "FT-00 CONFIG.SET device ok" "$cfg_dev"

table="$(iptest_tier1_setup)" || exit $?
log_info "tier1 table=$table"

tcp4_port=443
tcp6_port=4443
udp4_port=53531
udp6_port=53532

iptest_tier1_start_tcp_zero_server "$tcp4_port" >/dev/null 2>&1 || {
  echo "BLOCKED: failed to start tier1 tcp server (port=$tcp4_port)" >&2
  exit 77
}
adb_su "ip netns exec \"$IPTEST_NS\" sh -c 'nc ${IPTEST_NC6_FLAG} -p \"$tcp6_port\" -L cat /dev/zero >/dev/null 2>&1 & echo \$!'" >/dev/null 2>&1 || {
  echo "SKIP: failed to start tier1 ipv6 tcp server (port=$tcp6_port)" >&2
  exit 10
}

# Ensure the UID selector exists, then enable per-app config used by IFACE_BLOCK.
iptest_adb_as_uid "$IPTEST_UID" "ping -c 1 -W 1 \"$IPTEST_PEER_IP\" >/dev/null 2>&1 || true" >/dev/null 2>&1 || true
ctl_or_block cfg_app CONFIG.SET "{\"scope\":\"app\",\"app\":{\"uid\":${IPTEST_UID}},\"set\":{\"tracked\":1,\"block.ifaceKindMask\":0}}" "CONFIG.SET(app) failed" || exit $?
assert_json_ok "FT-00 CONFIG.SET app ok" "$cfg_app"

blocked_domain="ft-blocked-$(date +%s).example.com"
allowed_domain="ft-allowed-$(date +%s).example.com"
policy_args="{\"scope\":\"device\",\"policy\":{\"allow\":{\"domains\":[\"${allowed_domain}\"],\"ruleIds\":[]},\"block\":{\"domains\":[\"${blocked_domain}\"],\"ruleIds\":[]}}}"
ctl_or_block dns_policy DOMAINPOLICY.APPLY "$policy_args" "DOMAINPOLICY.APPLY failed" || exit $?
assert_json_ok "FT-DNS policy apply ok" "$dns_policy"

matrix_out="$tmp_dir/telemetry_matrix.jsonl"
start_consumer "$matrix_out" "$CONSUMER_COLLECT_MS" 10 1 ""

log_info "triggering default-allow IPv4/IPv6 TCP/UDP/ICMP/other traffic..."
iptest_tier1_ping_once || true
iptest_tier1_ping6_once || true
iptest_tier1_tcp_read_bytes "$tcp4_port" 4096 "$IPTEST_UID" >/dev/null 2>&1 || true
iptest_adb_as_uid "$IPTEST_UID" "nc ${IPTEST_NC6_FLAG} -n -w 5 \"$IPTEST_PEER_IP6\" \"$tcp6_port\" | head -c 4096 >/dev/null 2>&1 || true" >/dev/null 2>&1 || true
udp4_send_once "$udp4_port" || true
udp6_send_once "$udp6_port" || true
other4_send || true
other6_send || true
ping4_large_once 4000 || true
ping6_large_once 4000 || true
fragment4_send || true
invalid4_send || true
invalid6_send || true

log_info "triggering IP_RULE_ALLOW/IP_RULE_BLOCK/IFACE_BLOCK decisions..."
apply_single_rule "ipv4-allow" "ipv4" "allow" "tcp" "${IPTEST_PEER_IP}/32" "$tcp4_port" 10
iptest_tier1_tcp_read_bytes "$tcp4_port" 2048 "$IPTEST_UID" >/dev/null 2>&1 || true

apply_single_rule "ipv4-block" "ipv4" "block" "tcp" "${IPTEST_PEER_IP}/32" "$tcp4_port" 11
iptest_adb_as_uid "$IPTEST_UID" "nc -n -z -w 1 \"$IPTEST_PEER_IP\" \"$tcp4_port\" >/dev/null 2>&1 || true" >/dev/null 2>&1 || true

iface_bit="$(iface_kind_bit_for_tier1)"
ctl_or_block cfg_iface CONFIG.SET "{\"scope\":\"app\",\"app\":{\"uid\":${IPTEST_UID}},\"set\":{\"block.ifaceKindMask\":${iface_bit}}}" "CONFIG.SET(block.ifaceKindMask) failed" || exit $?
assert_json_ok "FT-IFACE block.ifaceKindMask set ok" "$cfg_iface"
iptest_adb_as_uid "$IPTEST_UID" "nc -n -z -w 1 \"$IPTEST_PEER_IP\" \"$tcp4_port\" >/dev/null 2>&1 || true" >/dev/null 2>&1 || true
ctl_or_block cfg_iface0 CONFIG.SET "{\"scope\":\"app\",\"app\":{\"uid\":${IPTEST_UID}},\"set\":{\"block.ifaceKindMask\":0}}" "restore block.ifaceKindMask failed" || exit $?
assert_json_ok "FT-IFACE block.ifaceKindMask restore ok" "$cfg_iface0"

apply_single_rule "ipv6-allow" "ipv6" "allow" "tcp" "${IPTEST_PEER_IP6}/128" "$tcp6_port" 20
iptest_adb_as_uid "$IPTEST_UID" "nc ${IPTEST_NC6_FLAG} -n -w 5 \"$IPTEST_PEER_IP6\" \"$tcp6_port\" | head -c 2048 >/dev/null 2>&1 || true" >/dev/null 2>&1 || true

apply_single_rule "ipv6-block" "ipv6" "block" "tcp" "${IPTEST_PEER_IP6}/128" "$tcp6_port" 21
iptest_adb_as_uid "$IPTEST_UID" "nc ${IPTEST_NC6_FLAG} -n -z -w 1 \"$IPTEST_PEER_IP6\" \"$tcp6_port\" >/dev/null 2>&1 || true" >/dev/null 2>&1 || true

log_info "triggering DNS blocked + allowed synthetic netd decisions..."
adb_su "\"$DX_NETD_INJECT_DEVICE_BIN\" --uid \"$IPTEST_UID\" --domain \"$blocked_domain\"" >/dev/null 2>&1 || {
  echo "BLOCKED: dx-netd-inject failed for blocked domain" >&2
  exit 77
}
adb_su "\"$DX_NETD_INJECT_DEVICE_BIN\" --uid \"$IPTEST_UID\" --domain \"$allowed_domain\"" >/dev/null 2>&1 || {
  echo "BLOCKED: dx-netd-inject failed for allowed domain" >&2
  exit 77
}

wait_consumer "FT-01 telemetry consumer completed matrix collection" "$matrix_out"
assert_matrix_output "$matrix_out" "$blocked_domain" "$allowed_domain"
log_pass "FT-02 FLOW matrix + blocked-only DNS_DECISION assertions ok"

gap_out="$tmp_dir/telemetry_gap.jsonl"
start_consumer "$gap_out" "$GAP_COLLECT_MS" 1 0 "--slotBytes 1024 --ringDataBytes 1024 --pollMs ${GAP_POLL_MS}"
log_info "triggering sustained one-flow TCP stream for recordSeq gap visibility..."
iptest_tier1_tcp_stream_count_bytes "$tcp4_port" 2 "$IPTEST_UID" >/dev/null 2>&1 || true
wait_consumer "FT-03 tiny-ring telemetry consumer completed gap collection" "$gap_out"
assert_gap_output "$gap_out"
log_pass "FT-04 per-flow recordSeq gap visibility observed"

sed -n '1,30p' "$matrix_out" | sed 's/^/    /'
sed -n '1,20p' "$gap_out" | sed 's/^/    /'

exit 0
