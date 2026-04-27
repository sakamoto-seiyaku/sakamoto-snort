#!/bin/bash

set -euo pipefail

CASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$CASE_DIR/../lib.sh"

log_section "iprules vNext datapath smoke (tier1)"

VNEXT_PORT="${VNEXT_PORT:-60607}"
SNORT_CTL="${SNORT_CTL:-}"

find_snort_ctl() {
  if [[ -n "$SNORT_CTL" ]]; then
    if [[ -x "$SNORT_CTL" ]]; then
      printf '%s\n' "$SNORT_CTL"
      return 0
    fi
    echo "❌ sucre-snort-ctl 不可执行: $SNORT_CTL" >&2
    return 1
  fi

  local candidates=(
    "$SNORT_ROOT/build-output/cmake/dev-debug/tests/host/sucre-snort-ctl"
    "$SNORT_ROOT/build-output/cmake/dev-relwithdebinfo/tests/host/sucre-snort-ctl"
    "$SNORT_ROOT/build-output/cmake/host-asan-clang/tests/host/sucre-snort-ctl"
  )

  local c
  for c in "${candidates[@]}"; do
    if [[ -x "$c" ]]; then
      printf '%s\n' "$c"
      return 0
    fi
  done

  echo "❌ 未找到 sucre-snort-ctl；请先构建 clang host preset（例如: cmake --build --preset dev-debug --target sucre-snort-ctl）" >&2
  return 1
}

ctl_cmd() {
  local cmd="$1"
  local args_json="${2:-}"
  if [[ -n "$args_json" ]]; then
    "$SNORT_CTL" --tcp "127.0.0.1:${VNEXT_PORT}" --compact "$cmd" "$args_json"
  else
    "$SNORT_CTL" --tcp "127.0.0.1:${VNEXT_PORT}" --compact "$cmd"
  fi
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
  return 1
}

ctl_json_or_block() {
  local out_var="$1"
  local cmd="$2"
  local args_json="${3:-}"
  local block_msg="${4:-$cmd failed}"
  local result st

  set +e
  if [[ -n "$args_json" ]]; then
    result="$(ctl_cmd "$cmd" "$args_json" 2>/dev/null)"
  else
    result="$(ctl_cmd "$cmd" 2>/dev/null)"
  fi
  st=$?
  set -e
  if [[ $st -ne 0 ]]; then
    echo "BLOCKED: $block_msg" >&2
    exit 77
  fi
  printf -v "$out_var" '%s' "$result"
}

assert_or_exit() {
  assert_json_pred "$@" || exit 1
}

metrics_reset_reasons() {
  local desc="$1" out
  ctl_json_or_block out METRICS.RESET '{"name":"reasons"}' "METRICS.RESET(reasons) failed"
  assert_or_exit "$desc" "$out" \
    'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True'
}

metrics_reset_traffic() {
  local desc="$1" out
  ctl_json_or_block out METRICS.RESET "{\"name\":\"traffic\",\"app\":{\"uid\":${app_uid}}}" "METRICS.RESET(traffic,app) failed"
  assert_or_exit "$desc" "$out" \
    'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True'
}

metrics_get_reasons() {
  local out
  ctl_json_or_block out METRICS.GET '{"name":"reasons"}' "METRICS.GET(reasons) failed"
  printf '%s\n' "$out"
}

metrics_get_traffic() {
  local out
  ctl_json_or_block out METRICS.GET "{\"name\":\"traffic\",\"app\":{\"uid\":${app_uid}}}" "METRICS.GET(traffic,app) failed"
  printf '%s\n' "$out"
}

assert_reasons_zero() {
  local desc="$1" json
  json="$(metrics_get_reasons)"
  assert_or_exit "$desc" "$json" \
    'import sys,json; j=json.load(sys.stdin); r=j["result"]["reasons"]; assert sum(int(v["packets"]) for v in r.values())==0; assert sum(int(v["bytes"]) for v in r.values())==0'
}

assert_reason_bucket_ge() {
  local desc="$1" reason="$2" field="$3" min="$4" json
  json="$(metrics_get_reasons)"
  REASON="$reason" FIELD="$field" MIN="$min" assert_or_exit "$desc" "$json" \
    'import os,sys,json; j=json.load(sys.stdin); r=j["result"]["reasons"][os.environ["REASON"]]; assert int(r[os.environ["FIELD"]]) >= int(os.environ["MIN"])'
}

assert_traffic_zero() {
  local desc="$1" json
  json="$(metrics_get_traffic)"
  assert_or_exit "$desc" "$json" \
    'import sys,json; j=json.load(sys.stdin); t=j["result"]["traffic"]; total=0; \
     total += int(t["dns"]["allow"])+int(t["dns"]["block"]); \
     total += int(t["rxp"]["allow"])+int(t["rxp"]["block"]); \
     total += int(t["rxb"]["allow"])+int(t["rxb"]["block"]); \
     total += int(t["txp"]["allow"])+int(t["txp"]["block"]); \
     total += int(t["txb"]["allow"])+int(t["txb"]["block"]); \
     assert total==0'
}

assert_traffic_bucket_ge() {
  local desc="$1" dimension="$2" verdict="$3" min="$4" json
  json="$(metrics_get_traffic)"
  DIMENSION="$dimension" VERDICT="$verdict" MIN="$min" assert_or_exit "$desc" "$json" \
    'import os,sys,json; j=json.load(sys.stdin); t=j["result"]["traffic"]; assert int(t[os.environ["DIMENSION"]][os.environ["VERDICT"]]) >= int(os.environ["MIN"])'
}

single_rule_id() {
  APPLY_JSON="$1" python3 - <<'PY'
import json
import os

j = json.loads(os.environ["APPLY_JSON"])
rules = j["result"]["rules"]
print(rules[0]["ruleId"] if rules else "")
PY
}

rule_id_by_client() {
  APPLY_JSON="$1" CLIENT_RULE_ID="$2" python3 - <<'PY'
import json
import os

j = json.loads(os.environ["APPLY_JSON"])
want = os.environ["CLIENT_RULE_ID"]
for rule in j.get("result", {}).get("rules", []):
    if rule.get("clientRuleId") == want:
        print(rule.get("ruleId", ""))
        raise SystemExit(0)
print("")
PY
}

rule_stat() {
  local rule_id="$1" stat_name="$2" printed
  ctl_json_or_block printed IPRULES.PRINT "{\"app\":{\"uid\":${app_uid}}}" "IPRULES.PRINT failed"
  IP_PRINT_JSON="$printed" RULE_ID="$rule_id" STAT_NAME="$stat_name" python3 - <<'PY'
import json
import os

j = json.loads(os.environ["IP_PRINT_JSON"])
rid = int(os.environ["RULE_ID"])
stat = os.environ["STAT_NAME"]
for rule in j.get("result", {}).get("rules", []):
    if int(rule.get("ruleId", -1)) == rid:
        print(int(rule.get("stats", {}).get(stat, 0)))
        raise SystemExit(0)
print(0)
PY
}

assert_rule_stat_ge() {
  local desc="$1" rule_id="$2" stat_name="$3" min="$4" value
  value="$(rule_stat "$rule_id" "$stat_name")" || value="0"
  if [[ "$value" =~ ^[0-9]+$ && "$value" -ge "$min" ]]; then
    log_pass "$desc ($stat_name=$value)"
  else
    log_fail "$desc"
    echo "    ruleId=$rule_id $stat_name=$value min=$min"
    exit 1
  fi
}

assert_rule_stat_eq() {
  local desc="$1" rule_id="$2" stat_name="$3" expected="$4" value
  value="$(rule_stat "$rule_id" "$stat_name")" || value="0"
  if [[ "$value" == "$expected" ]]; then
    log_pass "$desc ($stat_name=$value)"
  else
    log_fail "$desc"
    echo "    ruleId=$rule_id $stat_name expected=$expected actual=$value"
    exit 1
  fi
}

tcp_probe_once() {
  set +e
  iptest_adb_shell "nc -n -z -w 1 \"$IPTEST_PEER_IP\" 443 >/dev/null 2>&1"
  local rc=$?
  set -e
  return "$rc"
}

trigger_tcp_expect_success() {
  local desc="$1" ok=0
  for _ in 1 2 3; do
    if tcp_probe_once; then
      ok=1
    fi
  done
  if [[ $ok -eq 1 ]]; then
    log_pass "$desc"
  else
    log_fail "$desc"
    exit 1
  fi
}

trigger_tcp_expect_failure() {
  local desc="$1" ok=0
  for _ in 1 2 3; do
    if tcp_probe_once; then
      ok=1
    fi
  done
  if [[ $ok -eq 0 ]]; then
    log_pass "$desc"
  else
    log_fail "$desc"
    echo "    at least one nc -z probe unexpectedly succeeded"
    exit 1
  fi
}

tcp6_probe_once() {
  local port="$1"
  set +e
  iptest_adb_shell "nc ${IPTEST_NC6_FLAG} -n -z -w 1 \"$IPTEST_PEER_IP6\" \"$port\" >/dev/null 2>&1"
  local rc=$?
  set -e
  return "$rc"
}

trigger_tcp6_expect_success() {
  local desc="$1" port="$2" ok=0
  for _ in 1 2 3; do
    if tcp6_probe_once "$port"; then
      ok=1
    fi
  done
  if [[ $ok -eq 1 ]]; then
    log_pass "$desc"
  else
    log_fail "$desc"
    exit 1
  fi
}

trigger_tcp6_expect_failure() {
  local desc="$1" port="$2" ok=0
  for _ in 1 2 3; do
    if tcp6_probe_once "$port"; then
      ok=1
    fi
  done
  if [[ $ok -eq 0 ]]; then
    log_pass "$desc"
  else
    log_fail "$desc"
    echo "    at least one nc -z probe unexpectedly succeeded"
    exit 1
  fi
}

udp6_send_once() {
  local port="$1"
  # On some Android builds, `nc -u` can hang despite `-q/-w`. Wrap in `timeout`
  # to keep Tier-1 smoke deterministic; tolerate failures.
  iptest_adb_shell "timeout 3 sh -c 'printf x | nc ${IPTEST_NC6_FLAG} -n -u -w 1 -q 1 \"$IPTEST_PEER_IP6\" \"$port\" >/dev/null 2>&1' >/dev/null 2>&1 || true" >/dev/null 2>&1
}

PKT_CAPTURE_DIR=""
PKT_CAPTURE_PID=""

pkt_capture_begin() {
  local mode="$1"
  local direction="$2"
  local reason="$3"
  local accepted="$4"
  local rule_id="${5:-}"
  local would_rule_id="${6:-}"
  local no_rule_id="${7:-0}"
  local no_would_rule_id="${8:-0}"
  local dport="${9:-443}"
  local src_ip="${10:-}"
  local sport="${11:-}"
  local dst_ip="${12:-$IPTEST_PEER_IP}"
  local l4_status="${13:-known-l4}"

  PKT_CAPTURE_DIR="$(mktemp -d)"
  local ready_file="$PKT_CAPTURE_DIR/stream_ready"

  VNEXT_PORT="$VNEXT_PORT" \
    EXPECT_MODE="$mode" \
    EXPECT_UID="$app_uid" \
    EXPECT_DIRECTION="$direction" \
    EXPECT_SRC="$src_ip" \
    EXPECT_DST="$dst_ip" \
    EXPECT_SPORT="$sport" \
    EXPECT_DPORT="$dport" \
    EXPECT_L4_STATUS="$l4_status" \
    EXPECT_REASON="$reason" \
    EXPECT_ACCEPTED="$accepted" \
    EXPECT_RULE_ID="$rule_id" \
    EXPECT_WOULD_RULE_ID="$would_rule_id" \
    EXPECT_NO_RULE_ID="$no_rule_id" \
    EXPECT_NO_WOULD_RULE_ID="$no_would_rule_id" \
    READY_FILE="$ready_file" \
    python3 - <<'PY' &
import json
import os
import socket
import sys
import time

PORT = int(os.environ["VNEXT_PORT"])
READY_FILE = os.environ["READY_FILE"]
EXPECT_MODE = os.environ.get("EXPECT_MODE", "present")
EXPECT_UID = int(os.environ["EXPECT_UID"])
EXPECT_DIRECTION = os.environ.get("EXPECT_DIRECTION", "")
EXPECT_SRC = os.environ.get("EXPECT_SRC", "")
EXPECT_DST = os.environ.get("EXPECT_DST", "")
EXPECT_SPORT = os.environ.get("EXPECT_SPORT", "")
EXPECT_DPORT = os.environ.get("EXPECT_DPORT", "")
EXPECT_L4_STATUS = os.environ.get("EXPECT_L4_STATUS", "")
EXPECT_REASON = os.environ.get("EXPECT_REASON", "")
EXPECT_ACCEPTED = os.environ.get("EXPECT_ACCEPTED", "")
EXPECT_RULE_ID = os.environ.get("EXPECT_RULE_ID", "")
EXPECT_WOULD_RULE_ID = os.environ.get("EXPECT_WOULD_RULE_ID", "")
EXPECT_NO_RULE_ID = os.environ.get("EXPECT_NO_RULE_ID", "0") == "1"
EXPECT_NO_WOULD_RULE_ID = os.environ.get("EXPECT_NO_WOULD_RULE_ID", "0") == "1"


def encode_netstring(payload: bytes) -> bytes:
    return str(len(payload)).encode("ascii") + b":" + payload + b","


def read_exact(sock: socket.socket, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise EOFError("eof while reading payload")
        out += chunk
    return bytes(out)


def read_netstring(sock: socket.socket) -> bytes:
    header = bytearray()
    while True:
        ch = sock.recv(1)
        if not ch:
            raise EOFError("eof while reading netstring header")
        if ch == b":":
            break
        header += ch
        if len(header) > 32:
            raise ValueError("netstring header too long")
    if not header:
        raise ValueError("empty netstring length")
    if header.startswith(b"0") and header != b"0":
        raise ValueError("leading zero in netstring length")
    length = int(header.decode("ascii"))
    payload = read_exact(sock, length)
    comma = read_exact(sock, 1)
    if comma != b",":
        raise ValueError("netstring missing trailing comma")
    return payload


def rpc(sock: socket.socket, req_id: int, cmd: str, args: dict) -> dict:
    req = {"id": req_id, "cmd": cmd, "args": args}
    payload = json.dumps(req, separators=(",", ":")).encode("utf-8")
    sock.sendall(encode_netstring(payload))
    return json.loads(read_netstring(sock))


def int_field(frame: dict, name: str, default: int = -1) -> int:
    try:
        return int(frame.get(name, default))
    except (TypeError, ValueError):
        return default


def bool_matches(value, expected: str) -> bool:
    if expected == "":
        return True
    want = expected == "true"
    return value is want


def matches(frame: dict) -> bool:
    if frame.get("type") != "pkt":
        return False
    if int_field(frame, "uid") != EXPECT_UID:
        return False
    if EXPECT_DIRECTION and frame.get("direction") != EXPECT_DIRECTION:
        return False
    if EXPECT_SRC and frame.get("srcIp") != EXPECT_SRC:
        return False
    if EXPECT_DST and frame.get("dstIp") != EXPECT_DST:
        return False
    if EXPECT_SPORT and int_field(frame, "srcPort") != int(EXPECT_SPORT):
        return False
    if EXPECT_DPORT and int_field(frame, "dstPort") != int(EXPECT_DPORT):
        return False
    if EXPECT_L4_STATUS and frame.get("l4Status") != EXPECT_L4_STATUS:
        return False
    if EXPECT_REASON and frame.get("reasonId") != EXPECT_REASON:
        return False
    if not bool_matches(frame.get("accepted"), EXPECT_ACCEPTED):
        return False
    if EXPECT_RULE_ID and int_field(frame, "ruleId") != int(EXPECT_RULE_ID):
        return False
    if EXPECT_WOULD_RULE_ID and int_field(frame, "wouldRuleId") != int(EXPECT_WOULD_RULE_ID):
        return False
    if EXPECT_NO_RULE_ID and "ruleId" in frame:
        return False
    if EXPECT_NO_WOULD_RULE_ID and "wouldRuleId" in frame:
        return False
    return True


try:
    sock = socket.create_connection(("127.0.0.1", PORT), timeout=3)
    sock.settimeout(0.25)

    start = rpc(sock, 1, "STREAM.START", {"type": "pkt", "horizonSec": 0, "minSize": 0})
    if not start.get("ok", False):
        raise SystemExit(1)

    deadline = time.time() + 5.0
    ready = False
    found = False
    samples = []
    while time.time() < deadline:
        try:
            frame = json.loads(read_netstring(sock))
        except socket.timeout:
            continue

        if frame.get("type") == "notice" and frame.get("notice") == "started" and frame.get("stream") == "pkt":
            if not ready:
                with open(READY_FILE, "w", encoding="utf-8") as f:
                    f.write("ready\n")
                ready = True
            continue

        if frame.get("type") != "pkt":
            continue

        if len(samples) < 5:
            samples.append(
                {
                    "uid": frame.get("uid"),
                    "direction": frame.get("direction"),
                    "srcIp": frame.get("srcIp"),
                    "srcPort": frame.get("srcPort"),
                    "dstIp": frame.get("dstIp"),
                    "dstPort": frame.get("dstPort"),
                    "accepted": frame.get("accepted"),
                    "reasonId": frame.get("reasonId"),
                    "ruleId": frame.get("ruleId"),
                    "wouldRuleId": frame.get("wouldRuleId"),
                }
            )
        if matches(frame):
            found = True
            break

    rpc(sock, 2, "STREAM.STOP", {})
    sock.close()

    if EXPECT_MODE == "absent":
        if found:
            print("DEBUG: unexpected matching pkt event", file=sys.stderr)
            print(json.dumps(samples[-1], separators=(",", ":")), file=sys.stderr)
            raise SystemExit(2)
        raise SystemExit(0)

    if not found:
        print("DEBUG: no matching pkt event found", file=sys.stderr)
        if samples:
            print("DEBUG: pkt samples (up to 5):", file=sys.stderr)
            for sample in samples:
                print(json.dumps(sample, separators=(",", ":")), file=sys.stderr)
        else:
            print("DEBUG: received no pkt frames within deadline", file=sys.stderr)
    raise SystemExit(0 if found else 2)
except Exception:
    raise SystemExit(77)
PY
  PKT_CAPTURE_PID=$!

  local ready=0
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if [[ -f "$ready_file" ]]; then
      ready=1
      break
    fi
    sleep 0.1
  done
  if [[ $ready -ne 1 ]]; then
    echo "BLOCKED: stream listener did not become ready" >&2
    wait "$PKT_CAPTURE_PID" >/dev/null 2>&1 || true
    rm -rf "$PKT_CAPTURE_DIR"
    exit 77
  fi
}

pkt_capture_wait() {
  local desc="$1" rc
  set +e
  wait "$PKT_CAPTURE_PID"
  rc=$?
  set -e
  rm -rf "$PKT_CAPTURE_DIR"
  PKT_CAPTURE_DIR=""
  PKT_CAPTURE_PID=""

  if [[ $rc -eq 77 ]]; then
    echo "BLOCKED: stream capture failed" >&2
    exit 77
  fi
  if [[ $rc -ne 0 ]]; then
    log_fail "$desc"
    exit 1
  fi
  log_pass "$desc"
}

device_preflight || {
  echo "BLOCKED: device_preflight failed (need adb + rooted device)" >&2
  exit 77
}

if ! check_control_vnext_forward "$VNEXT_PORT"; then
  log_info "设置 vNext adb forward..."
  setup_control_vnext_forward "$VNEXT_PORT" || {
    echo "BLOCKED: setup_control_vnext_forward failed (port=$VNEXT_PORT)" >&2
    exit 77
  }
fi

SNORT_CTL="$(find_snort_ctl)" || exit 77
log_info "sucre-snort-ctl: $SNORT_CTL"

ctl_json_or_block hello HELLO "" "vNext control HELLO failed (port=$VNEXT_PORT)"
assert_or_exit "VNXDP-01 HELLO ok" "$hello" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True; assert j["result"]["protocol"]=="control-vnext"'

app_uid=2000
log_info "target uid=$app_uid (shell)"

# Tier-1 routing must match the traffic UID. Use shell uid=2000 to avoid Android
# app permission variance (e.g., INTERNET permission).
export IPTEST_UID="$app_uid"

if ! iptest_require_tier1_prereqs; then
  echo "BLOCKED: tier1 prereqs missing (need root + ip/netns/veth + ping + nc)" >&2
  exit 77
fi

table=""
tracked_orig=""
iface_mask_orig=""

cleanup() {
  set +e

  ctl_cmd CONFIG.SET '{"scope":"device","set":{"block.enabled":1,"iprules.enabled":1}}' >/dev/null 2>&1 || true
  if [[ -n "$tracked_orig" ]]; then
    ctl_cmd CONFIG.SET "{\"scope\":\"app\",\"app\":{\"uid\":${app_uid}},\"set\":{\"tracked\":${tracked_orig}}}" >/dev/null 2>&1 || true
  fi
  if [[ -n "$iface_mask_orig" ]]; then
    ctl_cmd CONFIG.SET "{\"scope\":\"app\",\"app\":{\"uid\":${app_uid}},\"set\":{\"block.ifaceKindMask\":${iface_mask_orig}}}" >/dev/null 2>&1 || true
  fi

  if [[ -n "$table" ]]; then
    iptest_tier1_teardown "$table" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

ctl_json_or_block resetall RESETALL "" "vNext RESETALL failed"
assert_or_exit "VNXDP-02 RESETALL ok" "$resetall" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True'

ctl_json_or_block cfg_dev CONFIG.SET '{"scope":"device","set":{"block.enabled":1,"iprules.enabled":1}}' "CONFIG.SET(device) failed"
assert_or_exit "VNXDP-03 CONFIG.SET device ack" "$cfg_dev" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True'

log_info "setting up tier1 topology..."
table="$(iptest_tier1_setup)" || exit $?
log_info "tier1 table=$table"
ipv6_tcp_port=4443
ipv6_udp_port=4444
iptest_tier1_start_tcp_zero_server 443 >/dev/null 2>&1 || {
  echo "BLOCKED: failed to start tier1 tcp server (port=443)" >&2
  exit 77
}
adb_su "ip netns exec \"$IPTEST_NS\" sh -c 'nc ${IPTEST_NC6_FLAG} -p \"$ipv6_tcp_port\" -L cat /dev/zero >/dev/null 2>&1 & echo \$!'" >/dev/null 2>&1 || {
  echo "SKIP: failed to start tier1 ipv6 tcp server (port=$ipv6_tcp_port)" >&2
  exit 10
}

# Ensure the {uid} selector exists in AppManager before CONFIG.GET/SET + IPRULES.APPLY.
iptest_adb_shell "nc -n -z -w 1 \"$IPTEST_PEER_IP\" 443 >/dev/null 2>&1 || true" >/dev/null 2>&1 || true

ctl_json_or_block tracked_get CONFIG.GET "{\"scope\":\"app\",\"app\":{\"uid\":${app_uid}},\"keys\":[\"tracked\",\"block.ifaceKindMask\"]}" "CONFIG.GET(tracked/block.ifaceKindMask) failed"
tracked_orig="$(TRACKED_JSON="$tracked_get" python3 - <<'PY'
import os, json
j = json.loads(os.environ["TRACKED_JSON"])
print(j.get("result", {}).get("values", {}).get("tracked", 0))
PY
)" || tracked_orig="0"
if [[ "$tracked_orig" != "0" && "$tracked_orig" != "1" ]]; then
  tracked_orig="0"
fi
iface_mask_orig="$(MASK_JSON="$tracked_get" python3 - <<'PY'
import os, json
j = json.loads(os.environ["MASK_JSON"])
print(j.get("result", {}).get("values", {}).get("block.ifaceKindMask", 0))
PY
)" || iface_mask_orig="0"
if [[ ! "$iface_mask_orig" =~ ^[0-9]+$ ]]; then
  iface_mask_orig="0"
fi
log_info "tracked(orig)=$tracked_orig"
log_info "block.ifaceKindMask(orig)=$iface_mask_orig"

ctl_json_or_block cfg_tracked CONFIG.SET "{\"scope\":\"app\",\"app\":{\"uid\":${app_uid}},\"set\":{\"tracked\":1}}" "CONFIG.SET(tracked=1) failed"
assert_or_exit "VNXDP-04 CONFIG.SET tracked=1 ack" "$cfg_tracked" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True'

ctl_json_or_block tracked_after_get CONFIG.GET "{\"scope\":\"app\",\"app\":{\"uid\":${app_uid}},\"keys\":[\"tracked\"]}" "CONFIG.GET(tracked) after set failed"
tracked_after="$(TRACKED_JSON="$tracked_after_get" python3 - <<'PY'
import os, json
j = json.loads(os.environ["TRACKED_JSON"])
print(j.get("result", {}).get("values", {}).get("tracked", 0))
PY
)" || tracked_after="0"
if [[ "$tracked_after" != "1" ]]; then
  log_fail "VNXDP-04b tracked=1 confirmed"
  echo "    tracked_after=$tracked_after"
  exit 1
fi
log_pass "VNXDP-04b tracked=1 confirmed"

dst_cidr="${IPTEST_PEER_IP}/32"

# -----------------------------------------------------------------------------
# IP / Case 2: enforce allow
# -----------------------------------------------------------------------------
apply_args="{\"app\":{\"uid\":${app_uid}},\"rules\":[{\"clientRuleId\":\"dx-smoke:r1\",\"family\":\"ipv4\",\"action\":\"allow\",\"priority\":10,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"tcp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${dst_cidr}\",\"sport\":\"any\",\"dport\":\"443\"}]}"
ctl_json_or_block apply IPRULES.APPLY "$apply_args" "IPRULES.APPLY(allow) failed"
assert_or_exit "VNXDP-05 IPRULES.APPLY allow ok" "$apply" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True; assert len(j["result"]["rules"])==1'
rule_id="$(single_rule_id "$apply")" || rule_id=""
if [[ ! "$rule_id" =~ ^[0-9]+$ ]]; then
  log_fail "VNXDP-05b IPRULES.APPLY allow returns ruleId"
  echo "    ruleId=$rule_id"
  exit 1
fi
log_info "allow ruleId=$rule_id"

metrics_reset_reasons "VNXDP-05c METRICS.RESET reasons ok (allow)"
metrics_reset_traffic "VNXDP-05d METRICS.RESET traffic ok (allow)"
assert_traffic_zero "VNXDP-05e traffic zero after reset (allow)"

pkt_capture_begin present out IP_RULE_ALLOW true "$rule_id" "" 0 0 443
trigger_tcp_expect_success "VNXDP-06 TCP connect succeeds with allow rule"
pkt_capture_wait "VNXDP-06b STREAM pkt contains IP_RULE_ALLOW + ruleId"
assert_reason_bucket_ge "VNXDP-06c reasons IP_RULE_ALLOW increments" IP_RULE_ALLOW packets 1
assert_traffic_bucket_ge "VNXDP-06d traffic txp.allow increments" txp allow 1
assert_rule_stat_ge "VNXDP-07 per-rule stats hitPackets increments" "$rule_id" hitPackets 1

# -----------------------------------------------------------------------------
# IP / Case 3: enforce block
# -----------------------------------------------------------------------------
apply_args_block="{\"app\":{\"uid\":${app_uid}},\"rules\":[{\"clientRuleId\":\"dx-smoke:r2\",\"family\":\"ipv4\",\"action\":\"block\",\"priority\":11,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"tcp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${dst_cidr}\",\"sport\":\"any\",\"dport\":\"443\"}]}"
ctl_json_or_block apply_block IPRULES.APPLY "$apply_args_block" "IPRULES.APPLY(block) failed"
assert_or_exit "VNXDP-08 IPRULES.APPLY block ok" "$apply_block" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True; assert len(j["result"]["rules"])==1'
block_rule_id="$(single_rule_id "$apply_block")" || block_rule_id=""
if [[ ! "$block_rule_id" =~ ^[0-9]+$ ]]; then
  log_fail "VNXDP-08b IPRULES.APPLY block returns ruleId"
  echo "    ruleId=$block_rule_id"
  exit 1
fi
log_info "block ruleId=$block_rule_id"

metrics_reset_reasons "VNXDP-08c METRICS.RESET reasons ok (block)"
metrics_reset_traffic "VNXDP-08d METRICS.RESET traffic ok (block)"
assert_traffic_zero "VNXDP-08e traffic zero after reset (block)"

pkt_capture_begin present out IP_RULE_BLOCK false "$block_rule_id" "" 0 0 443
trigger_tcp_expect_failure "VNXDP-08f TCP connect fails with block rule"
pkt_capture_wait "VNXDP-08g STREAM pkt contains IP_RULE_BLOCK + ruleId"
assert_reason_bucket_ge "VNXDP-08h reasons IP_RULE_BLOCK increments" IP_RULE_BLOCK packets 1
assert_traffic_bucket_ge "VNXDP-08i traffic txp.block increments" txp block 1
assert_rule_stat_ge "VNXDP-08j per-rule stats hitPackets increments" "$block_rule_id" hitPackets 1

# -----------------------------------------------------------------------------
# IP / Case 4: would-match overlay on final ACCEPT
# -----------------------------------------------------------------------------
apply_args_would="{\"app\":{\"uid\":${app_uid}},\"rules\":[{\"clientRuleId\":\"dx-smoke:r3\",\"family\":\"ipv4\",\"action\":\"block\",\"priority\":12,\"enabled\":1,\"enforce\":0,\"log\":1,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"tcp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${dst_cidr}\",\"sport\":\"any\",\"dport\":\"443\"}]}"
ctl_json_or_block apply_would IPRULES.APPLY "$apply_args_would" "IPRULES.APPLY(would) failed"
assert_or_exit "VNXDP-09 IPRULES.APPLY would ok" "$apply_would" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True; assert len(j["result"]["rules"])==1'
would_rule_id="$(single_rule_id "$apply_would")" || would_rule_id=""
if [[ ! "$would_rule_id" =~ ^[0-9]+$ ]]; then
  log_fail "VNXDP-09b IPRULES.APPLY would returns ruleId"
  echo "    ruleId=$would_rule_id"
  exit 1
fi
log_info "would ruleId=$would_rule_id"

metrics_reset_reasons "VNXDP-09c METRICS.RESET reasons ok (would)"
metrics_reset_traffic "VNXDP-09d METRICS.RESET traffic ok (would)"
assert_traffic_zero "VNXDP-09e traffic zero after reset (would)"

pkt_capture_begin present out ALLOW_DEFAULT true "" "$would_rule_id" 1 0 443
trigger_tcp_expect_success "VNXDP-09f TCP connect succeeds with would-match rule"
pkt_capture_wait "VNXDP-09g STREAM pkt contains ALLOW_DEFAULT + wouldRuleId"
assert_reason_bucket_ge "VNXDP-09h reasons ALLOW_DEFAULT increments" ALLOW_DEFAULT packets 1
assert_traffic_bucket_ge "VNXDP-09i traffic txp.allow increments (would)" txp allow 1
assert_rule_stat_ge "VNXDP-09j per-rule stats wouldHitPackets increments" "$would_rule_id" wouldHitPackets 1

# -----------------------------------------------------------------------------
# IP / Case 5: IFACE_BLOCK wins over IPRULES
# -----------------------------------------------------------------------------
iface_kind_bit=128
iface_index="$(iptest_iface_ifindex "$IPTEST_VETH0" 2>/dev/null || true)"
if [[ "$iface_index" =~ ^[0-9]+$ ]]; then
  ifaces_json="$(ctl_cmd IFACES.LIST 2>/dev/null || true)"
  iface_kind="$(IFACES_JSON="$ifaces_json" IFINDEX="$iface_index" python3 - <<'PY'
import os, json
j = json.loads(os.environ["IFACES_JSON"] or "{}")
want = int(os.environ["IFINDEX"])
for it in j.get("result", {}).get("ifaces", []):
    try:
        if int(it.get("ifindex", -1)) == want:
            print(it.get("kind", ""))
            raise SystemExit(0)
    except Exception:
        continue
print("")
PY
  )" || iface_kind=""
  case "$iface_kind" in
    wifi) iface_kind_bit=1 ;;
    data) iface_kind_bit=2 ;;
    vpn) iface_kind_bit=4 ;;
    unmanaged) iface_kind_bit=128 ;;
    *) iface_kind_bit=128 ;;
  esac
fi
log_info "tier1 ifaceKindBit=$iface_kind_bit (ifindex=${iface_index:-?} kind=${iface_kind:-?})"

apply_args_iface="{\"app\":{\"uid\":${app_uid}},\"rules\":[{\"clientRuleId\":\"dx-smoke:r4\",\"family\":\"ipv4\",\"action\":\"allow\",\"priority\":13,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"tcp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${dst_cidr}\",\"sport\":\"any\",\"dport\":\"443\"}]}"
ctl_json_or_block apply_iface IPRULES.APPLY "$apply_args_iface" "IPRULES.APPLY(iface shadow rule) failed"
assert_or_exit "VNXDP-10 IPRULES.APPLY iface shadow rule ok" "$apply_iface" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True; assert len(j["result"]["rules"])==1'
iface_rule_id="$(single_rule_id "$apply_iface")" || iface_rule_id=""
if [[ ! "$iface_rule_id" =~ ^[0-9]+$ ]]; then
  log_fail "VNXDP-10b IPRULES.APPLY iface shadow rule returns ruleId"
  echo "    ruleId=$iface_rule_id"
  exit 1
fi
hits_before_iface="$(rule_stat "$iface_rule_id" hitPackets)" || hits_before_iface="0"

metrics_reset_reasons "VNXDP-10c METRICS.RESET reasons ok (iface)"
metrics_reset_traffic "VNXDP-10d METRICS.RESET traffic ok (iface)"
assert_traffic_zero "VNXDP-10e traffic zero after reset (iface)"

ctl_json_or_block cfg_iface CONFIG.SET "{\"scope\":\"app\",\"app\":{\"uid\":${app_uid}},\"set\":{\"block.ifaceKindMask\":${iface_kind_bit}}}" "CONFIG.SET(block.ifaceKindMask) failed"
assert_or_exit "VNXDP-10f CONFIG.SET block.ifaceKindMask ack" "$cfg_iface" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True'

pkt_capture_begin present out IFACE_BLOCK false "" "" 1 1 443
trigger_tcp_expect_failure "VNXDP-10g TCP connect fails with IFACE_BLOCK"
pkt_capture_wait "VNXDP-10h STREAM pkt contains IFACE_BLOCK without rule attribution"
assert_reason_bucket_ge "VNXDP-10i reasons IFACE_BLOCK increments" IFACE_BLOCK packets 1
assert_traffic_bucket_ge "VNXDP-10j traffic txp.block increments (iface)" txp block 1
assert_rule_stat_eq "VNXDP-10k IFACE_BLOCK does not grow rule hitPackets" "$iface_rule_id" hitPackets "$hits_before_iface"

ctl_json_or_block cfg_iface_restore CONFIG.SET "{\"scope\":\"app\",\"app\":{\"uid\":${app_uid}},\"set\":{\"block.ifaceKindMask\":${iface_mask_orig}}}" "restore block.ifaceKindMask failed"
assert_or_exit "VNXDP-10l restore block.ifaceKindMask ack" "$cfg_iface_restore" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True'

# -----------------------------------------------------------------------------
# IP / Case 5b: IPv6 dual-stack datapath sanity (TCP + UDP)
# -----------------------------------------------------------------------------
dst6_cidr="${IPTEST_PEER_IP6}/128"

apply_args6_allow="{\"app\":{\"uid\":${app_uid}},\"rules\":[{\"clientRuleId\":\"dx-smoke:ipv6-allow\",\"family\":\"ipv6\",\"action\":\"allow\",\"priority\":30,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"tcp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${dst6_cidr}\",\"sport\":\"any\",\"dport\":\"${ipv6_tcp_port}\"}]}"
ctl_json_or_block apply6_allow IPRULES.APPLY "$apply_args6_allow" "IPRULES.APPLY(ipv6 allow) failed"
assert_or_exit "VNXDP-10m IPRULES.APPLY ipv6 allow ok" "$apply6_allow" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True; assert len(j["result"]["rules"])==1'
rule6_allow_id="$(single_rule_id "$apply6_allow")" || rule6_allow_id=""
if [[ ! "$rule6_allow_id" =~ ^[0-9]+$ ]]; then
  log_fail "VNXDP-10n IPRULES.APPLY ipv6 allow returns ruleId"
  echo "    ruleId=$rule6_allow_id"
  exit 1
fi

metrics_reset_reasons "VNXDP-10o METRICS.RESET reasons ok (ipv6 allow)"
metrics_reset_traffic "VNXDP-10p METRICS.RESET traffic ok (ipv6 allow)"
assert_traffic_zero "VNXDP-10q traffic zero after reset (ipv6 allow)"

pkt_capture_begin present out IP_RULE_ALLOW true "$rule6_allow_id" "" 0 0 "$ipv6_tcp_port" "" "" "$IPTEST_PEER_IP6"
trigger_tcp6_expect_success "VNXDP-10r IPv6 TCP connect succeeds with allow rule" "$ipv6_tcp_port"
pkt_capture_wait "VNXDP-10s STREAM pkt contains ipv6 IP_RULE_ALLOW + ruleId"
assert_reason_bucket_ge "VNXDP-10t reasons IP_RULE_ALLOW increments (ipv6)" IP_RULE_ALLOW packets 1
assert_traffic_bucket_ge "VNXDP-10u traffic txp.allow increments (ipv6)" txp allow 1
assert_rule_stat_ge "VNXDP-10v ipv6 allow rule hitPackets increments" "$rule6_allow_id" hitPackets 1

apply_args6_block="{\"app\":{\"uid\":${app_uid}},\"rules\":[{\"clientRuleId\":\"dx-smoke:ipv6-block\",\"family\":\"ipv6\",\"action\":\"block\",\"priority\":31,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"tcp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${dst6_cidr}\",\"sport\":\"any\",\"dport\":\"${ipv6_tcp_port}\"}]}"
ctl_json_or_block apply6_block IPRULES.APPLY "$apply_args6_block" "IPRULES.APPLY(ipv6 block) failed"
assert_or_exit "VNXDP-10w IPRULES.APPLY ipv6 block ok" "$apply6_block" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True; assert len(j["result"]["rules"])==1'
rule6_block_id="$(single_rule_id "$apply6_block")" || rule6_block_id=""
if [[ ! "$rule6_block_id" =~ ^[0-9]+$ ]]; then
  log_fail "VNXDP-10x IPRULES.APPLY ipv6 block returns ruleId"
  echo "    ruleId=$rule6_block_id"
  exit 1
fi

metrics_reset_reasons "VNXDP-10y METRICS.RESET reasons ok (ipv6 block)"
metrics_reset_traffic "VNXDP-10z METRICS.RESET traffic ok (ipv6 block)"
assert_traffic_zero "VNXDP-10za traffic zero after reset (ipv6 block)"

pkt_capture_begin present out IP_RULE_BLOCK false "$rule6_block_id" "" 0 0 "$ipv6_tcp_port" "" "" "$IPTEST_PEER_IP6"
trigger_tcp6_expect_failure "VNXDP-10zb IPv6 TCP connect fails with block rule" "$ipv6_tcp_port"
pkt_capture_wait "VNXDP-10zc STREAM pkt contains ipv6 IP_RULE_BLOCK + ruleId"
assert_reason_bucket_ge "VNXDP-10zd reasons IP_RULE_BLOCK increments (ipv6)" IP_RULE_BLOCK packets 1
assert_traffic_bucket_ge "VNXDP-10ze traffic txp.block increments (ipv6)" txp block 1
assert_rule_stat_ge "VNXDP-10zf ipv6 block rule hitPackets increments" "$rule6_block_id" hitPackets 1

apply_args6_udp="{\"app\":{\"uid\":${app_uid}},\"rules\":[{\"clientRuleId\":\"dx-smoke:ipv6-udp\",\"family\":\"ipv6\",\"action\":\"allow\",\"priority\":32,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"udp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${dst6_cidr}\",\"sport\":\"any\",\"dport\":\"${ipv6_udp_port}\"}]}"
ctl_json_or_block apply6_udp IPRULES.APPLY "$apply_args6_udp" "IPRULES.APPLY(ipv6 udp allow) failed"
assert_or_exit "VNXDP-10zg IPRULES.APPLY ipv6 udp allow ok" "$apply6_udp" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True; assert len(j["result"]["rules"])==1'
rule6_udp_id="$(single_rule_id "$apply6_udp")" || rule6_udp_id=""
if [[ ! "$rule6_udp_id" =~ ^[0-9]+$ ]]; then
  log_fail "VNXDP-10zh IPRULES.APPLY ipv6 udp allow returns ruleId"
  echo "    ruleId=$rule6_udp_id"
  exit 1
fi

metrics_reset_reasons "VNXDP-10zi METRICS.RESET reasons ok (ipv6 udp)"
metrics_reset_traffic "VNXDP-10zj METRICS.RESET traffic ok (ipv6 udp)"
assert_traffic_zero "VNXDP-10zk traffic zero after reset (ipv6 udp)"

pkt_capture_begin present out IP_RULE_ALLOW true "$rule6_udp_id" "" 0 0 "$ipv6_udp_port" "" "" "$IPTEST_PEER_IP6"
udp6_send_once "$ipv6_udp_port"
pkt_capture_wait "VNXDP-10zl STREAM pkt contains ipv6 UDP IP_RULE_ALLOW + ruleId"
assert_reason_bucket_ge "VNXDP-10zm reasons IP_RULE_ALLOW increments (ipv6 udp)" IP_RULE_ALLOW packets 1
assert_traffic_bucket_ge "VNXDP-10zn traffic txp.allow increments (ipv6 udp)" txp allow 1
assert_rule_stat_ge "VNXDP-10zo ipv6 udp rule hitPackets increments" "$rule6_udp_id" hitPackets 1

# -----------------------------------------------------------------------------
# IP / Case 6: block.enabled=0 gates reasons, traffic, and pkt stream
# -----------------------------------------------------------------------------
metrics_reset_reasons "VNXDP-11 METRICS.RESET reasons ok (block=0)"
metrics_reset_traffic "VNXDP-11b METRICS.RESET traffic ok (block=0)"
assert_traffic_zero "VNXDP-11c traffic zero before block.enabled=0 trigger"

ctl_json_or_block cfg_block0 CONFIG.SET '{"scope":"device","set":{"block.enabled":0}}' "CONFIG.SET(block.enabled=0) failed"
assert_or_exit "VNXDP-11d CONFIG.SET block.enabled=0 ack" "$cfg_block0" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True'

pkt_capture_begin absent out "" "" "" "" 0 0 443
trigger_tcp_expect_success "VNXDP-11e TCP connect succeeds while block.enabled=0"
pkt_capture_wait "VNXDP-11f no pkt stream verdict while block.enabled=0"
assert_reasons_zero "VNXDP-11g reasons gated by block.enabled=0"
assert_traffic_zero "VNXDP-11h traffic gated by block.enabled=0"

ctl_json_or_block cfg_block1 CONFIG.SET '{"scope":"device","set":{"block.enabled":1}}' "CONFIG.SET(block.enabled=1) failed"
assert_or_exit "VNXDP-11i CONFIG.SET block.enabled=1 ack" "$cfg_block1" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True'

# -----------------------------------------------------------------------------
# IP / Case 7: iprules.enabled=0 falls back to ALLOW_DEFAULT
# -----------------------------------------------------------------------------
apply_args_iprules_off="{\"app\":{\"uid\":${app_uid}},\"rules\":[{\"clientRuleId\":\"dx-smoke:r5\",\"family\":\"ipv4\",\"action\":\"block\",\"priority\":14,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"tcp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${dst_cidr}\",\"sport\":\"any\",\"dport\":\"443\"}]}"
ctl_json_or_block apply_iprules_off IPRULES.APPLY "$apply_args_iprules_off" "IPRULES.APPLY(iprules.enabled=0 case) failed"
assert_or_exit "VNXDP-12 IPRULES.APPLY block rule for iprules.enabled=0 ok" "$apply_iprules_off" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True; assert len(j["result"]["rules"])==1'
iprules_off_rule_id="$(single_rule_id "$apply_iprules_off")" || iprules_off_rule_id=""
if [[ ! "$iprules_off_rule_id" =~ ^[0-9]+$ ]]; then
  log_fail "VNXDP-12b IPRULES.APPLY iprules.enabled=0 case returns ruleId"
  echo "    ruleId=$iprules_off_rule_id"
  exit 1
fi
iprules_off_hits_before="$(rule_stat "$iprules_off_rule_id" hitPackets)" || iprules_off_hits_before="0"
iprules_off_would_before="$(rule_stat "$iprules_off_rule_id" wouldHitPackets)" || iprules_off_would_before="0"

ctl_json_or_block cfg_iprules0 CONFIG.SET '{"scope":"device","set":{"iprules.enabled":0}}' "CONFIG.SET(iprules.enabled=0) failed"
assert_or_exit "VNXDP-12c CONFIG.SET iprules.enabled=0 ack" "$cfg_iprules0" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True'
metrics_reset_reasons "VNXDP-12d METRICS.RESET reasons ok (iprules=0)"
metrics_reset_traffic "VNXDP-12e METRICS.RESET traffic ok (iprules=0)"
assert_traffic_zero "VNXDP-12f traffic zero before iprules.enabled=0 trigger"

pkt_capture_begin present out ALLOW_DEFAULT true "" "" 1 1 443
trigger_tcp_expect_success "VNXDP-12g TCP connect succeeds while iprules.enabled=0"
pkt_capture_wait "VNXDP-12h STREAM pkt reports ALLOW_DEFAULT without rule attribution"
assert_reason_bucket_ge "VNXDP-12i reasons ALLOW_DEFAULT increments (iprules=0)" ALLOW_DEFAULT packets 1
assert_traffic_bucket_ge "VNXDP-12j traffic txp.allow increments (iprules=0)" txp allow 1
assert_rule_stat_eq "VNXDP-12k disabled IPRULES does not grow hitPackets" "$iprules_off_rule_id" hitPackets "$iprules_off_hits_before"
assert_rule_stat_eq "VNXDP-12l disabled IPRULES does not grow wouldHitPackets" "$iprules_off_rule_id" wouldHitPackets "$iprules_off_would_before"

ctl_json_or_block cfg_iprules1 CONFIG.SET '{"scope":"device","set":{"iprules.enabled":1}}' "CONFIG.SET(iprules.enabled=1) failed"
assert_or_exit "VNXDP-12m CONFIG.SET iprules.enabled=1 ack" "$cfg_iprules1" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True'

# -----------------------------------------------------------------------------
# IP / Case 8: payload bytes drive traffic.*b, reasons bytes, and hitBytes
# -----------------------------------------------------------------------------
payload_bytes=65536
apply_args_payload="{\"app\":{\"uid\":${app_uid}},\"rules\":[{\"clientRuleId\":\"dx-smoke:payload-out\",\"family\":\"ipv4\",\"action\":\"allow\",\"priority\":20,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"tcp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${dst_cidr}\",\"sport\":\"any\",\"dport\":\"443\"},{\"clientRuleId\":\"dx-smoke:payload-in\",\"family\":\"ipv4\",\"action\":\"allow\",\"priority\":21,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"in\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"tcp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"${dst_cidr}\",\"dst\":\"any\",\"sport\":\"443\",\"dport\":\"any\"}]}"
ctl_json_or_block apply_payload IPRULES.APPLY "$apply_args_payload" "IPRULES.APPLY(payload allow rules) failed"
assert_or_exit "VNXDP-13 IPRULES.APPLY payload allow rules ok" "$apply_payload" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True; assert len(j["result"]["rules"])==2'
payload_out_rule_id="$(rule_id_by_client "$apply_payload" "dx-smoke:payload-out")" || payload_out_rule_id=""
payload_in_rule_id="$(rule_id_by_client "$apply_payload" "dx-smoke:payload-in")" || payload_in_rule_id=""
if [[ ! "$payload_out_rule_id" =~ ^[0-9]+$ || ! "$payload_in_rule_id" =~ ^[0-9]+$ ]]; then
  log_fail "VNXDP-13b IPRULES.APPLY payload rules return ruleIds"
  echo "    out=$payload_out_rule_id in=$payload_in_rule_id"
  exit 1
fi
log_info "payload ruleIds out=$payload_out_rule_id in=$payload_in_rule_id"

metrics_reset_reasons "VNXDP-13c METRICS.RESET reasons ok (payload)"
metrics_reset_traffic "VNXDP-13d METRICS.RESET traffic ok (payload)"
assert_traffic_zero "VNXDP-13e traffic zero before payload trigger"

payload_count="$(iptest_tier1_tcp_count_bytes 443 "$payload_bytes" "$app_uid" | tr -d '\r\n ' || true)"
if [[ "$payload_count" == "$payload_bytes" ]]; then
  log_pass "VNXDP-13f payload read returns expected bytes ($payload_count)"
else
  log_fail "VNXDP-13f payload read returns expected bytes"
  echo "    expected=$payload_bytes actual=${payload_count:-<empty>}"
  exit 1
fi

assert_reason_bucket_ge "VNXDP-13g reasons IP_RULE_ALLOW packets increments (payload)" IP_RULE_ALLOW packets 1
assert_reason_bucket_ge "VNXDP-13h reasons IP_RULE_ALLOW bytes increments (payload)" IP_RULE_ALLOW bytes "$payload_bytes"
assert_traffic_bucket_ge "VNXDP-13i traffic rxp.allow increments (payload)" rxp allow 1
assert_traffic_bucket_ge "VNXDP-13j traffic rxb.allow reaches payload bytes" rxb allow "$payload_bytes"
assert_traffic_bucket_ge "VNXDP-13k traffic txp.allow increments (payload)" txp allow 1
assert_rule_stat_ge "VNXDP-13l inbound payload rule hitPackets increments" "$payload_in_rule_id" hitPackets 1
assert_rule_stat_ge "VNXDP-13m inbound payload rule hitBytes reaches payload bytes" "$payload_in_rule_id" hitBytes "$payload_bytes"
assert_rule_stat_ge "VNXDP-13n outbound payload rule hitPackets increments" "$payload_out_rule_id" hitPackets 1

log_pass "iprules vNext datapath smoke ok"
exit 0
