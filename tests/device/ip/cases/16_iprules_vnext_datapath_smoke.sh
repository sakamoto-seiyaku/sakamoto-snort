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

set +e
hello="$(ctl_cmd HELLO 2>/dev/null)"
st=$?
set -e
if [[ $st -ne 0 ]]; then
  echo "BLOCKED: vNext control HELLO failed (port=$VNEXT_PORT)" >&2
  exit 77
fi
assert_json_pred "VNXDP-01 HELLO ok" "$hello" \
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

set +e
resetall="$(ctl_cmd RESETALL 2>/dev/null)"
st=$?
set -e
if [[ $st -ne 0 ]]; then
  echo "BLOCKED: vNext RESETALL failed" >&2
  exit 77
fi
assert_json_pred "VNXDP-02 RESETALL ok" "$resetall" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True'

set +e
cfg_dev="$(ctl_cmd CONFIG.SET '{"scope":"device","set":{"block.enabled":1,"iprules.enabled":1}}' 2>/dev/null)"
st=$?
set -e
if [[ $st -ne 0 ]]; then
  echo "BLOCKED: CONFIG.SET(device) failed" >&2
  exit 77
fi
assert_json_pred "VNXDP-03 CONFIG.SET device ack" "$cfg_dev" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True'

log_info "setting up tier1 topology..."
table="$(iptest_tier1_setup)" || exit $?
log_info "tier1 table=$table"
iptest_tier1_start_tcp_zero_server 443 >/dev/null 2>&1 || {
  echo "BLOCKED: failed to start tier1 tcp server (port=443)" >&2
  exit 77
}

# Ensure the {uid} selector exists in AppManager before CONFIG.GET/SET + IPRULES.APPLY.
iptest_adb_shell "nc -n -z -w 1 \"$IPTEST_PEER_IP\" 443 >/dev/null 2>&1 || true" >/dev/null 2>&1 || true

set +e
tracked_get="$(ctl_cmd CONFIG.GET "{\"scope\":\"app\",\"app\":{\"uid\":${app_uid}},\"keys\":[\"tracked\",\"block.ifaceKindMask\"]}" 2>/dev/null)"
st=$?
set -e
if [[ $st -ne 0 ]]; then
  echo "BLOCKED: CONFIG.GET(tracked) failed" >&2
  exit 77
fi
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

set +e
cfg_tracked="$(ctl_cmd CONFIG.SET "{\"scope\":\"app\",\"app\":{\"uid\":${app_uid}},\"set\":{\"tracked\":1}}" 2>/dev/null)"
st=$?
set -e
if [[ $st -ne 0 ]]; then
  echo "BLOCKED: CONFIG.SET(tracked=1) failed" >&2
  exit 77
fi
assert_json_pred "VNXDP-04 CONFIG.SET tracked=1 ack" "$cfg_tracked" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True'

set +e
tracked_after_get="$(ctl_cmd CONFIG.GET "{\"scope\":\"app\",\"app\":{\"uid\":${app_uid}},\"keys\":[\"tracked\"]}" 2>/dev/null)"
st=$?
set -e
if [[ $st -ne 0 ]]; then
  echo "BLOCKED: CONFIG.GET(tracked) after set failed" >&2
  exit 77
fi
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
apply_args="{\"app\":{\"uid\":${app_uid}},\"rules\":[{\"clientRuleId\":\"dx-smoke:r1\",\"action\":\"allow\",\"priority\":10,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"tcp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${dst_cidr}\",\"sport\":\"any\",\"dport\":\"443\"}]}"

set +e
apply="$(ctl_cmd IPRULES.APPLY "$apply_args" 2>/dev/null)"
st=$?
set -e
if [[ $st -ne 0 ]]; then
  echo "BLOCKED: IPRULES.APPLY failed" >&2
  exit 77
fi
assert_json_pred "VNXDP-05 IPRULES.APPLY ok" "$apply" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True; assert len(j["result"]["rules"])==1'

rule_id="$(APPLY_JSON="$apply" python3 - <<'PY'
import os, json
j = json.loads(os.environ["APPLY_JSON"])
rules = j["result"]["rules"]
print(rules[0]["ruleId"] if rules else "")
PY
)" || rule_id=""
if [[ ! "$rule_id" =~ ^[0-9]+$ ]]; then
  log_fail "VNXDP-05b IPRULES.APPLY returns ruleId"
  echo "    ruleId=$rule_id"
  exit 1
fi
log_info "ruleId=$rule_id"

tmp_dir="$(mktemp -d)"
ready_file="$tmp_dir/stream_ready"

VNEXT_PORT="$VNEXT_PORT" EXPECT_UID="$app_uid" EXPECT_DST="$IPTEST_PEER_IP" EXPECT_RULE_ID="$rule_id" READY_FILE="$ready_file" python3 - <<'PY' &
import json
import os
import socket
import sys
import time

PORT = int(os.environ["VNEXT_PORT"])
EXPECT_UID = int(os.environ["EXPECT_UID"])
EXPECT_DST = os.environ["EXPECT_DST"]
EXPECT_RULE_ID = int(os.environ["EXPECT_RULE_ID"])
READY_FILE = os.environ["READY_FILE"]


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
    resp = json.loads(read_netstring(sock))
    return resp


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
    other = []
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
        if frame.get("type") == "notice" and len(other) < 5:
            other.append(frame)

        if frame.get("type") != "pkt":
            continue

        if len(samples) < 5:
            samples.append(
                {
                    "uid": frame.get("uid"),
                    "direction": frame.get("direction"),
                    "dstIp": frame.get("dstIp"),
                    "dstPort": frame.get("dstPort"),
                    "accepted": frame.get("accepted"),
                    "reasonId": frame.get("reasonId"),
                    "ruleId": frame.get("ruleId"),
                }
            )

        if int(frame.get("uid", -1)) != EXPECT_UID:
            continue
        if frame.get("direction") != "out":
            continue
        if frame.get("dstIp") != EXPECT_DST:
            continue
        if int(frame.get("dstPort", -1)) != 443:
            continue
        if frame.get("reasonId") != "IP_RULE_ALLOW":
            continue
        if int(frame.get("ruleId", -1)) != EXPECT_RULE_ID:
            continue
        found = True
        break

    if not found:
        print("DEBUG: no matching pkt event found", file=sys.stderr)
        if samples:
            print("DEBUG: pkt samples (up to 5):", file=sys.stderr)
            for s in samples:
                print(json.dumps(s, separators=(",", ":")), file=sys.stderr)
        else:
            print("DEBUG: received no pkt frames within deadline", file=sys.stderr)
        if other:
            print("DEBUG: non-pkt frames (up to 5):", file=sys.stderr)
            for f in other:
                print(json.dumps(f, separators=(",", ":")), file=sys.stderr)

    rpc(sock, 2, "STREAM.STOP", {})
    sock.close()
    raise SystemExit(0 if found else 2)
except Exception:
    raise SystemExit(77)
PY
stream_pid=$!

ready=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if [[ -f "$ready_file" ]]; then
    ready=1
    break
  fi
  sleep 0.1
done
if [[ $ready -ne 1 ]]; then
  echo "BLOCKED: stream listener did not become ready" >&2
  wait "$stream_pid" >/dev/null 2>&1 || true
  exit 77
fi

# Reset per-app traffic counters to make the trigger deterministic.
traffic_reset="$(ctl_cmd METRICS.RESET "{\"name\":\"traffic\",\"app\":{\"uid\":${app_uid}}}" 2>/dev/null || true)"
assert_json_pred "VNXDP-05c METRICS.RESET traffic ok (uid=$app_uid)" "$traffic_reset" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True'

traffic_zero="$(ctl_cmd METRICS.GET "{\"name\":\"traffic\",\"app\":{\"uid\":${app_uid}}}" 2>/dev/null || true)"
assert_json_pred "VNXDP-05d traffic zero after reset (uid=$app_uid)" "$traffic_zero" \
  'import sys,json; j=json.load(sys.stdin); t=j["result"]["traffic"]; total=0; \
   total += int(t["dns"]["allow"])+int(t["dns"]["block"]); \
   total += int(t["rxp"]["allow"])+int(t["rxp"]["block"]); \
   total += int(t["rxb"]["allow"])+int(t["rxb"]["block"]); \
   total += int(t["txp"]["allow"])+int(t["txp"]["block"]); \
   total += int(t["txb"]["allow"])+int(t["txb"]["block"]); \
   assert total==0'

# Trigger datapath traffic as the selected uid.
for _ in 1 2 3; do
  iptest_adb_shell "nc -n -z -w 1 \"$IPTEST_PEER_IP\" 443 >/dev/null 2>&1 || true" >/dev/null 2>&1 || true
done

set +e
wait "$stream_pid"
rc=$?
set -e

rm -rf "$tmp_dir"

if [[ $rc -eq 77 ]]; then
  echo "BLOCKED: stream capture failed" >&2
  exit 77
fi
if [[ $rc -ne 0 ]]; then
  set +e
  traffic_dbg="$(ctl_cmd METRICS.GET "{\"name\":\"traffic\",\"app\":{\"uid\":${app_uid}}}" 2>/dev/null)"
  set -e
  if [[ -n "$traffic_dbg" ]]; then
    echo "DEBUG: traffic snapshot for uid=$app_uid" >&2
    printf '%s\n' "$traffic_dbg" | head -n 3 | sed 's/^/    /' >&2
  fi
  log_fail "VNXDP-06 STREAM pkt captured expected verdict"
  exit 1
fi
log_pass "VNXDP-06 STREAM pkt contains reasonId/ruleId"

traffic_after="$(ctl_cmd METRICS.GET "{\"name\":\"traffic\",\"app\":{\"uid\":${app_uid}}}" 2>/dev/null || true)"
assert_json_pred "VNXDP-06b traffic counters increased (uid=$app_uid)" "$traffic_after" \
  'import sys,json; j=json.load(sys.stdin); t=j["result"]["traffic"]; total=0; \
   total += int(t["dns"]["allow"])+int(t["dns"]["block"]); \
   total += int(t["rxp"]["allow"])+int(t["rxp"]["block"]); \
   total += int(t["rxb"]["allow"])+int(t["rxb"]["block"]); \
   total += int(t["txp"]["allow"])+int(t["txp"]["block"]); \
   total += int(t["txb"]["allow"])+int(t["txb"]["block"]); \
   assert total>=1'

traffic_reset2="$(ctl_cmd METRICS.RESET "{\"name\":\"traffic\",\"app\":{\"uid\":${app_uid}}}" 2>/dev/null || true)"
assert_json_pred "VNXDP-06c METRICS.RESET traffic ok (uid=$app_uid)" "$traffic_reset2" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True'

traffic_zero2="$(ctl_cmd METRICS.GET "{\"name\":\"traffic\",\"app\":{\"uid\":${app_uid}}}" 2>/dev/null || true)"
assert_json_pred "VNXDP-06d traffic zero after reset (uid=$app_uid)" "$traffic_zero2" \
  'import sys,json; j=json.load(sys.stdin); t=j["result"]["traffic"]; total=0; \
   total += int(t["dns"]["allow"])+int(t["dns"]["block"]); \
   total += int(t["rxp"]["allow"])+int(t["rxp"]["block"]); \
   total += int(t["rxb"]["allow"])+int(t["rxb"]["block"]); \
   total += int(t["txp"]["allow"])+int(t["txp"]["block"]); \
   total += int(t["txb"]["allow"])+int(t["txb"]["block"]); \
   assert total==0'

set +e
printed="$(ctl_cmd IPRULES.PRINT "{\"app\":{\"uid\":${app_uid}}}" 2>/dev/null)"
st=$?
set -e
if [[ $st -ne 0 ]]; then
  echo "BLOCKED: IPRULES.PRINT failed" >&2
  exit 77
fi
hits="$(IP_PRINT_JSON="$printed" RULE_ID="$rule_id" python3 - <<'PY'
import os, json
j = json.loads(os.environ["IP_PRINT_JSON"])
rid = int(os.environ["RULE_ID"])
rules = j.get("result", {}).get("rules", [])
for r in rules:
  if int(r.get("ruleId", -1)) == rid:
    print(int(r.get("stats", {}).get("hitPackets", 0)))
    raise SystemExit(0)
print(0)
PY
)" || hits="0"

if [[ "$hits" =~ ^[0-9]+$ && "$hits" -ge 1 ]]; then
  log_pass "VNXDP-07 per-rule stats hitPackets increments (hitPackets=$hits)"
else
  log_fail "VNXDP-07 per-rule stats hitPackets increments"
  echo "    hitPackets=$hits"
  exit 1
fi

# -----------------------------------------------------------------------------
# Enforce block
# -----------------------------------------------------------------------------
set +e
reasons_reset="$(ctl_cmd METRICS.RESET '{"name":"reasons"}' 2>/dev/null)"
st=$?
set -e
if [[ $st -ne 0 ]]; then
  echo "BLOCKED: METRICS.RESET(reasons) failed" >&2
  exit 77
fi
assert_json_pred "VNXDP-08 METRICS.RESET reasons ok" "$reasons_reset" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True'

apply_args_block="{\"app\":{\"uid\":${app_uid}},\"rules\":[{\"clientRuleId\":\"dx-smoke:r2\",\"action\":\"block\",\"priority\":11,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"tcp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${dst_cidr}\",\"sport\":\"any\",\"dport\":\"443\"}]}"

set +e
apply_block="$(ctl_cmd IPRULES.APPLY "$apply_args_block" 2>/dev/null)"
st=$?
set -e
if [[ $st -ne 0 ]]; then
  echo "BLOCKED: IPRULES.APPLY(block) failed" >&2
  exit 77
fi
assert_json_pred "VNXDP-08b IPRULES.APPLY(block) ok" "$apply_block" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True; assert len(j["result"]["rules"])==1'

block_rule_id="$(APPLY_JSON="$apply_block" python3 - <<'PY'
import os, json
j = json.loads(os.environ["APPLY_JSON"])
rules = j["result"]["rules"]
print(rules[0]["ruleId"] if rules else "")
PY
)" || block_rule_id=""
if [[ ! "$block_rule_id" =~ ^[0-9]+$ ]]; then
  log_fail "VNXDP-08c IPRULES.APPLY(block) returns ruleId"
  echo "    ruleId=$block_rule_id"
  exit 1
fi
log_info "block ruleId=$block_rule_id"

tmp_dir2="$(mktemp -d)"
ready_file2="$tmp_dir2/stream_ready"

VNEXT_PORT="$VNEXT_PORT" EXPECT_UID="$app_uid" EXPECT_DST="$IPTEST_PEER_IP" EXPECT_RULE_ID="$block_rule_id" READY_FILE="$ready_file2" python3 - <<'PY' &
import json
import os
import socket
import sys
import time

PORT = int(os.environ["VNEXT_PORT"])
EXPECT_UID = int(os.environ["EXPECT_UID"])
EXPECT_DST = os.environ["EXPECT_DST"]
EXPECT_RULE_ID = int(os.environ["EXPECT_RULE_ID"])
READY_FILE = os.environ["READY_FILE"]


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
                    "dstIp": frame.get("dstIp"),
                    "dstPort": frame.get("dstPort"),
                    "accepted": frame.get("accepted"),
                    "reasonId": frame.get("reasonId"),
                    "ruleId": frame.get("ruleId"),
                }
            )

        if int(frame.get("uid", -1)) != EXPECT_UID:
            continue
        if frame.get("direction") != "out":
            continue
        if frame.get("dstIp") != EXPECT_DST:
            continue
        if int(frame.get("dstPort", -1)) != 443:
            continue
        if frame.get("reasonId") != "IP_RULE_BLOCK":
            continue
        if frame.get("accepted") is not False:
            continue
        if int(frame.get("ruleId", -1)) != EXPECT_RULE_ID:
            continue
        found = True
        break

    if not found:
        print("DEBUG: no matching pkt event found", file=sys.stderr)
        if samples:
            print("DEBUG: pkt samples (up to 5):", file=sys.stderr)
            for s in samples:
                print(json.dumps(s, separators=(",", ":")), file=sys.stderr)
        else:
            print("DEBUG: received no pkt frames within deadline", file=sys.stderr)

    rpc(sock, 2, "STREAM.STOP", {})
    sock.close()
    raise SystemExit(0 if found else 2)
except Exception:
    raise SystemExit(77)
PY
stream_pid2=$!

ready=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if [[ -f "$ready_file2" ]]; then
    ready=1
    break
  fi
  sleep 0.1
done
if [[ $ready -ne 1 ]]; then
  echo "BLOCKED: stream listener did not become ready (block)" >&2
  wait "$stream_pid2" >/dev/null 2>&1 || true
  rm -rf "$tmp_dir2"
  exit 77
fi

for _ in 1 2 3; do
  iptest_adb_shell "nc -n -z -w 1 \"$IPTEST_PEER_IP\" 443 >/dev/null 2>&1 || true" >/dev/null 2>&1 || true
done

set +e
wait "$stream_pid2"
rc=$?
set -e
rm -rf "$tmp_dir2"

if [[ $rc -eq 77 ]]; then
  echo "BLOCKED: stream capture failed (block)" >&2
  exit 77
fi
if [[ $rc -ne 0 ]]; then
  log_fail "VNXDP-08d STREAM pkt contains IP_RULE_BLOCK + ruleId"
  exit 1
fi
log_pass "VNXDP-08d STREAM pkt contains IP_RULE_BLOCK + ruleId"

reasons_after="$(ctl_cmd METRICS.GET '{"name":"reasons"}' 2>/dev/null || true)"
assert_json_pred "VNXDP-08e reasons IP_RULE_BLOCK increments" "$reasons_after" \
  'import sys,json; j=json.load(sys.stdin); r=j["result"]["reasons"]["IP_RULE_BLOCK"]; assert int(r["packets"]) >= 1'

printed_block="$(ctl_cmd IPRULES.PRINT "{\"app\":{\"uid\":${app_uid}}}" 2>/dev/null || true)"
hits_block="$(IP_PRINT_JSON="$printed_block" RULE_ID="$block_rule_id" python3 - <<'PY'
import os, json
j = json.loads(os.environ["IP_PRINT_JSON"] or "{}")
rid = int(os.environ["RULE_ID"])
for r in j.get("result", {}).get("rules", []):
  if int(r.get("ruleId", -1)) == rid:
    print(int(r.get("stats", {}).get("hitPackets", 0)))
    raise SystemExit(0)
print(0)
PY
)" || hits_block="0"
if [[ "$hits_block" =~ ^[0-9]+$ && "$hits_block" -ge 1 ]]; then
  log_pass "VNXDP-08f per-rule stats hitPackets increments (hitPackets=$hits_block)"
else
  log_fail "VNXDP-08f per-rule stats hitPackets increments"
  echo "    hitPackets=$hits_block"
  exit 1
fi

# -----------------------------------------------------------------------------
# Would-match overlay (enforce=0) on final ACCEPT
# -----------------------------------------------------------------------------
set +e
reasons_reset="$(ctl_cmd METRICS.RESET '{"name":"reasons"}' 2>/dev/null)"
st=$?
set -e
if [[ $st -ne 0 ]]; then
  echo "BLOCKED: METRICS.RESET(reasons) failed (would)" >&2
  exit 77
fi
assert_json_pred "VNXDP-09 METRICS.RESET reasons ok (would)" "$reasons_reset" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True'

apply_args_would="{\"app\":{\"uid\":${app_uid}},\"rules\":[{\"clientRuleId\":\"dx-smoke:r3\",\"action\":\"block\",\"priority\":12,\"enabled\":1,\"enforce\":0,\"log\":1,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"tcp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${dst_cidr}\",\"sport\":\"any\",\"dport\":\"443\"}]}"
apply_would="$(ctl_cmd IPRULES.APPLY "$apply_args_would" 2>/dev/null || true)"
assert_json_pred "VNXDP-09b IPRULES.APPLY(would) ok" "$apply_would" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True; assert len(j["result"]["rules"])==1'

would_rule_id="$(APPLY_JSON="$apply_would" python3 - <<'PY'
import os, json
j = json.loads(os.environ["APPLY_JSON"])
rules = j["result"]["rules"]
print(rules[0]["ruleId"] if rules else "")
PY
)" || would_rule_id=""
if [[ ! "$would_rule_id" =~ ^[0-9]+$ ]]; then
  log_fail "VNXDP-09c IPRULES.APPLY(would) returns ruleId"
  echo "    ruleId=$would_rule_id"
  exit 1
fi
log_info "would ruleId=$would_rule_id"

tmp_dir3="$(mktemp -d)"
ready_file3="$tmp_dir3/stream_ready"

VNEXT_PORT="$VNEXT_PORT" EXPECT_UID="$app_uid" EXPECT_DST="$IPTEST_PEER_IP" EXPECT_WOULD_RULE_ID="$would_rule_id" READY_FILE="$ready_file3" python3 - <<'PY' &
import json
import os
import socket
import sys
import time

PORT = int(os.environ["VNEXT_PORT"])
EXPECT_UID = int(os.environ["EXPECT_UID"])
EXPECT_DST = os.environ["EXPECT_DST"]
EXPECT_WOULD_RULE_ID = int(os.environ["EXPECT_WOULD_RULE_ID"])
READY_FILE = os.environ["READY_FILE"]


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
                    "dstIp": frame.get("dstIp"),
                    "dstPort": frame.get("dstPort"),
                    "accepted": frame.get("accepted"),
                    "reasonId": frame.get("reasonId"),
                    "ruleId": frame.get("ruleId"),
                    "wouldRuleId": frame.get("wouldRuleId"),
                }
            )

        if int(frame.get("uid", -1)) != EXPECT_UID:
            continue
        if frame.get("direction") != "out":
            continue
        if frame.get("dstIp") != EXPECT_DST:
            continue
        if int(frame.get("dstPort", -1)) != 443:
            continue
        if frame.get("reasonId") != "ALLOW_DEFAULT":
            continue
        if frame.get("accepted") is not True:
            continue
        if "ruleId" in frame:
            continue
        if int(frame.get("wouldRuleId", -1)) != EXPECT_WOULD_RULE_ID:
            continue
        found = True
        break

    if not found:
        print("DEBUG: no matching pkt event found", file=sys.stderr)
        if samples:
            print("DEBUG: pkt samples (up to 5):", file=sys.stderr)
            for s in samples:
                print(json.dumps(s, separators=(",", ":")), file=sys.stderr)
        else:
            print("DEBUG: received no pkt frames within deadline", file=sys.stderr)

    rpc(sock, 2, "STREAM.STOP", {})
    sock.close()
    raise SystemExit(0 if found else 2)
except Exception:
    raise SystemExit(77)
PY
stream_pid3=$!

ready=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if [[ -f "$ready_file3" ]]; then
    ready=1
    break
  fi
  sleep 0.1
done
if [[ $ready -ne 1 ]]; then
  echo "BLOCKED: stream listener did not become ready (would)" >&2
  wait "$stream_pid3" >/dev/null 2>&1 || true
  rm -rf "$tmp_dir3"
  exit 77
fi

for _ in 1 2 3; do
  iptest_adb_shell "nc -n -z -w 1 \"$IPTEST_PEER_IP\" 443 >/dev/null 2>&1 || true" >/dev/null 2>&1 || true
done

set +e
wait "$stream_pid3"
rc=$?
set -e
rm -rf "$tmp_dir3"

if [[ $rc -eq 77 ]]; then
  echo "BLOCKED: stream capture failed (would)" >&2
  exit 77
fi
if [[ $rc -ne 0 ]]; then
  log_fail "VNXDP-09d STREAM pkt contains wouldRuleId on ACCEPT"
  exit 1
fi
log_pass "VNXDP-09d STREAM pkt contains wouldRuleId on ACCEPT"

reasons_after="$(ctl_cmd METRICS.GET '{"name":"reasons"}' 2>/dev/null || true)"
assert_json_pred "VNXDP-09e reasons ALLOW_DEFAULT increments" "$reasons_after" \
  'import sys,json; j=json.load(sys.stdin); r=j["result"]["reasons"]["ALLOW_DEFAULT"]; assert int(r["packets"]) >= 1'

printed_would="$(ctl_cmd IPRULES.PRINT "{\"app\":{\"uid\":${app_uid}}}" 2>/dev/null || true)"
would_hits="$(IP_PRINT_JSON="$printed_would" RULE_ID="$would_rule_id" python3 - <<'PY'
import os, json
j = json.loads(os.environ["IP_PRINT_JSON"] or "{}")
rid = int(os.environ["RULE_ID"])
for r in j.get("result", {}).get("rules", []):
  if int(r.get("ruleId", -1)) == rid:
    print(int(r.get("stats", {}).get("wouldHitPackets", 0)))
    raise SystemExit(0)
print(0)
PY
)" || would_hits="0"
if [[ "$would_hits" =~ ^[0-9]+$ && "$would_hits" -ge 1 ]]; then
  log_pass "VNXDP-09f per-rule stats wouldHitPackets increments (wouldHitPackets=$would_hits)"
else
  log_fail "VNXDP-09f per-rule stats wouldHitPackets increments"
  echo "    wouldHitPackets=$would_hits"
  exit 1
fi

# -----------------------------------------------------------------------------
# IFACE_BLOCK + BLOCK=0 (reasons gating)
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

set +e
reasons_reset="$(ctl_cmd METRICS.RESET '{"name":"reasons"}' 2>/dev/null)"
st=$?
set -e
if [[ $st -ne 0 ]]; then
  echo "BLOCKED: METRICS.RESET(reasons) failed (iface)" >&2
  exit 77
fi
assert_json_pred "VNXDP-10 METRICS.RESET reasons ok (iface)" "$reasons_reset" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True'

apply_args_iface="{\"app\":{\"uid\":${app_uid}},\"rules\":[{\"clientRuleId\":\"dx-smoke:r4\",\"action\":\"allow\",\"priority\":13,\"enabled\":1,\"enforce\":1,\"log\":0,\"dir\":\"out\",\"iface\":\"any\",\"ifindex\":0,\"proto\":\"tcp\",\"ct\":{\"state\":\"any\",\"direction\":\"any\"},\"src\":\"any\",\"dst\":\"${dst_cidr}\",\"sport\":\"any\",\"dport\":\"443\"}]}"
apply_iface="$(ctl_cmd IPRULES.APPLY "$apply_args_iface" 2>/dev/null || true)"
assert_json_pred "VNXDP-10b IPRULES.APPLY(iface) ok" "$apply_iface" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True; assert len(j["result"]["rules"])==1'
iface_rule_id="$(APPLY_JSON="$apply_iface" python3 - <<'PY'
import os, json
j = json.loads(os.environ["APPLY_JSON"])
rules = j["result"]["rules"]
print(rules[0]["ruleId"] if rules else "")
PY
)" || iface_rule_id=""
if [[ ! "$iface_rule_id" =~ ^[0-9]+$ ]]; then
  log_fail "VNXDP-10c IPRULES.APPLY(iface) returns ruleId"
  echo "    ruleId=$iface_rule_id"
  exit 1
fi

printed_before_iface="$(ctl_cmd IPRULES.PRINT "{\"app\":{\"uid\":${app_uid}}}" 2>/dev/null || true)"
hits_before_iface="$(IP_PRINT_JSON="$printed_before_iface" RULE_ID="$iface_rule_id" python3 - <<'PY'
import os, json
j = json.loads(os.environ["IP_PRINT_JSON"] or "{}")
rid = int(os.environ["RULE_ID"])
for r in j.get("result", {}).get("rules", []):
  if int(r.get("ruleId", -1)) == rid:
    print(int(r.get("stats", {}).get("hitPackets", 0)))
    raise SystemExit(0)
print(0)
PY
)" || hits_before_iface="0"

cfg_iface="$(ctl_cmd CONFIG.SET "{\"scope\":\"app\",\"app\":{\"uid\":${app_uid}},\"set\":{\"block.ifaceKindMask\":${iface_kind_bit}}}" 2>/dev/null || true)"
assert_json_pred "VNXDP-10d CONFIG.SET block.ifaceKindMask ack" "$cfg_iface" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True'

tmp_dir4="$(mktemp -d)"
ready_file4="$tmp_dir4/stream_ready"
VNEXT_PORT="$VNEXT_PORT" EXPECT_UID="$app_uid" EXPECT_DST="$IPTEST_PEER_IP" READY_FILE="$ready_file4" python3 - <<'PY' &
import json
import os
import socket
import sys
import time

PORT = int(os.environ["VNEXT_PORT"])
EXPECT_UID = int(os.environ["EXPECT_UID"])
EXPECT_DST = os.environ["EXPECT_DST"]
READY_FILE = os.environ["READY_FILE"]


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
                    "dstIp": frame.get("dstIp"),
                    "dstPort": frame.get("dstPort"),
                    "accepted": frame.get("accepted"),
                    "reasonId": frame.get("reasonId"),
                    "ruleId": frame.get("ruleId"),
                    "wouldRuleId": frame.get("wouldRuleId"),
                }
            )

        if int(frame.get("uid", -1)) != EXPECT_UID:
            continue
        if frame.get("direction") != "out":
            continue
        if frame.get("dstIp") != EXPECT_DST:
            continue
        if int(frame.get("dstPort", -1)) != 443:
            continue
        if frame.get("reasonId") != "IFACE_BLOCK":
            continue
        if frame.get("accepted") is not False:
            continue
        if "ruleId" in frame or "wouldRuleId" in frame:
            continue
        found = True
        break

    if not found:
        print("DEBUG: no matching pkt event found", file=sys.stderr)
        if samples:
            print("DEBUG: pkt samples (up to 5):", file=sys.stderr)
            for s in samples:
                print(json.dumps(s, separators=(",", ":")), file=sys.stderr)
        else:
            print("DEBUG: received no pkt frames within deadline", file=sys.stderr)

    rpc(sock, 2, "STREAM.STOP", {})
    sock.close()
    raise SystemExit(0 if found else 2)
except Exception:
    raise SystemExit(77)
PY
stream_pid4=$!

ready=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if [[ -f "$ready_file4" ]]; then
    ready=1
    break
  fi
  sleep 0.1
done
if [[ $ready -ne 1 ]]; then
  echo "BLOCKED: stream listener did not become ready (iface)" >&2
  wait "$stream_pid4" >/dev/null 2>&1 || true
  rm -rf "$tmp_dir4"
  exit 77
fi

for _ in 1 2 3; do
  iptest_adb_shell "nc -n -z -w 1 \"$IPTEST_PEER_IP\" 443 >/dev/null 2>&1 || true" >/dev/null 2>&1 || true
done

set +e
wait "$stream_pid4"
rc=$?
set -e
rm -rf "$tmp_dir4"

if [[ $rc -eq 77 ]]; then
  echo "BLOCKED: stream capture failed (iface)" >&2
  exit 77
fi
if [[ $rc -ne 0 ]]; then
  log_fail "VNXDP-10e STREAM pkt contains IFACE_BLOCK (no ruleId)"
  exit 1
fi
log_pass "VNXDP-10e STREAM pkt contains IFACE_BLOCK (no ruleId)"

reasons_after="$(ctl_cmd METRICS.GET '{"name":"reasons"}' 2>/dev/null || true)"
assert_json_pred "VNXDP-10f reasons IFACE_BLOCK increments" "$reasons_after" \
  'import sys,json; j=json.load(sys.stdin); r=j["result"]["reasons"]["IFACE_BLOCK"]; assert int(r["packets"]) >= 1'

printed_after_iface="$(ctl_cmd IPRULES.PRINT "{\"app\":{\"uid\":${app_uid}}}" 2>/dev/null || true)"
hits_after_iface="$(IP_PRINT_JSON="$printed_after_iface" RULE_ID="$iface_rule_id" python3 - <<'PY'
import os, json
j = json.loads(os.environ["IP_PRINT_JSON"] or "{}")
rid = int(os.environ["RULE_ID"])
for r in j.get("result", {}).get("rules", []):
  if int(r.get("ruleId", -1)) == rid:
    print(int(r.get("stats", {}).get("hitPackets", 0)))
    raise SystemExit(0)
print(0)
PY
)" || hits_after_iface="0"
if [[ "$hits_after_iface" == "$hits_before_iface" ]]; then
  log_pass "VNXDP-10g IFACE_BLOCK does not grow rule stats (hitPackets=$hits_after_iface)"
else
  log_fail "VNXDP-10g IFACE_BLOCK does not grow rule stats"
  echo "    hitPackets before=$hits_before_iface after=$hits_after_iface"
  exit 1
fi

cfg_iface_restore="$(ctl_cmd CONFIG.SET "{\"scope\":\"app\",\"app\":{\"uid\":${app_uid}},\"set\":{\"block.ifaceKindMask\":${iface_mask_orig}}}" 2>/dev/null || true)"
assert_json_pred "VNXDP-10h restore block.ifaceKindMask ack" "$cfg_iface_restore" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True'

set +e
reasons_reset="$(ctl_cmd METRICS.RESET '{"name":"reasons"}' 2>/dev/null)"
st=$?
set -e
if [[ $st -ne 0 ]]; then
  echo "BLOCKED: METRICS.RESET(reasons) failed (block=0)" >&2
  exit 77
fi
assert_json_pred "VNXDP-11 METRICS.RESET reasons ok (block=0)" "$reasons_reset" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True'

cfg_block0="$(ctl_cmd CONFIG.SET '{"scope":"device","set":{"block.enabled":0}}' 2>/dev/null || true)"
assert_json_pred "VNXDP-11b CONFIG.SET block.enabled=0 ack" "$cfg_block0" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True'

for _ in 1 2 3; do
  iptest_adb_shell "nc -n -z -w 1 \"$IPTEST_PEER_IP\" 443 >/dev/null 2>&1 || true" >/dev/null 2>&1 || true
done

reasons_after="$(ctl_cmd METRICS.GET '{"name":"reasons"}' 2>/dev/null || true)"
assert_json_pred "VNXDP-11c reasons gated by block.enabled=0 (totalPackets==0)" "$reasons_after" \
  'import sys,json; j=json.load(sys.stdin); r=j["result"]["reasons"]; total=sum(int(v["packets"]) for v in r.values()); assert total==0'

cfg_block1="$(ctl_cmd CONFIG.SET '{"scope":"device","set":{"block.enabled":1}}' 2>/dev/null || true)"
assert_json_pred "VNXDP-11d CONFIG.SET block.enabled=1 ack" "$cfg_block1" \
  'import sys,json; j=json.load(sys.stdin); assert j["ok"] is True'

log_pass "iprules vNext datapath smoke ok"
exit 0
