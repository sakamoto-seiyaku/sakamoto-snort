#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-55 product VPN/TUN + HEV transport evidence matrix.
#
# This matrix is intentionally product-path only: it starts the Android
# RuntimeService VPN profile, waits for attach-later TUN/transport handoff,
# generates real IPv4 TCP, IPv6 TCP, and UDP DNS traffic through the VPN, and
# records control-plane counters proving transport outcome is separate from
# policy verdict.

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"

# Force device operations through the repo-local wrapper.
export ADB="${repo_root}/dev/adb"
source "${repo_root}/dev/dev-android-device-lib.sh"

PACKAGE="${PACKAGE:-com.sakamoto.snort.androidruntime}"
ACTIVITY="${ACTIVITY:-${PACKAGE}/.DebugControlActivity}"
RESULTS_ROOT="${RESULTS_ROOT:-${repo_root}/build-output/s55-product-vpn-transport-matrix}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
RESULT_DIR="${RESULT_DIR:-${RESULTS_ROOT}/${RUN_ID}}"
APK="${APK:-${repo_root}/app/android-runtime/build/outputs/sakamoto-runtime-debug.apk}"
S55_BUILD_APK="${S55_BUILD_APK:-1}"
S55_INSTALL_APK="${S55_INSTALL_APK:-1}"
S55_FORWARD_PORT="${S55_FORWARD_PORT:-60655}"
S55_CLEANUP_ON_EXIT="${S55_CLEANUP_ON_EXIT:-1}"
S55_IPV4_TCP_HOST="${S55_IPV4_TCP_HOST:-1.1.1.1}"
S55_IPV4_TCP_PORT="${S55_IPV4_TCP_PORT:-80}"
S55_IPV6_TCP_HOST="${S55_IPV6_TCP_HOST:-2606:4700:4700::1111}"
S55_IPV6_TCP_PORT="${S55_IPV6_TCP_PORT:-80}"
S55_IPV6_REQUIRED="${S55_IPV6_REQUIRED:-1}"
S55_UDP_DNS_HOST="${S55_UDP_DNS_HOST:-1.1.1.1}"
S55_UDP_DNS_PORT="${S55_UDP_DNS_PORT:-53}"
SOCKS5_BUILD_SCRIPT="${repo_root}/experiments/vpp-nfq-poc/scripts/android-build-socks5-smoke-server.sh"
SOCKS5_HOST_BIN="${repo_root}/experiments/vpp-nfq-poc/build/android-socks5-smoke-server"
SOCKS5_REMOTE_BIN="${SOCKS5_REMOTE_BIN:-/data/local/tmp/sakamoto-s55-socks5-smoke}"
SOCKS5_REMOTE_LOG="${SOCKS5_REMOTE_LOG:-/data/local/tmp/sakamoto-s55-socks5-smoke.log}"
SOCKS5_REMOTE_PID="${SOCKS5_REMOTE_PID:-/data/local/tmp/sakamoto-s55-socks5-smoke.pid}"
STATE_PATH="files/runtime-state/snapshot.properties"
LOG_PATH="files/logs/runtime-service.log"
VPN_HEV_LOG_PATH="files/profiles/vpn/vpp/logs/vpn-hev.log"
VPN_HEV_PROTECT_LOG_PATH="files/profiles/vpn/vpp/logs/vpn-hev-protect.log"
CONTROL_SOCKET="sucre-snort-control-vnext"

mkdir -p "$RESULT_DIR"

kv() {
  printf '%s=%s\n' "$1" "$2"
}

section() {
  printf '\n## %s\n' "$1"
}

cleanup() {
  if [[ "$S55_CLEANUP_ON_EXIT" != "1" ]]; then
    return
  fi
  adb_cmd shell am start -n "$ACTIVITY" --ez runtimeStop true >/dev/null 2>&1 || true
  adb_cmd forward --remove "tcp:${S55_FORWARD_PORT}" >/dev/null 2>&1 || true
  adb_su "if [ -f '$SOCKS5_REMOTE_PID' ]; then kill \"\$(cat '$SOCKS5_REMOTE_PID')\" 2>/dev/null || true; fi; pidof sakamoto-s55-socks5-smoke 2>/dev/null | xargs -r kill 2>/dev/null || true" >/dev/null 2>&1 || true
}
trap cleanup EXIT

read_snapshot() {
  adb_cmd shell run-as "$PACKAGE" cat "$STATE_PATH" 2>/dev/null | tr -d '\r' || true
}

snapshot_value() {
  local key="$1"
  awk -F= -v key="$key" '$1 == key { print $2; found=1 } END { if (!found) exit 1 }'
}

wait_for_snapshot_field() {
  local key="$1"
  local expected="$2"
  local out_file="$3"
  local attempts="${4:-45}"
  local state=""
  for _ in $(seq 1 "$attempts"); do
    state="$(read_snapshot)"
    printf '%s\n' "$state" >"$out_file"
    if grep -Fxq "${key}=${expected}" <<<"$state"; then
      printf '%s\n' "$state"
      return 0
    fi
    sleep 1
  done
  return 1
}

run_device_shell() {
  local name="$1"
  local command="$2"
  local output_file="${RESULT_DIR}/${name}.log"
  local quoted_command
  quoted_command="$(shell_single_quote "$command")"
  set +e
  adb_cmd shell "sh -c ${quoted_command}" >"$output_file" 2>&1
  local rc=$?
  set -e
  kv "${name}.rc" "$rc"
  kv "${name}.log" "${output_file#${repo_root}/}"
  return "$rc"
}

query_control_json() {
  local name="$1"
  local command="$2"
  local args="${3:-{}}"
  python3 - "$S55_FORWARD_PORT" "$RESULT_DIR" "$name" "$command" "$args" <<'PY'
import json
import pathlib
import socket
import sys

port = int(sys.argv[1])
result_dir = pathlib.Path(sys.argv[2])
name = sys.argv[3]
command = sys.argv[4]
args = json.loads(sys.argv[5])

payload = json.dumps({"id": 1, "cmd": command, "args": args},
                     separators=(",", ":")).encode()
frame = str(len(payload)).encode() + b":" + payload + b","

with socket.create_connection(("127.0.0.1", port), timeout=2.5) as sock:
    sock.sendall(frame)
    digits = bytearray()
    while True:
        byte = sock.recv(1)
        if not byte:
            raise RuntimeError("eof before netstring length")
        if byte == b":":
            break
        digits += byte
    length = int(digits)
    body = bytearray()
    while len(body) < length:
        chunk = sock.recv(length - len(body))
        if not chunk:
            raise RuntimeError("eof in netstring body")
        body += chunk
    if sock.recv(1) != b",":
        raise RuntimeError("missing netstring comma")
    response = json.loads(body.decode())

(result_dir / f"{name}.json").write_text(
    json.dumps(response, indent=2, sort_keys=True) + "\n")
if not response.get("ok"):
    raise SystemExit(f"{command} failed: {response}")
PY
}

assert_counter_delta() {
  local before_json="$1"
  local after_json="$2"
  local key="$3"
  local min_delta="$4"
  python3 - "$before_json" "$after_json" "$key" "$min_delta" <<'PY'
import json
import sys

before = json.load(open(sys.argv[1]))["result"]
after = json.load(open(sys.argv[2]))["result"]
key = sys.argv[3]
min_delta = int(sys.argv[4])
delta = int(after[key]) - int(before[key])
print(delta)
if delta < min_delta:
    raise SystemExit(f"{key} delta {delta} < {min_delta}")
PY
}

section "matrix_contract"
require_adb_device
kv "matrix" "SAKAMOTO-55-product-vpn-transport"
kv "resultDir" "${RESULT_DIR#${repo_root}/}"
kv "adbWrapper" "./dev/adb"
kv "device" "$(adb_target_desc)"
kv "package" "$PACKAGE"
kv "activity" "$ACTIVITY"
kv "productRuntimeServiceVpnAdapter" "claimed"
kv "transportOutcomeSeparateFromPolicyDrop" "claimed"
kv "icmpEchoCapability" "not_claimed"

section "build_install"
if [[ "$S55_BUILD_APK" == "1" ]]; then
  kv "build.command" "bash app/android-runtime/scripts/build-debug-apk.sh"
  (cd "$repo_root" && bash app/android-runtime/scripts/build-debug-apk.sh) \
    >"${RESULT_DIR}/build-debug-apk.log" 2>&1
  kv "build.result" "PASS"
  kv "socks5.build.command" "bash experiments/vpp-nfq-poc/scripts/android-build-socks5-smoke-server.sh"
  (cd "$repo_root" && bash "$SOCKS5_BUILD_SCRIPT") \
    >"${RESULT_DIR}/build-socks5-smoke-server.log" 2>&1
  kv "socks5.build.result" "PASS"
fi
[[ -f "$APK" ]] || {
  kv "apk.exists" "false"
  echo "missing APK: $APK" >&2
  exit 1
}
kv "apk" "${APK#${repo_root}/}"
kv "apk.sha256" "$(sha256sum "$APK" | awk '{print $1}')"
if [[ "$S55_INSTALL_APK" == "1" ]]; then
  adb_cmd install -r "$APK" >"${RESULT_DIR}/install.log" 2>&1
  kv "install.result" "PASS"
fi

section "socks5_upstream"
[[ -f "$SOCKS5_HOST_BIN" ]] || {
  kv "socks5.hostBin.exists" "false"
  echo "missing SOCKS5 smoke server: $SOCKS5_HOST_BIN" >&2
  exit 1
}
adb_cmd push "$SOCKS5_HOST_BIN" "$SOCKS5_REMOTE_BIN" >"${RESULT_DIR}/push-socks5.log" 2>&1
adb_su "chmod 755 '$SOCKS5_REMOTE_BIN'; if [ -f '$SOCKS5_REMOTE_PID' ]; then kill \"\$(cat '$SOCKS5_REMOTE_PID')\" 2>/dev/null || true; fi; pidof sakamoto-s55-socks5-smoke 2>/dev/null | xargs -r kill 2>/dev/null || true; rm -f '$SOCKS5_REMOTE_LOG'; nohup '$SOCKS5_REMOTE_BIN' >'$SOCKS5_REMOTE_LOG' 2>&1 < /dev/null & echo \$! > '$SOCKS5_REMOTE_PID'"
for _ in $(seq 1 20); do
  adb_cmd shell cat "$SOCKS5_REMOTE_LOG" >"${RESULT_DIR}/socks5.start.log" 2>/dev/null || true
  if grep -q 'android socks5 smoke server ready' "${RESULT_DIR}/socks5.start.log"; then
    kv "socks5.start.result" "PASS"
    break
  fi
  sleep 0.5
done
grep -q 'android socks5 smoke server ready' "${RESULT_DIR}/socks5.start.log"

section "start_vpn"
adb_cmd shell am force-stop "$PACKAGE" >/dev/null
adb_cmd shell am start -n "$ACTIVITY" --ez runtimeStart true --es runtimeProfile vpn \
  >"${RESULT_DIR}/start.intent.log" 2>&1
state=""
for _ in $(seq 1 45); do
  state="$(read_snapshot)"
  printf '%s\n' "$state" >"${RESULT_DIR}/snapshot.running"
  if grep -Fxq "state=running" <<<"$state" \
      && grep -Fxq "profile=vpn" <<<"$state" \
      && grep -Fxq "health=ok" <<<"$state" \
      && grep -Fxq "coreHealth=ok" <<<"$state" \
      && grep -Fxq "adapterReadiness=vpn-tun-hev" <<<"$state"; then
    break
  fi
  sleep 1
done
if ! grep -Fxq "state=running" <<<"$state" \
    || ! grep -Fxq "profile=vpn" <<<"$state" \
    || ! grep -Fxq "health=ok" <<<"$state" \
    || ! grep -Fxq "coreHealth=ok" <<<"$state" \
    || ! grep -Fxq "adapterReadiness=vpn-tun-hev" <<<"$state"; then
  kv "start.result" "FAIL"
  cat "${RESULT_DIR}/snapshot.running" >&2
  exit 1
fi
kv "start.result" "PASS"
kv "snapshot.pid" "$(printf '%s\n' "$state" | snapshot_value pid)"

section "runtime_log"
adb_cmd shell run-as "$PACKAGE" cat "$LOG_PATH" >"${RESULT_DIR}/runtime-service.log" 2>/dev/null
grep -q "vpn_tun_control_ready=ok" "${RESULT_DIR}/runtime-service.log"
grep -q "vpn_tun_control_attach=ok adapter=vpn-tun-hev" "${RESULT_DIR}/runtime-service.log"
grep -q "vpn_hev_transport=ok" "${RESULT_DIR}/runtime-service.log"
kv "runtimeLog.attachLater" "PASS"

section "protect_anti_loop"
protect_ok=0
for _ in $(seq 1 20); do
  adb_cmd shell run-as "$PACKAGE" cat "$VPN_HEV_PROTECT_LOG_PATH" \
    >"${RESULT_DIR}/vpn-hev-protect.log" 2>/dev/null || true
  adb_cmd shell run-as "$PACKAGE" cat "$VPN_HEV_LOG_PATH" \
    >"${RESULT_DIR}/vpn-hev.log" 2>/dev/null || true
  if grep -Eq 'protect fd=[0-9]+ result=1' "${RESULT_DIR}/vpn-hev-protect.log" \
      && grep -q 'protect callback enabled' "${RESULT_DIR}/vpn-hev.log"; then
    protect_ok=1
    break
  fi
  sleep 1
done
[[ "$protect_ok" == "1" ]] || {
  kv "protect.result" "FAIL"
  exit 1
}
kv "protect.beforeUpstreamConnect" "PASS"

section "control_socket"
adb_cmd forward "tcp:${S55_FORWARD_PORT}" "localabstract:${CONTROL_SOCKET}" \
  >"${RESULT_DIR}/adb-forward.log" 2>&1
query_control_json "hello" "HELLO"
python3 - "${RESULT_DIR}/hello.json" <<'PY'
import json
import sys

hello = json.load(open(sys.argv[1]))
caps = set(hello["result"]["capabilities"])
required = {
    "packet-adapter-vpn-tun-hev",
    "vpn-tun-fd-handoff",
    "vpn-tun-transport-fd-handoff",
    "vpn-tun-runtime-counters",
    "packet-policy-control",
}
missing = sorted(required - caps)
if missing:
    raise SystemExit(f"missing capabilities: {missing}")
PY
kv "control.HELLO" "PASS"

section "traffic_before"
query_control_json "vpn_tun_status.before" "VPN_TUN.STATUS"
query_control_json "policy_status.before" "POLICY.STATUS"

section "tcp4_real_connection"
run_device_shell "tcp4_connect" \
  "toybox timeout 8 toybox nc -4 -z -w 5 ${S55_IPV4_TCP_HOST} ${S55_IPV4_TCP_PORT}"
kv "tcp4.host" "$S55_IPV4_TCP_HOST"
kv "tcp4.port" "$S55_IPV4_TCP_PORT"
kv "tcp4.result" "PASS"

section "tcp6_real_connection"
set +e
ipv6_route="$(adb_cmd shell ip -6 route get "$S55_IPV6_TCP_HOST" 2>&1 | tr -d '\r')"
ipv6_route_rc=$?
set -e
printf '%s\n' "$ipv6_route" >"${RESULT_DIR}/tcp6.route.log"
kv "tcp6.routeRc" "$ipv6_route_rc"
kv "tcp6.routeLog" "${RESULT_DIR#${repo_root}/}/tcp6.route.log"
if [[ "$ipv6_route_rc" != "0" || "$ipv6_route" == *"unreachable"* \
      || "$ipv6_route" == *"Network is unreachable"* || "$ipv6_route" != *" dev "* ]]; then
  kv "tcp6.result" "UNAVAILABLE"
  kv "tcp6.reason" "no_usable_ipv6_route"
  if [[ "$S55_IPV6_REQUIRED" == "1" ]]; then
    exit 1
  fi
else
  run_device_shell "tcp6_connect" \
    "toybox timeout 8 toybox nc -6 -z -w 5 ${S55_IPV6_TCP_HOST} ${S55_IPV6_TCP_PORT}"
  kv "tcp6.host" "$S55_IPV6_TCP_HOST"
  kv "tcp6.port" "$S55_IPV6_TCP_PORT"
  kv "tcp6.result" "PASS"
fi

section "udp_dns_relay"
dns_query="toybox printf '\\000\\001\\001\\000\\000\\001\\000\\000\\000\\000\\000\\000\\007example\\003com\\000\\000\\001\\000\\001' | toybox nc -u -q 1 -W 2 -w 2 ${S55_UDP_DNS_HOST} ${S55_UDP_DNS_PORT} | toybox wc -c"
run_device_shell "udp_dns_response_bytes" "toybox timeout 6 sh -c $(shell_single_quote "$dns_query")"
udp_bytes="$(tr -d '\r[:space:]' <"${RESULT_DIR}/udp_dns_response_bytes.log")"
[[ "$udp_bytes" =~ ^[0-9]+$ ]] || {
  kv "udp_dns.result" "FAIL"
  kv "udp_dns.reason" "non_numeric_response_bytes"
  exit 1
}
if (( udp_bytes <= 0 )); then
  kv "udp_dns.result" "FAIL"
  kv "udp_dns.responseBytes" "$udp_bytes"
  exit 1
fi
kv "udp_dns.host" "$S55_UDP_DNS_HOST"
kv "udp_dns.port" "$S55_UDP_DNS_PORT"
kv "udp_dns.responseBytes" "$udp_bytes"
kv "udp_dns.result" "PASS"
adb_cmd shell cat "$SOCKS5_REMOTE_LOG" >"${RESULT_DIR}/socks5.after-udp.log" 2>/dev/null || true
grep -q 'fwd-udp' "${RESULT_DIR}/socks5.after-udp.log"
grep -q 'udp response-len' "${RESULT_DIR}/socks5.after-udp.log"
kv "socks5.udpInTcpRelay" "PASS"

section "traffic_after"
query_control_json "vpn_tun_status.after" "VPN_TUN.STATUS"
query_control_json "policy_status.after" "POLICY.STATUS"
packets_delta="$(assert_counter_delta "${RESULT_DIR}/vpn_tun_status.before.json" \
  "${RESULT_DIR}/vpn_tun_status.after.json" packetsSeen 3)"
forwarded_delta="$(assert_counter_delta "${RESULT_DIR}/vpn_tun_status.before.json" \
  "${RESULT_DIR}/vpn_tun_status.after.json" forwardedPackets 3)"
transport_success_delta="$(assert_counter_delta "${RESULT_DIR}/vpn_tun_status.before.json" \
  "${RESULT_DIR}/vpn_tun_status.after.json" transportSucceededPackets 3)"
transport_return_delta="$(assert_counter_delta "${RESULT_DIR}/vpn_tun_status.before.json" \
  "${RESULT_DIR}/vpn_tun_status.after.json" transportReturnPackets 1)"
kv "counters.packetsSeenDelta" "$packets_delta"
kv "counters.forwardedPacketsDelta" "$forwarded_delta"
kv "counters.transportSucceededPacketsDelta" "$transport_success_delta"
kv "counters.transportReturnPacketsDelta" "$transport_return_delta"
python3 - "${RESULT_DIR}/vpn_tun_status.before.json" "${RESULT_DIR}/vpn_tun_status.after.json" <<'PY'
import json
import sys

before = json.load(open(sys.argv[1]))["result"].get("allowedFlowActivity", {})
after = json.load(open(sys.argv[2]))["result"].get("allowedFlowActivity", {})

before_total = int(before.get("totalRecords", 0))
after_total = int(after.get("totalRecords", 0))
if after_total - before_total < 3:
    raise SystemExit("allowedFlowActivity did not record VPN FlowEntry traffic")
if not after.get("hasLastRecord", False):
    raise SystemExit("allowedFlowActivity missing last FlowEntry record")
if int(after.get("lastPackets", 0)) <= 0:
    raise SystemExit("allowedFlowActivity lastPackets did not grow")
if int(after.get("lastBytes", 0)) <= 0:
    raise SystemExit("allowedFlowActivity lastBytes did not grow")
if str(after.get("lastDeviceDirection", "")) not in {"input", "output"}:
    raise SystemExit("allowedFlowActivity missing device packet direction")
if str(after.get("lastFlowDirection", "")) not in {"orig", "reply"}:
    raise SystemExit("allowedFlowActivity missing flow direction")
if int(after.get("lastIpProtocol", 0)) not in {6, 17}:
    raise SystemExit("allowedFlowActivity missing TCP/UDP protocol evidence")
print(f"allowed.totalRecordsDelta={after_total - before_total}")
print(f"allowed.lastUid={after.get('lastLinuxUid')}")
print(f"allowed.lastUidKnown={after.get('lastUidKnown')}")
print(f"allowed.lastRemote={after.get('lastDestinationAddress')}:{after.get('lastDestinationPort')}")
print(f"allowed.lastDeviceDirection={after.get('lastDeviceDirection')}")
print(f"allowed.lastFlowDirection={after.get('lastFlowDirection')}")
print(f"allowed.lastPackets={after.get('lastPackets')}")
print(f"allowed.lastBytes={after.get('lastBytes')}")
print(f"allowed.lastPolicyRevision={after.get('lastPolicyRevision')}")
PY
kv "allowedFlowActivity.vpnEvidence" "PASS"
python3 - "${RESULT_DIR}/vpn_tun_status.before.json" "${RESULT_DIR}/vpn_tun_status.after.json" <<'PY'
import json
import sys

before = json.load(open(sys.argv[1]))["result"]
after = json.load(open(sys.argv[2]))["result"]
if int(after["droppedPackets"]) != int(before["droppedPackets"]):
    raise SystemExit("policy droppedPackets changed during allow transport probe")
if int(after["transportFailedPackets"]) != int(before["transportFailedPackets"]):
    raise SystemExit("transport failure increased during nominal probe")
PY
kv "policyDrop.notUsedForTransportFailure" "PASS"
kv "transportOutcome.nominalSuccess" "PASS"

section "cleanup"
adb_cmd shell am start -n "$ACTIVITY" --ez runtimeStop true >"${RESULT_DIR}/stop.intent.log" 2>&1
stopped="$(wait_for_snapshot_field state stopped "${RESULT_DIR}/snapshot.stopped" 30)" || {
  kv "cleanup.result" "FAIL"
  cat "${RESULT_DIR}/snapshot.stopped" >&2
  exit 1
}
printf '%s\n' "$stopped" | grep -Fxq "mayBeActive=false"
printf '%s\n' "$stopped" | grep -Fxq "adapterReadiness=unavailable"
kv "cleanup.result" "PASS"

section "matrix_result"
kv "matrix.result" "PASS"
kv "matrix.s55TransportEvidence" "claimed"
