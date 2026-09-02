#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-178 Root NFQUEUE dual-stack TCP/UDP INPUT/OUTPUT real-device matrix.
#
# PASS means the installed debug APK starts Root Product VPP on the controlled
# Pixel 6a, the Root NFQUEUE adapter is ready for two lanes, IPv4/IPv6 TCP/UDP
# OUTPUT probes reach controlled host echo endpoints, IPv4/IPv6 TCP/UDP INPUT
# probes reach app-UID listeners on the device, and STOP/restart removes hook
# residue. Device PASS is the only PASS.

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export ADB="${repo_root}/dev/adb"

readonly S178_SERIAL="28201JEGR0XPAJ"
readonly PACKAGE="${PACKAGE:-com.sakamoto.snort.androidruntime}"
readonly ACTIVITY="${ACTIVITY:-${PACKAGE}/.DebugControlActivity}"
readonly RESULTS_ROOT="${RESULTS_ROOT:-${repo_root}/build-output/s178-root-nfqueue-dual-stack-matrix}"
readonly RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
readonly RESULT_DIR="${RESULT_DIR:-${RESULTS_ROOT}/${RUN_ID}}"

readonly STATE_PATH="${STATE_PATH:-files/runtime-state/snapshot.properties}"
readonly STATUS_PATH="${STATUS_PATH:-files/product-state/s178-root-nfqueue-matrix.properties}"
readonly CLEANUP_PATH="${CLEANUP_PATH:-files/product-state/s176-root-nfqueue-cleanup.properties}"
readonly TCP_PROBE_PATH="${TCP_PROBE_PATH:-files/debug/traffic-probe.properties}"
readonly UDP_PROBE_PATH="${UDP_PROBE_PATH:-files/debug/udp-traffic-probe.properties}"
readonly TCP_LISTENER_PATH="${TCP_LISTENER_PATH:-files/debug/tcp-listener.properties}"
readonly UDP_LISTENER_PATH="${UDP_LISTENER_PATH:-files/debug/udp-listener.properties}"

usage() {
  cat <<'EOF'
Usage:
  tests/device/s178-root-nfqueue-dual-stack-matrix-product.sh --run \
    --host4 <controlled-lan-ipv4> --host6 <controlled-lan-ipv6>

Required:
  --run
  --host4 / S178_CONTROLLED_LAN_HOST4
  --host6 / S178_CONTROLLED_LAN_HOST6

Optional:
  --serial 28201JEGR0XPAJ
  --base-port / S178_BASE_PORT            default 18178
  --timeout-ms / S178_TIMEOUT_MILLIS      default 5000

The host addresses must be local controlled LAN addresses that this runner can
bind. Before running, grant Superuser permission for this debug APK in KernelSU
Manager. ADB shell root alone is not APK root authorization evidence.

Required final evidence:
  product.adapter_available=1
  queue_id=176
  queue_last=177
  queue_range=176-177
  lane_count=2
  ready_lane_mask=3
  hooks=INPUT,OUTPUT
  families=IPv4,IPv6
  input_packets>=2
  output_packets>=2
  ipv4_packets>=2
  ipv6_packets>=2
  tcp_packets>=2
  udp_packets>=2
  uid_known_packets>=2
  uid_unknown_packets>=2
  all eight case nonces echoed
  productRootNfqueueResidueClean=true
  restart_no_residue=true
EOF
}

serial="$S178_SERIAL"
run=0
controlled_host4="${S178_CONTROLLED_LAN_HOST4:-}"
controlled_host6="${S178_CONTROLLED_LAN_HOST6:-}"
base_port="${S178_BASE_PORT:-18178}"
timeout_ms="${S178_TIMEOUT_MILLIS:-5000}"
restart_no_residue="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --serial)
      serial="${2:-}"
      shift 2
      ;;
    --run)
      run=1
      shift
      ;;
    --host4)
      controlled_host4="${2:-}"
      shift 2
      ;;
    --host6)
      controlled_host6="${2:-}"
      shift 2
      ;;
    --base-port)
      base_port="${2:-}"
      shift 2
      ;;
    --timeout-ms)
      timeout_ms="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "$serial" != "$S178_SERIAL" ]]; then
  echo "SAKAMOTO-178 only accepts controlled Pixel 6a serial $S178_SERIAL; got $serial" >&2
  exit 2
fi
if [[ "$run" != 1 ]]; then
  usage >&2
  exit 2
fi
if [[ -z "$controlled_host4" || -z "$controlled_host6" ]]; then
  echo "missing --host4/--host6 or S178_CONTROLLED_LAN_HOST4/HOST6" >&2
  usage >&2
  exit 2
fi
if ! [[ "$controlled_host4" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "controlled host4 must be an IPv4 literal: $controlled_host4" >&2
  exit 2
fi
if [[ "$controlled_host6" != *:* ]]; then
  echo "controlled host6 must be an IPv6 literal: $controlled_host6" >&2
  exit 2
fi
if ! [[ "$base_port" =~ ^[0-9]+$ ]] \
    || (( base_port < 1024 || base_port > 65400 )); then
  echo "invalid base port: $base_port" >&2
  exit 2
fi
if ! [[ "$timeout_ms" =~ ^[0-9]+$ ]] || (( timeout_ms < 100 || timeout_ms > 30000 )); then
  echo "invalid timeout: $timeout_ms" >&2
  exit 2
fi

readonly TCP4_OUT_PORT=$((base_port))
readonly UDP4_OUT_PORT=$((base_port + 1))
readonly TCP6_OUT_PORT=$((base_port + 2))
readonly UDP6_OUT_PORT=$((base_port + 3))
readonly TCP4_IN_PORT=$((base_port + 4))
readonly UDP4_IN_PORT=$((base_port + 5))
readonly TCP6_IN_PORT=$((base_port + 6))
readonly UDP6_IN_PORT=$((base_port + 7))

mkdir -p "$RESULT_DIR"
exec > >(tee "$RESULT_DIR/runner.log") 2>&1

kv() {
  printf '%s=%s\n' "$1" "$2"
}

fail_closed() {
  printf 'SAKAMOTO-178-root-nfqueue-dual-stack-matrix=BLOCKED\n' >&2
  printf '%s\n' "$1" >&2
  exit 77
}

adb_target() {
  "$ADB" -s "$serial" "$@"
}

app_file() {
  local relative="$1"
  adb_target shell run-as "$PACKAGE" cat "$relative" 2>/dev/null || true
}

field_value() {
  local name="$1"
  local evidence="$2"
  awk -F= -v key="$name" '$1 == key { print $2; exit }' <<<"$evidence"
}

require_exact() {
  local name="$1"
  local expected="$2"
  local evidence="$3"
  if ! grep -Fxq "${name}=${expected}" <<<"$evidence"; then
    printf 'missing or unequal evidence: %s=%s\n' "$name" "$expected" >&2
    return 1
  fi
}

require_ge() {
  local name="$1"
  local minimum="$2"
  local evidence="$3"
  local value
  value="$(field_value "$name" "$evidence")"
  [[ "$value" =~ ^[0-9]+$ ]] || return 1
  (( value >= minimum )) || return 1
}

positive_equal_packet_counters() {
  local evidence="$1"
  local verdicts settlements returns
  verdicts="$(field_value origin_verdict_attempts "$evidence")"
  settlements="$(field_value internal_settlements "$evidence")"
  returns="$(field_value buffer_returns "$evidence")"
  [[ "$verdicts" =~ ^[0-9]+$ ]] || return 1
  [[ "$settlements" =~ ^[0-9]+$ ]] || return 1
  [[ "$returns" =~ ^[0-9]+$ ]] || return 1
  (( verdicts >= 8 )) || return 1
  (( settlements == verdicts )) || return 1
  (( returns == verdicts )) || return 1
}

start_activity() {
  adb_target shell am start -n "$ACTIVITY" "$@" >/dev/null
}

clear_previous_evidence() {
  adb_target shell run-as "$PACKAGE" rm -f \
    "$STATE_PATH" "$STATUS_PATH" "$CLEANUP_PATH" \
    "$TCP_PROBE_PATH" "$UDP_PROBE_PATH" \
    "$TCP_LISTENER_PATH" "$UDP_LISTENER_PATH" >/dev/null 2>&1 || true
}

grant_notification_permission_best_effort() {
  adb_target shell pm grant "$PACKAGE" android.permission.POST_NOTIFICATIONS >/dev/null 2>&1 || true
}

read_snapshot() {
  app_file "$STATE_PATH" | tr -d '\r'
}

wait_for_root_running() {
  local snapshot=""
  local attempt
  for ((attempt = 1; attempt <= 90; attempt++)); do
    snapshot="$(read_snapshot)"
    printf '%s\n' "$snapshot" >"$RESULT_DIR/snapshot.running.poll"
    if grep -Fxq "errorCode=root_authorization_required" <<<"$snapshot"; then
      fail_closed "KernelSU Superuser grant is missing for the installed debug APK"
    fi
    if grep -Fxq "errorCode=notification_permission_required" <<<"$snapshot"; then
      fail_closed "Android notification permission is required before RuntimeService can start"
    fi
    if grep -Fxq "state=running" <<<"$snapshot" \
        && grep -Fxq "profile=root" <<<"$snapshot" \
        && grep -Fxq "coreHealth=ok" <<<"$snapshot" \
        && grep -Fxq "adapterReadiness=root-nfqueue" <<<"$snapshot" \
        && grep -Fxq "protectionRunning=true" <<<"$snapshot"; then
      printf '%s\n' "$snapshot" >"$RESULT_DIR/snapshot.running.properties"
      return 0
    fi
    sleep 1
  done
  printf '%s\n' "$snapshot" >"$RESULT_DIR/snapshot.running.timeout.properties"
  fail_closed "Product Root runtime did not publish root-nfqueue running state"
}

wait_for_cleanup() {
  local cleanup=""
  local snapshot=""
  local attempt
  for ((attempt = 1; attempt <= 45; attempt++)); do
    cleanup="$(app_file "$CLEANUP_PATH" | tr -d '\r')"
    snapshot="$(read_snapshot)"
    printf '%s\n' "$cleanup" >"$RESULT_DIR/cleanup-status.poll"
    printf '%s\n' "$snapshot" >"$RESULT_DIR/snapshot.stopped.poll"
    if grep -Fxq "productRootNfqueueResidueClean=true" <<<"$cleanup" \
        && grep -Fxq "state=stopped" <<<"$snapshot" \
        && grep -Fxq "mayBeActive=false" <<<"$snapshot" \
        && grep -Fxq "errorCode=" <<<"$snapshot"; then
      printf '%s\n' "$cleanup" >"$RESULT_DIR/cleanup-status.properties"
      printf '%s\n' "$snapshot" >"$RESULT_DIR/snapshot.stopped.properties"
      return 0
    fi
    sleep 1
  done
  printf '%s\n' "$cleanup" >"$RESULT_DIR/cleanup-status.timeout.properties"
  fail_closed "Product Root NFQUEUE hook residue did not clean after STOP"
}

wait_local_result() {
  local path="$1"
  local expected="$2"
  local attempt
  for ((attempt = 1; attempt <= 50; attempt++)); do
    if [[ -f "$path" ]] && grep -Fxq "result=${expected}" "$path"; then
      return 0
    fi
    sleep 0.1
  done
  [[ -f "$path" ]] && cat "$path"
  return 1
}

wait_app_result() {
  local path="$1"
  local expected="$2"
  local output="$3"
  local evidence=""
  local attempt
  for ((attempt = 1; attempt <= 45; attempt++)); do
    evidence="$(app_file "$path" | tr -d '\r')"
    printf '%s\n' "$evidence" >"$output"
    if grep -Fxq "result=${expected}" <<<"$evidence"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

refresh_product_status() {
  start_activity --ez debugRefresh true
}

read_status_after_refresh() {
  local label="$1"
  local status=""
  local attempt
  refresh_product_status
  for ((attempt = 1; attempt <= 15; attempt++)); do
    status="$(app_file "$STATUS_PATH" | tr -d '\r')"
    printf '%s\n' "$status" >"$RESULT_DIR/product-status.${label}.poll"
    if grep -Fxq "product.adapter_available=1" <<<"$status"; then
      printf '%s\n' "$status" >"$RESULT_DIR/product-status.${label}.properties"
      return 0
    fi
    sleep 1
  done
  printf '%s\n' "$status" >"$RESULT_DIR/product-status.${label}.timeout.properties"
  return 1
}

matrix_status_complete() {
  local status="$1"
  grep -Fxq "product.adapter_available=1" <<<"$status" \
    && grep -Fxq "queue_id=176" <<<"$status" \
    && grep -Fxq "queue_last=177" <<<"$status" \
    && grep -Fxq "queue_range=176-177" <<<"$status" \
    && grep -Fxq "lane_count=2" <<<"$status" \
    && grep -Fxq "ready_lane_mask=3" <<<"$status" \
    && grep -Fxq "hooks=INPUT,OUTPUT" <<<"$status" \
    && grep -Fxq "families=IPv4,IPv6" <<<"$status" \
    && positive_equal_packet_counters "$status" \
    && require_ge input_packets 2 "$status" \
    && require_ge output_packets 2 "$status" \
    && require_ge ipv4_packets 2 "$status" \
    && require_ge ipv6_packets 2 "$status" \
    && require_ge tcp_packets 2 "$status" \
    && require_ge udp_packets 2 "$status" \
    && require_ge uid_known_packets 2 "$status" \
    && require_ge uid_unknown_packets 2 "$status" \
    && require_ge lane0_verdict_attempts 1 "$status" \
    && require_ge lane1_verdict_attempts 1 "$status"
}

wait_for_matrix_status() {
  local status=""
  local attempt
  for ((attempt = 1; attempt <= 30; attempt++)); do
    read_status_after_refresh "final" || true
    status="$(app_file "$STATUS_PATH" | tr -d '\r')"
    printf '%s\n' "$status" >"$RESULT_DIR/product-status.final.poll"
    if matrix_status_complete "$status"; then
      printf '%s\n' "$status" >"$RESULT_DIR/product-status.final.properties"
      return 0
    fi
    sleep 1
  done
  printf '%s\n' "$status" >"$RESULT_DIR/product-status.final.incomplete.properties"
  return 1
}

host_tcp_echo_once() {
  local family="$1"
  local host="$2"
  local port="$3"
  local nonce="$4"
  local result_file="$5"
  python3 - "$family" "$host" "$port" "$nonce" "$result_file" <<'PY'
import socket
import sys

family = socket.AF_INET6 if sys.argv[1] == "6" else socket.AF_INET
host = sys.argv[2]
port = int(sys.argv[3])
nonce = sys.argv[4].encode()
result_file = sys.argv[5]
result = "tcp_echo_failed"
remote = ""
request_bytes = 0
response_bytes = 0
try:
    with socket.socket(family, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(1)
        server.settimeout(8)
        conn, address = server.accept()
        remote = str(address)
        with conn:
            conn.settimeout(8)
            data = bytearray()
            while len(data) < len(nonce):
                chunk = conn.recv(len(nonce) - len(data))
                if not chunk:
                    break
                data.extend(chunk)
            request_bytes = len(data)
            conn.sendall(data)
            response_bytes = len(data)
            result = "tcp_echo_matched" if bytes(data) == nonce else "tcp_echo_mismatch"
except Exception as error:
    remote = error.__class__.__name__ + ":" + str(error).replace("\n", "_")
with open(result_file, "w", encoding="utf-8") as output:
    output.write(f"host={host}\n")
    output.write(f"port={port}\n")
    output.write(f"nonce={nonce.decode()}\n")
    output.write(f"result={result}\n")
    output.write(f"remote={remote}\n")
    output.write(f"requestBytes={request_bytes}\n")
    output.write(f"responseBytes={response_bytes}\n")
PY
}

host_udp_echo_once() {
  local family="$1"
  local host="$2"
  local port="$3"
  local nonce="$4"
  local result_file="$5"
  python3 - "$family" "$host" "$port" "$nonce" "$result_file" <<'PY'
import socket
import sys

family = socket.AF_INET6 if sys.argv[1] == "6" else socket.AF_INET
host = sys.argv[2]
port = int(sys.argv[3])
nonce = sys.argv[4].encode()
result_file = sys.argv[5]
result = "udp_echo_failed"
remote = ""
request_bytes = 0
response_bytes = 0
try:
    with socket.socket(family, socket.SOCK_DGRAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.settimeout(8)
        data, address = server.recvfrom(4096)
        remote = str(address)
        request_bytes = len(data)
        server.sendto(data, address)
        response_bytes = len(data)
        result = "udp_echo_matched" if data == nonce else "udp_echo_mismatch"
except Exception as error:
    remote = error.__class__.__name__ + ":" + str(error).replace("\n", "_")
with open(result_file, "w", encoding="utf-8") as output:
    output.write(f"host={host}\n")
    output.write(f"port={port}\n")
    output.write(f"nonce={nonce.decode()}\n")
    output.write(f"result={result}\n")
    output.write(f"remote={remote}\n")
    output.write(f"requestBytes={request_bytes}\n")
    output.write(f"responseBytes={response_bytes}\n")
PY
}

host_tcp_client_once() {
  local family="$1"
  local host="$2"
  local port="$3"
  local nonce="$4"
  local result_file="$5"
  python3 - "$family" "$host" "$port" "$nonce" "$result_file" <<'PY'
import socket
import sys

family = socket.AF_INET6 if sys.argv[1] == "6" else socket.AF_INET
host = sys.argv[2]
port = int(sys.argv[3])
nonce = sys.argv[4].encode()
result_file = sys.argv[5]
result = "tcp_client_failed"
request_bytes = len(nonce)
response_bytes = 0
try:
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(8)
        sock.connect((host, port))
        sock.sendall(nonce)
        data = bytearray()
        while len(data) < len(nonce):
            chunk = sock.recv(len(nonce) - len(data))
            if not chunk:
                break
            data.extend(chunk)
        response_bytes = len(data)
        result = "tcp_echo_matched" if bytes(data) == nonce else "tcp_echo_mismatch"
except Exception as error:
    result = "tcp_client_failed:" + error.__class__.__name__ + ":" + str(error).replace("\n", "_")
with open(result_file, "w", encoding="utf-8") as output:
    output.write(f"host={host}\n")
    output.write(f"port={port}\n")
    output.write(f"nonce={nonce.decode()}\n")
    output.write(f"result={result}\n")
    output.write(f"requestBytes={request_bytes}\n")
    output.write(f"responseBytes={response_bytes}\n")
PY
}

host_udp_client_once() {
  local family="$1"
  local host="$2"
  local port="$3"
  local nonce="$4"
  local result_file="$5"
  python3 - "$family" "$host" "$port" "$nonce" "$result_file" <<'PY'
import socket
import sys

family = socket.AF_INET6 if sys.argv[1] == "6" else socket.AF_INET
host = sys.argv[2]
port = int(sys.argv[3])
nonce = sys.argv[4].encode()
result_file = sys.argv[5]
result = "udp_client_failed"
request_bytes = len(nonce)
response_bytes = 0
try:
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(8)
        sock.sendto(nonce, (host, port))
        data, _ = sock.recvfrom(max(len(nonce), 1))
        response_bytes = len(data)
        result = "udp_echo_matched" if data == nonce else "udp_echo_mismatch"
except Exception as error:
    result = "udp_client_failed:" + error.__class__.__name__ + ":" + str(error).replace("\n", "_")
with open(result_file, "w", encoding="utf-8") as output:
    output.write(f"host={host}\n")
    output.write(f"port={port}\n")
    output.write(f"nonce={nonce.decode()}\n")
    output.write(f"result={result}\n")
    output.write(f"requestBytes={request_bytes}\n")
    output.write(f"responseBytes={response_bytes}\n")
PY
}

run_output_tcp_case() {
  local family="$1"
  local host="$2"
  local port="$3"
  local label="$4"
  local nonce="s178-${label}-${RUN_ID}"
  local host_result="$RESULT_DIR/host-${label}.properties"
  rm -f "$host_result"
  host_tcp_echo_once "$family" "$host" "$port" "$nonce" "$host_result" &
  local server_pid=$!
  sleep 0.3
  adb_target shell run-as "$PACKAGE" rm -f "$TCP_PROBE_PATH" >/dev/null 2>&1 || true
  start_activity --ez debugTraffic true \
    --es debugTrafficHost "$host" \
    --ei debugTrafficPort "$port" \
    --es debugTrafficNonce "$nonce" \
    --ei debugTrafficTimeoutMillis "$timeout_ms"
  if ! wait_app_result "$TCP_PROBE_PATH" tcp_echo_matched \
      "$RESULT_DIR/device-${label}.properties"; then
    kill "$server_pid" >/dev/null 2>&1 || true
    fail_closed "OUTPUT ${label} did not echo through the installed app"
  fi
  wait "$server_pid" || true
  wait_local_result "$host_result" tcp_echo_matched \
    || fail_closed "host did not observe OUTPUT ${label} nonce"
  read_status_after_refresh "$label" || true
}

run_output_udp_case() {
  local family="$1"
  local host="$2"
  local port="$3"
  local label="$4"
  local nonce="s178-${label}-${RUN_ID}"
  local host_result="$RESULT_DIR/host-${label}.properties"
  rm -f "$host_result"
  host_udp_echo_once "$family" "$host" "$port" "$nonce" "$host_result" &
  local server_pid=$!
  sleep 0.3
  adb_target shell run-as "$PACKAGE" rm -f "$UDP_PROBE_PATH" >/dev/null 2>&1 || true
  start_activity --ez debugUdpTraffic true \
    --es debugUdpHost "$host" \
    --ei debugUdpPort "$port" \
    --es debugUdpNonce "$nonce" \
    --ez debugUdpExpectReply true \
    --ez debugTrafficBindToVpn false \
    --ei debugUdpTimeoutMillis "$timeout_ms"
  if ! wait_app_result "$UDP_PROBE_PATH" udp_echo_matched \
      "$RESULT_DIR/device-${label}.properties"; then
    kill "$server_pid" >/dev/null 2>&1 || true
    fail_closed "OUTPUT ${label} did not echo through the installed app"
  fi
  wait "$server_pid" || true
  wait_local_result "$host_result" udp_echo_matched \
    || fail_closed "host did not observe OUTPUT ${label} nonce"
  read_status_after_refresh "$label" || true
}

run_input_tcp_case() {
  local family="$1"
  local host="$2"
  local port="$3"
  local label="$4"
  local listen_host="0.0.0.0"
  if [[ "$family" == "6" ]]; then
    listen_host="::"
  fi
  local nonce="s178-${label}-${RUN_ID}"
  local host_result="$RESULT_DIR/host-${label}.properties"
  adb_target shell run-as "$PACKAGE" rm -f "$TCP_LISTENER_PATH" >/dev/null 2>&1 || true
  start_activity --ez debugListen true \
    --es debugListenHost "$listen_host" \
    --ei debugListenPort "$port" \
    --es debugListenNonce "$nonce" \
    --ei debugListenTimeoutMillis "$timeout_ms"
  sleep 0.5
  host_tcp_client_once "$family" "$host" "$port" "$nonce" "$host_result"
  wait_local_result "$host_result" tcp_echo_matched \
    || fail_closed "host did not receive INPUT ${label} listener echo"
  wait_app_result "$TCP_LISTENER_PATH" tcp_echo_matched \
    "$RESULT_DIR/device-${label}.properties" \
    || fail_closed "installed app listener did not record INPUT ${label}"
  read_status_after_refresh "$label" || true
}

run_input_udp_case() {
  local family="$1"
  local host="$2"
  local port="$3"
  local label="$4"
  local listen_host="0.0.0.0"
  if [[ "$family" == "6" ]]; then
    listen_host="::"
  fi
  local nonce="s178-${label}-${RUN_ID}"
  local host_result="$RESULT_DIR/host-${label}.properties"
  adb_target shell run-as "$PACKAGE" rm -f "$UDP_LISTENER_PATH" >/dev/null 2>&1 || true
  start_activity --ez debugUdpListen true \
    --es debugUdpListenHost "$listen_host" \
    --ei debugUdpListenPort "$port" \
    --es debugUdpListenNonce "$nonce" \
    --ei debugUdpListenTimeoutMillis "$timeout_ms"
  sleep 0.5
  host_udp_client_once "$family" "$host" "$port" "$nonce" "$host_result"
  wait_local_result "$host_result" udp_echo_matched \
    || fail_closed "host did not receive INPUT ${label} listener echo"
  wait_app_result "$UDP_LISTENER_PATH" udp_echo_matched \
    "$RESULT_DIR/device-${label}.properties" \
    || fail_closed "installed app UDP listener did not record INPUT ${label}"
  read_status_after_refresh "$label" || true
}

infer_device_route_src() {
  local family="$1"
  local target="$2"
  local route
  if [[ "$family" == "6" ]]; then
    route="$(adb_target shell ip -6 route get "$target" 2>/dev/null | tr -d '\r')"
  else
    route="$(adb_target shell ip -4 route get "$target" 2>/dev/null | tr -d '\r')"
  fi
  awk '{
    for (field = 1; field <= NF; field++) {
      if ($field == "src") {
        print $(field + 1)
        exit
      }
    }
  }' <<<"$route"
}

"$ADB" devices | tr -d '\r' | grep -Eq "^${serial}[[:space:]]+device$" \
  || fail_closed "controlled Pixel 6a is not connected through ./dev/adb"

adb_target shell pm path "$PACKAGE" >/dev/null 2>&1 \
  || fail_closed "installed debug APK is missing: $PACKAGE"

device_host4="$(infer_device_route_src 4 "$controlled_host4")"
device_host6="$(infer_device_route_src 6 "$controlled_host6")"
if [[ -z "$device_host4" || -z "$device_host6" ]]; then
  fail_closed "could not infer Pixel controlled LAN IPv4/IPv6 source addresses"
fi

kv test_id SAKAMOTO-178-root-nfqueue-dual-stack-matrix
kv device_serial "$serial"
kv package "$PACKAGE"
kv activity "$ACTIVITY"
kv controlled_lan_host4 "$controlled_host4"
kv controlled_lan_host6 "$controlled_host6"
kv device_lan_host4 "$device_host4"
kv device_lan_host6 "$device_host6"
kv base_port "$base_port"
kv tcp4_output_port "$TCP4_OUT_PORT"
kv udp4_output_port "$UDP4_OUT_PORT"
kv tcp6_output_port "$TCP6_OUT_PORT"
kv udp6_output_port "$UDP6_OUT_PORT"
kv tcp4_input_port "$TCP4_IN_PORT"
kv udp4_input_port "$UDP4_IN_PORT"
kv tcp6_input_port "$TCP6_IN_PORT"
kv udp6_input_port "$UDP6_IN_PORT"

clear_previous_evidence
grant_notification_permission_best_effort

start_activity --ez runtimeStart true --es runtimeProfile root
wait_for_root_running
read_status_after_refresh start || true

run_output_tcp_case 4 "$controlled_host4" "$TCP4_OUT_PORT" tcp4-output
run_output_udp_case 4 "$controlled_host4" "$UDP4_OUT_PORT" udp4-output
run_output_tcp_case 6 "$controlled_host6" "$TCP6_OUT_PORT" tcp6-output
run_output_udp_case 6 "$controlled_host6" "$UDP6_OUT_PORT" udp6-output

run_input_tcp_case 4 "$device_host4" "$TCP4_IN_PORT" tcp4-input
run_input_udp_case 4 "$device_host4" "$UDP4_IN_PORT" udp4-input
run_input_tcp_case 6 "$device_host6" "$TCP6_IN_PORT" tcp6-input
run_input_udp_case 6 "$device_host6" "$UDP6_IN_PORT" udp6-input

if ! wait_for_matrix_status; then
  start_activity --ez runtimeStop true
  wait_for_cleanup || true
  fail_closed "Product S178 status did not cover dual-stack TCP/UDP INPUT/OUTPUT"
fi

status="$(app_file "$STATUS_PATH" | tr -d '\r')"
printf '%s\n' "$status" >"$RESULT_DIR/product-status.final.properties"
matrix_status_complete "$status" \
  || fail_closed "Product S178 final status lost required matrix evidence"

start_activity --ez runtimeStop true
wait_for_cleanup

clear_previous_evidence
start_activity --ez runtimeStart true --es runtimeProfile root
wait_for_root_running
start_activity --ez runtimeStop true
wait_for_cleanup
restart_no_residue="true"
kv restart_no_residue "$restart_no_residue"

cleanup="$(app_file "$CLEANUP_PATH" | tr -d '\r')"
snapshot="$(read_snapshot)"
printf '%s\n' "$cleanup" >"$RESULT_DIR/cleanup-status.final.properties"
printf '%s\n' "$snapshot" >"$RESULT_DIR/snapshot.final.properties"

require_exact product.adapter_available 1 "$status"
require_exact queue_id 176 "$status"
require_exact queue_last 177 "$status"
require_exact queue_range 176-177 "$status"
require_exact lane_count 2 "$status"
require_exact ready_lane_mask 3 "$status"
require_exact hooks INPUT,OUTPUT "$status"
require_exact families IPv4,IPv6 "$status"
positive_equal_packet_counters "$status"
require_ge input_packets 2 "$status"
require_ge output_packets 2 "$status"
require_ge ipv4_packets 2 "$status"
require_ge ipv6_packets 2 "$status"
require_ge tcp_packets 2 "$status"
require_ge udp_packets 2 "$status"
require_ge uid_known_packets 2 "$status"
require_ge uid_unknown_packets 2 "$status"
require_ge lane0_verdict_attempts 1 "$status"
require_ge lane1_verdict_attempts 1 "$status"
require_exact productRootNfqueueResidueClean true "$cleanup"
require_exact state stopped "$snapshot"
require_exact mayBeActive false "$snapshot"
require_exact errorCode "" "$snapshot"
[[ "$restart_no_residue" == "true" ]] \
  || fail_closed "fresh restart did not prove no residue"

printf 'SAKAMOTO-178-root-nfqueue-dual-stack-matrix=PASS\n'
