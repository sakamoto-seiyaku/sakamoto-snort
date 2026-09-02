#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-178 Root NFQUEUE dual-stack TCP/UDP INPUT/OUTPUT real-device
# acceptance entry point. PASS means the installed Product Root path forwards
# nonce-bearing controlled LAN traffic through the VPP-native NFQUEUE adapter
# and records the expected family/protocol/direction counters.

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export ADB="${repo_root}/dev/adb"

readonly S178_SERIAL="28201JEGR0XPAJ"
readonly PACKAGE="${PACKAGE:-com.sakamoto.snort.androidruntime}"
readonly ACTIVITY="${ACTIVITY:-${PACKAGE}/.DebugControlActivity}"
readonly RESULTS_ROOT="${RESULTS_ROOT:-${repo_root}/build-output/s178-root-nfqueue-matrix}"
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
  tests/device/s178-root-nfqueue-matrix-product.sh --run \
    --host-v4 <lan-ipv4> --host-v6 <lan-ipv6> \
    --device-v4 <pixel-ipv4> --device-v6 <pixel-ipv6>

Runs SAKAMOTO-178 on the controlled Pixel 6a.

Required:
  --run
  --host-v4       Controlled LAN IPv4 address on this host.
  --host-v6       Controlled LAN IPv6 address on this host.
  --device-v4     Pixel LAN IPv4 address reachable from this host.
  --device-v6     Pixel LAN IPv6 address reachable from this host.

Optional:
  --serial 28201JEGR0XPAJ
  --port-base / S178_PORT_BASE
  --timeout-ms / S178_TIMEOUT_MILLIS

Evidence:
  Four device OUTPUT cases: IPv4 TCP, IPv4 UDP, IPv6 TCP, IPv6 UDP.
  Four LAN-host to device INPUT cases: IPv4 TCP, IPv4 UDP, IPv6 TCP, IPv6 UDP.
  Each case records nonce, request/response bytes, product status deltas, and
  final cleanup/fresh-restart proof.
EOF
}

serial="$S178_SERIAL"
run=0
host_v4="${S178_HOST_V4:-}"
host_v6="${S178_HOST_V6:-}"
device_v4="${S178_DEVICE_V4:-}"
device_v6="${S178_DEVICE_V6:-}"
port_base="${S178_PORT_BASE:-18178}"
timeout_ms="${S178_TIMEOUT_MILLIS:-5000}"
runtime_started=0
host_pids=()

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
    --host-v4)
      host_v4="${2:-}"
      shift 2
      ;;
    --host-v6)
      host_v6="${2:-}"
      shift 2
      ;;
    --device-v4)
      device_v4="${2:-}"
      shift 2
      ;;
    --device-v6)
      device_v6="${2:-}"
      shift 2
      ;;
    --port-base)
      port_base="${2:-}"
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

mkdir -p "$RESULT_DIR"
exec > >(tee "$RESULT_DIR/runner.log") 2>&1

kv() {
  printf '%s=%s\n' "$1" "$2"
}

invalid_env() {
  printf 'SAKAMOTO-178-root-nfqueue-matrix=INVALID\n' >&2
  printf '%s\n' "$1" >&2
  exit 77
}

fail_product() {
  printf 'SAKAMOTO-178-root-nfqueue-matrix=FAIL\n' >&2
  printf '%s\n' "$1" >&2
  stop_runtime_best_effort
  exit 1
}

adb_target() {
  "$ADB" -s "$serial" "$@"
}

app_file() {
  local relative="$1"
  adb_target shell run-as "$PACKAGE" cat "$relative" 2>/dev/null || true
}

clear_app_file() {
  local relative="$1"
  adb_target shell run-as "$PACKAGE" rm -f "$relative" >/dev/null 2>&1 || true
}

start_activity() {
  adb_target shell am start -n "$ACTIVITY" "$@" >/dev/null
}

cleanup_host_jobs() {
  local pid
  for pid in "${host_pids[@]}"; do
    kill "$pid" >/dev/null 2>&1 || true
  done
}

stop_runtime_best_effort() {
  if [[ "$runtime_started" == 1 ]]; then
    start_activity --ez runtimeStop true >/dev/null 2>&1 || true
    wait_for_cleanup_quiet || true
    runtime_started=0
  fi
  cleanup_host_jobs
}

trap stop_runtime_best_effort EXIT

field_value_file() {
  local key="$1"
  local file="$2"
  awk -F= -v key="$key" '$1 == key { print substr($0, length(key) + 2); found=1 } END { if (!found) exit 1 }' "$file"
}

field_ge_file() {
  local key="$1"
  local minimum="$2"
  local file="$3"
  local value
  value="$(field_value_file "$key" "$file" 2>/dev/null || true)"
  [[ "$value" =~ ^[0-9]+$ ]] || return 1
  (( value >= minimum ))
}

delta_ge() {
  local label="$1"
  local key="$2"
  local minimum="$3"
  local before="$4"
  local after="$5"
  local before_value after_value delta
  before_value="$(field_value_file "$key" "$before" 2>/dev/null || echo 0)"
  after_value="$(field_value_file "$key" "$after" 2>/dev/null || echo 0)"
  [[ "$before_value" =~ ^[0-9]+$ ]] || before_value=0
  [[ "$after_value" =~ ^[0-9]+$ ]] || after_value=0
  delta=$((after_value - before_value))
  kv "${label}.${key}Delta" "$delta"
  (( delta >= minimum ))
}

wait_app_file_result() {
  local relative="$1"
  local expected="$2"
  local nonce_key="$3"
  local nonce="$4"
  local output="$5"
  local evidence=""
  local attempt
  for ((attempt = 1; attempt <= 40; attempt++)); do
    evidence="$(app_file "$relative" | tr -d '\r')"
    printf '%s\n' "$evidence" >"$output"
    if grep -Fxq "result=${expected}" <<<"$evidence" \
        && grep -Fxq "${nonce_key}=${nonce}" <<<"$evidence"; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

wait_product_status() {
  local output="$1"
  local status=""
  local attempt
  for ((attempt = 1; attempt <= 40; attempt++)); do
    status="$(app_file "$STATUS_PATH" | tr -d '\r')"
    printf '%s\n' "$status" >"$output"
    if grep -Fxq "product.adapter_available=1" <<<"$status" \
        && grep -Fxq "hooks=INPUT,OUTPUT" <<<"$status" \
        && grep -Fxq "families=IPv4,IPv6" <<<"$status"; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

wait_for_root_running() {
  local snapshot=""
  local attempt
  for ((attempt = 1; attempt <= 90; attempt++)); do
    snapshot="$(app_file "$STATE_PATH" | tr -d '\r')"
    printf '%s\n' "$snapshot" >"$RESULT_DIR/snapshot.running.poll"
    if grep -Fxq "errorCode=root_authorization_required" <<<"$snapshot"; then
      invalid_env "KernelSU Superuser grant is missing for the installed debug APK"
    fi
    if grep -Fxq "state=running" <<<"$snapshot" \
        && grep -Fxq "profile=root" <<<"$snapshot" \
        && grep -Fxq "adapterReadiness=root-nfqueue" <<<"$snapshot"; then
      printf '%s\n' "$snapshot" >"$RESULT_DIR/snapshot.running.properties"
      return 0
    fi
    sleep 1
  done
  printf '%s\n' "$snapshot" >"$RESULT_DIR/snapshot.running.timeout.properties"
  fail_product "Product Root runtime did not publish root-nfqueue running state"
}

wait_for_cleanup_quiet() {
  local cleanup=""
  local snapshot=""
  local attempt
  for ((attempt = 1; attempt <= 45; attempt++)); do
    cleanup="$(app_file "$CLEANUP_PATH" | tr -d '\r')"
    snapshot="$(app_file "$STATE_PATH" | tr -d '\r')"
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
  return 1
}

wait_for_cleanup() {
  wait_for_cleanup_quiet || fail_product "Product Root NFQUEUE hook residue did not clean after STOP"
}

start_root_runtime() {
  start_activity --ez runtimeStart true --es runtimeProfile root
  runtime_started=1
  wait_for_root_running
  wait_product_status "$RESULT_DIR/product-status.running.properties" \
    || fail_product "Product Root status did not expose S178 matrix fields"
}

stop_root_runtime() {
  start_activity --ez runtimeStop true
  wait_for_cleanup
  runtime_started=0
}

start_host_echo_server() {
  local protocol="$1"
  local bind_host="$2"
  local port="$3"
  local nonce="$4"
  local ready="$5"
  local log="$6"
  python3 - "$protocol" "$bind_host" "$port" "$nonce" "$ready" >"$log" 2>&1 <<'PY' &
import socket
import sys

protocol, host, port_text, nonce, ready = sys.argv[1:6]
port = int(port_text)
payload = nonce.encode("utf-8")
family = socket.AF_INET6 if ":" in host else socket.AF_INET

if protocol == "tcp":
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(1)
    open(ready, "w", encoding="utf-8").write("ready\n")
    conn, addr = sock.accept()
    with conn:
        conn.settimeout(5.0)
        data = b""
        while len(data) < len(payload):
            chunk = conn.recv(len(payload) - len(data))
            if not chunk:
                break
            data += chunk
        conn.sendall(data)
    sock.close()
else:
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.settimeout(5.0)
    open(ready, "w", encoding="utf-8").write("ready\n")
    data, addr = sock.recvfrom(max(len(payload), 1))
    sock.sendto(data, addr)
    sock.close()

result = "server_echo_matched" if data == payload else "server_echo_mismatch"
print(f"result={result}")
print(f"protocol={protocol}")
print(f"host={host}")
print(f"port={port}")
print(f"nonce={nonce}")
print(f"requestBytes={len(data)}")
print(f"responseBytes={len(data)}")
PY
  local pid=$!
  host_pids+=("$pid")
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    [[ -s "$ready" ]] && return 0
    sleep 0.2
  done
  return 1
}

host_echo_client() {
  local protocol="$1"
  local host="$2"
  local port="$3"
  local nonce="$4"
  local log="$5"
  python3 - "$protocol" "$host" "$port" "$nonce" >"$log" 2>&1 <<'PY'
import socket
import sys

protocol, host, port_text, nonce = sys.argv[1:5]
port = int(port_text)
payload = nonce.encode("utf-8")
family = socket.AF_INET6 if ":" in host else socket.AF_INET

if protocol == "tcp":
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    sock.connect((host, port))
    sock.sendall(payload)
    data = b""
    while len(data) < len(payload):
        chunk = sock.recv(len(payload) - len(data))
        if not chunk:
            break
        data += chunk
    sock.close()
else:
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(5.0)
    sock.sendto(payload, (host, port))
    data, _ = sock.recvfrom(max(len(payload), 1))
    sock.close()

result = "client_echo_matched" if data == payload else "client_echo_mismatch"
print(f"result={result}")
print(f"protocol={protocol}")
print(f"host={host}")
print(f"port={port}")
print(f"nonce={nonce}")
print(f"requestBytes={len(payload)}")
print(f"responseBytes={len(data)}")
PY
}

wait_server_exit() {
  local pid="$1"
  local log="$2"
  if ! wait "$pid"; then
    cat "$log" >&2 || true
    return 1
  fi
  grep -Fxq "result=server_echo_matched" "$log"
}

run_output_case() {
  local label="$1"
  local family="$2"
  local protocol="$3"
  local host="$4"
  local port="$5"
  local source_port="$6"
  local nonce="s178-${label}-${RUN_ID}"
  local before="$RESULT_DIR/${label}.status.before.properties"
  local after="$RESULT_DIR/${label}.status.after.properties"
  local ready="$RESULT_DIR/${label}.server.ready"
  local server_log="$RESULT_DIR/${label}.server.properties"
  local probe_file probe_path expected_result family_key protocol_key

  kv "${label}.direction" "output"
  kv "${label}.family" "$family"
  kv "${label}.protocol" "$protocol"
  kv "${label}.nonce" "$nonce"
  wait_product_status "$before" || fail_product "${label}: missing status before probe"
  start_host_echo_server "$protocol" "$host" "$port" "$nonce" "$ready" "$server_log" \
    || fail_product "${label}: host echo server did not become ready"
  local pid="${host_pids[-1]}"

  if [[ "$protocol" == "tcp" ]]; then
    probe_path="$TCP_PROBE_PATH"
    probe_file="$RESULT_DIR/${label}.tcp-probe.properties"
    expected_result="tcp_echo_matched"
    clear_app_file "$TCP_PROBE_PATH"
    start_activity --ez debugTraffic true \
      --es debugTrafficHost "$host" \
      --ei debugTrafficPort "$port" \
      --ei debugTrafficSourcePort "$source_port" \
      --es debugTrafficNonce "$nonce" \
      --ei debugTrafficTimeoutMillis "$timeout_ms"
  else
    probe_path="$UDP_PROBE_PATH"
    probe_file="$RESULT_DIR/${label}.udp-probe.properties"
    expected_result="udp_echo_matched"
    clear_app_file "$UDP_PROBE_PATH"
    start_activity --ez debugUdpTraffic true \
      --es debugUdpHost "$host" \
      --ei debugUdpPort "$port" \
      --ei debugUdpSourcePort "$source_port" \
      --es debugUdpNonce "$nonce" \
      --ez debugUdpExpectReply true \
      --ei debugUdpTimeoutMillis "$timeout_ms" \
      --ez debugTrafficBindToVpn false
  fi

  wait_app_file_result "$probe_path" "$expected_result" "nonce" "$nonce" "$probe_file" \
    || fail_product "${label}: device OUTPUT echo did not match"
  wait_server_exit "$pid" "$server_log" \
    || fail_product "${label}: host echo server did not observe matching nonce"
  wait_product_status "$after" || fail_product "${label}: missing status after probe"

  family_key=$([[ "$family" == "ipv4" ]] && echo "ipv4_packets" || echo "ipv6_packets")
  protocol_key=$([[ "$protocol" == "tcp" ]] && echo "tcp_packets" || echo "udp_packets")
  delta_ge "$label" output_packets 1 "$before" "$after" \
    || fail_product "${label}: Root status did not record OUTPUT traffic"
  delta_ge "$label" "$family_key" 1 "$before" "$after" \
    || fail_product "${label}: Root status did not record ${family}"
  delta_ge "$label" "$protocol_key" 1 "$before" "$after" \
    || fail_product "${label}: Root status did not record ${protocol}"
  delta_ge "$label" uid_known_packets 1 "$before" "$after" \
    || fail_product "${label}: OUTPUT did not record complete app UID"
}

run_input_case() {
  local label="$1"
  local family="$2"
  local protocol="$3"
  local device_host="$4"
  local port="$5"
  local listen_host="0.0.0.0"
  if [[ "$family" == "ipv6" ]]; then
    listen_host="::"
  fi
  local nonce="s178-${label}-${RUN_ID}"
  local before="$RESULT_DIR/${label}.status.before.properties"
  local after="$RESULT_DIR/${label}.status.after.properties"
  local listener_file client_log family_key protocol_key

  kv "${label}.direction" "input"
  kv "${label}.family" "$family"
  kv "${label}.protocol" "$protocol"
  kv "${label}.nonce" "$nonce"
  wait_product_status "$before" || fail_product "${label}: missing status before listener"
  if [[ "$protocol" == "tcp" ]]; then
    listener_file="$RESULT_DIR/${label}.tcp-listener.properties"
    client_log="$RESULT_DIR/${label}.client.properties"
    clear_app_file "$TCP_LISTENER_PATH"
    start_activity --ez debugListen true \
      --es debugListenHost "$listen_host" \
      --ei debugListenPort "$port" \
      --es debugListenNonce "$nonce" \
      --ei debugListenTimeoutMillis "$timeout_ms"
  else
    listener_file="$RESULT_DIR/${label}.udp-listener.properties"
    client_log="$RESULT_DIR/${label}.client.properties"
    clear_app_file "$UDP_LISTENER_PATH"
    start_activity --ez debugUdpListen true \
      --es debugUdpListenHost "$listen_host" \
      --ei debugUdpListenPort "$port" \
      --es debugUdpListenNonce "$nonce" \
      --ei debugUdpListenTimeoutMillis "$timeout_ms"
  fi
  sleep 0.5
  host_echo_client "$protocol" "$device_host" "$port" "$nonce" "$client_log" \
    || fail_product "${label}: host INPUT client failed"
  grep -Fxq "result=client_echo_matched" "$client_log" \
    || fail_product "${label}: host INPUT client did not receive matching echo"
  if [[ "$protocol" == "tcp" ]]; then
    wait_app_file_result "$TCP_LISTENER_PATH" "tcp_echo_matched" "expectedNonce" \
      "$nonce" "$listener_file" || fail_product "${label}: TCP listener did not match"
  else
    wait_app_file_result "$UDP_LISTENER_PATH" "udp_echo_matched" "expectedNonce" \
      "$nonce" "$listener_file" || fail_product "${label}: UDP listener did not match"
  fi
  wait_product_status "$after" || fail_product "${label}: missing status after input"

  family_key=$([[ "$family" == "ipv4" ]] && echo "ipv4_packets" || echo "ipv6_packets")
  protocol_key=$([[ "$protocol" == "tcp" ]] && echo "tcp_packets" || echo "udp_packets")
  delta_ge "$label" input_packets 1 "$before" "$after" \
    || fail_product "${label}: Root status did not record INPUT traffic"
  delta_ge "$label" "$family_key" 1 "$before" "$after" \
    || fail_product "${label}: Root status did not record ${family}"
  delta_ge "$label" "$protocol_key" 1 "$before" "$after" \
    || fail_product "${label}: Root status did not record ${protocol}"
}

require_final_matrix_status() {
  local status="$1"
  for key in output_packets input_packets ipv4_packets ipv6_packets tcp_packets \
      udp_packets uid_known_packets origin_verdict_attempts internal_settlements \
      buffer_returns; do
    field_ge_file "$key" 1 "$status" || fail_product "final status missing positive $key"
  done
  grep -Fxq "hooks=INPUT,OUTPUT" "$status" \
    || fail_product "final status missing INPUT/OUTPUT hook scope"
  grep -Fxq "families=IPv4,IPv6" "$status" \
    || fail_product "final status missing IPv4/IPv6 family scope"
}

if [[ "$serial" != "$S178_SERIAL" ]]; then
  invalid_env "SAKAMOTO-178 only accepts controlled Pixel 6a serial $S178_SERIAL; got $serial"
fi
if [[ "$run" != 1 ]]; then
  usage >&2
  exit 2
fi
for required in host_v4 host_v6 device_v4 device_v6; do
  if [[ -z "${!required}" ]]; then
    invalid_env "missing required --${required/_/-}"
  fi
done
if ! [[ "$port_base" =~ ^[0-9]+$ ]] || (( port_base < 1024 || port_base > 65000 )); then
  invalid_env "invalid --port-base: $port_base"
fi
if ! [[ "$timeout_ms" =~ ^[0-9]+$ ]] || (( timeout_ms < 100 || timeout_ms > 30000 )); then
  invalid_env "invalid --timeout-ms: $timeout_ms"
fi

"$ADB" devices | tr -d '\r' | grep -Eq "^${serial}[[:space:]]+device$" \
  || invalid_env "controlled Pixel 6a is not connected through ./dev/adb"
adb_target shell pm path "$PACKAGE" >/dev/null 2>&1 \
  || invalid_env "installed debug APK is missing: $PACKAGE"

kv test_id SAKAMOTO-178-root-nfqueue-matrix
kv device_serial "$serial"
kv package "$PACKAGE"
kv host_v4 "$host_v4"
kv host_v6 "$host_v6"
kv device_v4 "$device_v4"
kv device_v6 "$device_v6"
kv port_base "$port_base"
kv timeout_ms "$timeout_ms"

clear_app_file "$STATE_PATH"
clear_app_file "$STATUS_PATH"
clear_app_file "$CLEANUP_PATH"
clear_app_file "$TCP_PROBE_PATH"
clear_app_file "$UDP_PROBE_PATH"
clear_app_file "$TCP_LISTENER_PATH"
clear_app_file "$UDP_LISTENER_PATH"
adb_target shell pm grant "$PACKAGE" android.permission.POST_NOTIFICATIONS >/dev/null 2>&1 || true

start_root_runtime

run_output_case ipv4_tcp_output ipv4 tcp "$host_v4" "$((port_base + 0))" 22100
run_output_case ipv4_udp_output ipv4 udp "$host_v4" "$((port_base + 1))" 22101
run_output_case ipv6_tcp_output ipv6 tcp "$host_v6" "$((port_base + 2))" 22102
run_output_case ipv6_udp_output ipv6 udp "$host_v6" "$((port_base + 3))" 22103
run_input_case ipv4_tcp_input ipv4 tcp "$device_v4" "$((port_base + 4))"
run_input_case ipv4_udp_input ipv4 udp "$device_v4" "$((port_base + 5))"
run_input_case ipv6_tcp_input ipv6 tcp "$device_v6" "$((port_base + 6))"
run_input_case ipv6_udp_input ipv6 udp "$device_v6" "$((port_base + 7))"

wait_product_status "$RESULT_DIR/product-status.matrix.properties" \
  || fail_product "missing final matrix product status"
require_final_matrix_status "$RESULT_DIR/product-status.matrix.properties"

stop_root_runtime

start_root_runtime
wait_product_status "$RESULT_DIR/product-status.fresh-restart.properties" \
  || fail_product "fresh restart did not publish Product status"
stop_root_runtime

printf 'SAKAMOTO-178-root-nfqueue-matrix=PASS\n'
