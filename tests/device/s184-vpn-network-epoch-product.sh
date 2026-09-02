#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-184-vpn-network-epoch real-device acceptance entry point.
#
# PASS means the installed debug APK, not shell nc, exercises all four VPN
# Direct Egress cells against controlled LAN endpoints, then a live TCP6 flow
# is present when Wi-Fi is disabled. The old flow must not transparently
# migrate/reconnect. After Wi-Fi is re-enabled, a fresh runtime generation
# creates a fresh underlay snapshot/socket handoff and a new TCP6 flow succeeds.

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export ADB="${repo_root}/dev/adb"

readonly S184_SERIAL="28201JEGR0XPAJ"
readonly PACKAGE="${PACKAGE:-com.sakamoto.snort.androidruntime}"
readonly ACTIVITY="${ACTIVITY:-${PACKAGE}/.DebugControlActivity}"
readonly RESULTS_ROOT="${RESULTS_ROOT:-${repo_root}/build-output/s184-vpn-network-epoch}"
readonly RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
readonly RESULT_DIR="${RESULT_DIR:-${RESULTS_ROOT}/${RUN_ID}}"

readonly STATE_PATH="files/runtime-state/snapshot.properties"
readonly STATUS_PATH="files/product-state/s184-vpn-network-epoch.properties"
readonly S180_STATUS_PATH="files/product-state/s180-vpn-udp4-direct-egress.properties"
readonly S181_STATUS_PATH="files/product-state/s181-vpn-tcp4-direct-egress.properties"
readonly S182_STATUS_PATH="files/product-state/s182-vpn-udp6-direct-egress.properties"
readonly S183_STATUS_PATH="files/product-state/s183-vpn-tcp6-direct-egress.properties"
readonly TCP_PROBE_PATH="files/debug/traffic-probe.properties"
readonly UDP_PROBE_PATH="files/debug/udp-traffic-probe.properties"
readonly RUNTIME_LOG_PATH="files/logs/runtime-service.log"

usage() {
  cat <<'EOF'
Usage:
  tests/device/s184-vpn-network-epoch-product.sh --run \
    --host4 <controlled-lan-ipv4> --host6 <controlled-lan-ipv6>

Required:
  --run
  --host4 / S184_CONTROLLED_LAN_HOST4
  --host6 / S184_CONTROLLED_LAN_HOST6

Optional:
  --serial 28201JEGR0XPAJ
  --udp4-port / S184_UDP4_PORT       default 18184
  --tcp4-port / S184_TCP4_PORT       default 18185
  --udp6-port / S184_UDP6_PORT       default 18186
  --tcp6-port / S184_TCP6_PORT       default 18187
  --old-tcp6-port / S184_OLD_TCP6_PORT default 18188
  --timeout-ms / S184_TIMEOUT_MILLIS default 5000

The script disables and re-enables Wi-Fi on the controlled device and restores
Wi-Fi in EXIT cleanup. Use only with a USB ADB connection to the controlled
Pixel 6a.

Required final evidence:
  installed_app_udp4_source true
  installed_app_tcp4_source true
  installed_app_udp6_source true
  installed_app_tcp6_source true
  old_tcp6_active_flow_observed true
  old_tcp6_not_migrated true
  fresh_epoch_after_wifi_restore true
  new_flow_after_wifi_restore true
  final_residue_clean true
EOF
}

serial="$S184_SERIAL"
run=0
host4="${S184_CONTROLLED_LAN_HOST4:-}"
host6="${S184_CONTROLLED_LAN_HOST6:-}"
udp4_port="${S184_UDP4_PORT:-18184}"
tcp4_port="${S184_TCP4_PORT:-18185}"
udp6_port="${S184_UDP6_PORT:-18186}"
tcp6_port="${S184_TCP6_PORT:-18187}"
old_tcp6_port="${S184_OLD_TCP6_PORT:-18188}"
timeout_ms="${S184_TIMEOUT_MILLIS:-5000}"

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
      host4="${2:-}"
      shift 2
      ;;
    --host6)
      host6="${2:-}"
      shift 2
      ;;
    --udp4-port)
      udp4_port="${2:-}"
      shift 2
      ;;
    --tcp4-port)
      tcp4_port="${2:-}"
      shift 2
      ;;
    --udp6-port)
      udp6_port="${2:-}"
      shift 2
      ;;
    --tcp6-port)
      tcp6_port="${2:-}"
      shift 2
      ;;
    --old-tcp6-port)
      old_tcp6_port="${2:-}"
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

if [[ "$serial" != "$S184_SERIAL" ]]; then
  echo "SAKAMOTO-184 only accepts controlled Pixel 6a serial $S184_SERIAL; got $serial" >&2
  exit 2
fi
if [[ "$run" != 1 ]]; then
  usage >&2
  exit 2
fi
if [[ -z "$host4" || -z "$host6" ]]; then
  echo "missing --host4/--host6 or S184_CONTROLLED_LAN_HOST4/6" >&2
  usage >&2
  exit 2
fi
if ! [[ "$host4" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "controlled IPv4 host must be an IPv4 literal: $host4" >&2
  exit 2
fi
python3 - "$host6" <<'PY'
import ipaddress
import sys

try:
    address = ipaddress.ip_address(sys.argv[1])
except ValueError:
    raise SystemExit("controlled IPv6 host must be an IPv6 literal")
if address.version != 6:
    raise SystemExit("controlled IPv6 host must be an IPv6 literal")
if getattr(address, "ipv4_mapped", None) is not None:
    raise SystemExit("controlled IPv6 host must not be IPv4-mapped")
if address.is_loopback or address.is_unspecified or address.is_global:
    raise SystemExit("controlled IPv6 host must be reachable LAN, not loopback/public")
PY
for value in "$udp4_port" "$tcp4_port" "$udp6_port" "$tcp6_port" "$old_tcp6_port"; do
  if ! [[ "$value" =~ ^[0-9]+$ ]] || (( value < 1024 || value > 65535 )); then
    echo "invalid port: $value" >&2
    exit 2
  fi
done
if ! [[ "$timeout_ms" =~ ^[0-9]+$ ]] || (( timeout_ms < 500 || timeout_ms > 30000 )); then
  echo "invalid timeout ms: $timeout_ms" >&2
  exit 2
fi

mkdir -p "$RESULT_DIR"
summary="$RESULT_DIR/summary.properties"
: > "$summary"
server_pid=""
wifi_disabled=0

kv() {
  printf '%s=%s\n' "$1" "$2" | tee -a "$summary"
}

adb_target() {
  "$ADB" -s "$serial" "$@"
}

restore_wifi() {
  local status=$?
  set +e
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
  fi
  start_activity --ez runtimeStop true >/dev/null 2>&1 || true
  if [[ "$wifi_disabled" == 1 ]]; then
    adb_target shell cmd wifi set-wifi-enabled enabled >/dev/null 2>&1 \
      || adb_target shell svc wifi enable >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap restore_wifi EXIT

fail_closed() {
  kv result FAIL
  kv failure "$1"
  echo "SAKAMOTO-184 FAIL: $1" >&2
  exit 1
}

start_activity() {
  adb_target shell am start -n "$ACTIVITY" "$@" >/dev/null
}

stop_runtime_best_effort() {
  start_activity --ez runtimeStop true >/dev/null 2>&1 || true
  local deadline=$((SECONDS + 10))
  while (( SECONDS < deadline )); do
    read_app_file "$STATE_PATH" > "$RESULT_DIR/state.preflight.stop.properties"
    if grep -Fq "state=stopped" "$RESULT_DIR/state.preflight.stop.properties"; then
      return 0
    fi
    sleep 1
  done
  return 0
}

read_app_file() {
  local relative="$1"
  adb_target shell run-as "$PACKAGE" cat "$relative" 2>/dev/null | tr -d '\r' || true
}

capture_runtime_log() {
  local label="$1"
  read_app_file "$RUNTIME_LOG_PATH" > "$RESULT_DIR/runtime-service.${label}.log"
}

clear_app_files() {
  adb_target shell run-as "$PACKAGE" rm -f "$STATE_PATH" "$STATUS_PATH" \
    "$S180_STATUS_PATH" "$S181_STATUS_PATH" "$S182_STATUS_PATH" \
    "$S183_STATUS_PATH" "$TCP_PROBE_PATH" "$UDP_PROBE_PATH" \
    >/dev/null 2>&1 || true
}

wait_app_property() {
  local relative="$1"
  local key="$2"
  local expected="$3"
  local out_file="$4"
  local deadline=$((SECONDS + 30))
  while (( SECONDS < deadline )); do
    read_app_file "$relative" > "$out_file"
    if grep -Fq "${key}=${expected}" "$out_file"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

wait_probe_result() {
  local relative="$1"
  local expected_nonce="$2"
  local expected_result="$3"
  local out_file="$4"
  local deadline=$((SECONDS + 40))
  while (( SECONDS < deadline )); do
    read_app_file "$relative" > "$out_file"
    if grep -Fq "nonce=${expected_nonce}" "$out_file" \
      && grep -Fq "result=${expected_result}" "$out_file"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

wait_probe_nonce() {
  local relative="$1"
  local expected_nonce="$2"
  local out_file="$3"
  local deadline=$((SECONDS + 45))
  while (( SECONDS < deadline )); do
    read_app_file "$relative" > "$out_file"
    if grep -Fq "nonce=${expected_nonce}" "$out_file"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

property_value() {
  local key="$1"
  local file="$2"
  awk -F= -v wanted="$key" '
    $1 == wanted {
      value = substr($0, index($0, "=") + 1)
      sub(/\r$/, "", value)
      print value
      exit
    }' "$file"
}

require_positive_property() {
  local key="$1"
  local file="$2"
  local value
  value="$(property_value "$key" "$file")"
  if ! [[ "$value" =~ ^[0-9]+$ ]] || (( value <= 0 )); then
    fail_closed "$key is not positive in $file"
  fi
  kv "$key" "$value"
}

require_zero_property() {
  local key="$1"
  local file="$2"
  local value
  value="$(property_value "$key" "$file")"
  if [[ -z "$value" ]]; then
    fail_closed "$key is missing in $file"
  fi
  if ! [[ "$value" =~ ^[0-9]+$ ]] || (( value != 0 )); then
    fail_closed "$key is not zero in $file"
  fi
  kv "$key" "$value"
}

capture_connectivity() {
  local label="$1"
  adb_target shell cmd wifi status | tr -d '\r' > "$RESULT_DIR/wifi.${label}.txt" || true
  adb_target shell dumpsys connectivity > "$RESULT_DIR/connectivity.${label}.txt" || true
}

wifi_handle_from_connectivity() {
  local file="$1"
  awk '
    /NetworkAgentInfo\{network\{[0-9]+\}  handle\{[0-9]+\}/ && /WIFI CONNECTED/ {
      line = $0
      sub(/^.*handle\{/, "", line)
      sub(/\}.*$/, "", line)
      print line
      exit
    }' "$file"
}

wait_for_wifi_connectivity_gone() {
  local deadline=$((SECONDS + 30))
  while (( SECONDS < deadline )); do
    capture_connectivity wifi_off
    if ! grep -Fq "WIFI CONNECTED" "$RESULT_DIR/connectivity.wifi_off.txt"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

require_s184_underlay_snapshot() {
  local status_file="$1"
  local expected_wifi_handle="$2"
  local label="$3"
  grep -Fq "network_context_snapshot=explicit_underlay_at_socket_creation" \
    "$status_file" || fail_closed "$label missing network snapshot evidence"
  grep -Fq "set_underlying_networks=explicit_bound_underlay" \
    "$status_file" || fail_closed "$label missing setUnderlyingNetworks evidence"
  grep -Fq "vpn_direct_underlay_handles_consistent=true" \
    "$status_file" || fail_closed "$label underlay handles are inconsistent"
  grep -Fq "vpn_direct_underlay_transport=wifi" \
    "$status_file" || fail_closed "$label did not use Wi-Fi as Direct underlay"
  require_positive_property vpn_direct_underlay_epoch "$status_file"
  require_positive_property vpn_direct_underlay_network_handle "$status_file"
  require_positive_property vpn_direct_udp4_network_handle "$status_file"
  require_positive_property vpn_direct_udp6_network_handle "$status_file"
  require_positive_property vpn_direct_tcp4_network_handle "$status_file"
  require_positive_property vpn_direct_tcp6_network_handle "$status_file"
  local underlay_handle
  underlay_handle="$(property_value vpn_direct_underlay_network_handle "$status_file")"
  if [[ "$underlay_handle" != "$expected_wifi_handle" ]]; then
    fail_closed "$label Direct underlay handle $underlay_handle does not match Wi-Fi handle $expected_wifi_handle"
  fi
  require_zero_property vpn_direct_udp4_transport_failed "$status_file"
  require_zero_property vpn_direct_udp6_transport_failed "$status_file"
  require_zero_property vpn_direct_tcp4_transport_failed "$status_file"
  require_zero_property vpn_direct_tcp6_transport_failed "$status_file"
}

require_app_probe() {
  local probe_file="$1"
  local label="$2"
  grep -Fq "bindToVpn=true" "$probe_file" \
    || fail_closed "$label was not requested as VPN-bound"
  grep -Fq "bindResult=bound" "$probe_file" \
    || fail_closed "$label did not bind to the active VPN Network"
  local uid request_bytes response_bytes
  uid="$(property_value uid "$probe_file")"
  if ! [[ "$uid" =~ ^[0-9]+$ ]] || [[ "$uid" == "2000" ]]; then
    fail_closed "$label did not run as installed app uid"
  fi
  request_bytes="$(property_value requestBytes "$probe_file")"
  response_bytes="$(property_value responseBytes "$probe_file")"
  if ! [[ "$request_bytes" =~ ^[0-9]+$ ]] || (( request_bytes <= 0 )); then
    fail_closed "$label did not write request bytes"
  fi
  if [[ "$response_bytes" != "$request_bytes" ]]; then
    fail_closed "$label response bytes did not match request bytes"
  fi
  kv "${label}.uid" "$uid"
}

wait_for_host_ready() {
  local ready_file="$1"
  local deadline=$((SECONDS + 10))
  while (( SECONDS < deadline )); do
    if [[ -f "$ready_file" ]]; then
      return 0
    fi
    sleep 1
  done
  return 1
}

start_udp4_echo_server() {
  local bind_host="$1"
  local listen_port="$2"
  local expected_nonce="$3"
  local ready_file="$4"
  local log_file="$5"
  python3 - "$bind_host" "$listen_port" "$expected_nonce" "$ready_file" "$log_file" \
    <<'PY' >/dev/null 2>&1 &
import pathlib
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
expected = sys.argv[3].encode()
ready = pathlib.Path(sys.argv[4])
log = pathlib.Path(sys.argv[5])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((host, port))
sock.settimeout(30)
ready.write_text("ready\n", encoding="utf-8")
result = "udp_echo_unseen"
request_bytes = 0
response_bytes = 0
peer = ""
nonce = ""
try:
    data, address = sock.recvfrom(2048)
    peer = f"{address[0]}:{address[1]}"
    request_bytes = len(data)
    nonce = data.decode(errors="replace")
    if data == expected:
        sock.sendto(data, address)
        response_bytes = len(data)
        result = "udp_echo_matched"
    else:
        result = "udp_echo_mismatch"
except Exception as error:
    result = f"udp_echo_failed:{error.__class__.__name__}:{error}"
finally:
    sock.close()
    log.write_text(
        f"family=AF_INET\nresult={result}\npeer={peer}\n"
        f"requestBytes={request_bytes}\nresponseBytes={response_bytes}\n"
        f"nonce={nonce}\n",
        encoding="utf-8",
    )
PY
  server_pid="$!"
}

start_udp6_echo_server() {
  local bind_host="$1"
  local listen_port="$2"
  local expected_nonce="$3"
  local ready_file="$4"
  local log_file="$5"
  python3 - "$bind_host" "$listen_port" "$expected_nonce" "$ready_file" "$log_file" \
    <<'PY' >/dev/null 2>&1 &
import pathlib
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
expected = sys.argv[3].encode()
ready = pathlib.Path(sys.argv[4])
log = pathlib.Path(sys.argv[5])
sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
sock.bind((host, port))
sock.settimeout(30)
ready.write_text("ready\n", encoding="utf-8")
result = "udp_echo_unseen"
request_bytes = 0
response_bytes = 0
peer = ""
nonce = ""
try:
    data, address = sock.recvfrom(2048)
    peer = f"{address[0]}:{address[1]}"
    request_bytes = len(data)
    nonce = data.decode(errors="replace")
    if data == expected:
        sock.sendto(data, address)
        response_bytes = len(data)
        result = "udp_echo_matched"
    else:
        result = "udp_echo_mismatch"
except Exception as error:
    result = f"udp_echo_failed:{error.__class__.__name__}:{error}"
finally:
    sock.close()
    log.write_text(
        f"family=AF_INET6\nresult={result}\npeer={peer}\n"
        f"requestBytes={request_bytes}\nresponseBytes={response_bytes}\n"
        f"nonce={nonce}\n",
        encoding="utf-8",
    )
PY
  server_pid="$!"
}

start_tcp4_echo_server() {
  local bind_host="$1"
  local listen_port="$2"
  local expected_nonce="$3"
  local ready_file="$4"
  local log_file="$5"
  python3 - "$bind_host" "$listen_port" "$expected_nonce" "$ready_file" "$log_file" \
    <<'PY' >/dev/null 2>&1 &
import pathlib
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
expected = sys.argv[3].encode()
ready = pathlib.Path(sys.argv[4])
log = pathlib.Path(sys.argv[5])
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((host, port))
server.listen(1)
server.settimeout(30)
ready.write_text("ready\n", encoding="utf-8")
result = "tcp_echo_unseen"
request_bytes = 0
response_bytes = 0
peer = ""
nonce = ""
try:
    conn, address = server.accept()
    peer = f"{address[0]}:{address[1]}"
    with conn:
        conn.settimeout(10)
        data = conn.recv(4096)
        request_bytes = len(data)
        nonce = data.decode(errors="replace")
        if data == expected:
            conn.sendall(data)
            response_bytes = len(data)
            result = "tcp_echo_matched"
        else:
            result = "tcp_echo_mismatch"
except Exception as error:
    result = f"tcp_echo_failed:{error.__class__.__name__}:{error}"
finally:
    server.close()
    log.write_text(
        f"family=AF_INET\nresult={result}\npeer={peer}\n"
        f"requestBytes={request_bytes}\nresponseBytes={response_bytes}\n"
        f"nonce={nonce}\n",
        encoding="utf-8",
    )
PY
  server_pid="$!"
}

start_tcp6_echo_server() {
  local bind_host="$1"
  local listen_port="$2"
  local expected_nonce="$3"
  local ready_file="$4"
  local log_file="$5"
  python3 - "$bind_host" "$listen_port" "$expected_nonce" "$ready_file" "$log_file" \
    <<'PY' >/dev/null 2>&1 &
import pathlib
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
expected = sys.argv[3].encode()
ready = pathlib.Path(sys.argv[4])
log = pathlib.Path(sys.argv[5])
server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
server.bind((host, port))
server.listen(1)
server.settimeout(30)
ready.write_text("ready\n", encoding="utf-8")
result = "tcp_echo_unseen"
request_bytes = 0
response_bytes = 0
peer = ""
nonce = ""
try:
    conn, address = server.accept()
    peer = f"{address[0]}:{address[1]}"
    with conn:
        conn.settimeout(10)
        data = conn.recv(4096)
        request_bytes = len(data)
        nonce = data.decode(errors="replace")
        if data == expected:
            conn.sendall(data)
            response_bytes = len(data)
            result = "tcp_echo_matched"
        else:
            result = "tcp_echo_mismatch"
except Exception as error:
    result = f"tcp_echo_failed:{error.__class__.__name__}:{error}"
finally:
    server.close()
    log.write_text(
        f"family=AF_INET6\nresult={result}\npeer={peer}\n"
        f"requestBytes={request_bytes}\nresponseBytes={response_bytes}\n"
        f"nonce={nonce}\n",
        encoding="utf-8",
    )
PY
  server_pid="$!"
}

start_delayed_tcp6_echo_server() {
  local bind_host="$1"
  local listen_port="$2"
  local expected_nonce="$3"
  local ready_file="$4"
  local accepted_file="$5"
  local log_file="$6"
  local send_trigger_file="$7"
  python3 - "$bind_host" "$listen_port" "$expected_nonce" "$ready_file" \
    "$accepted_file" "$log_file" "$send_trigger_file" <<'PY' >/dev/null 2>&1 &
import pathlib
import socket
import sys
import time

host = sys.argv[1]
port = int(sys.argv[2])
expected = sys.argv[3].encode()
ready = pathlib.Path(sys.argv[4])
accepted = pathlib.Path(sys.argv[5])
log = pathlib.Path(sys.argv[6])
send_trigger = pathlib.Path(sys.argv[7])
server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
server.bind((host, port))
server.listen(1)
server.settimeout(30)
ready.write_text("ready\n", encoding="utf-8")
result = "tcp_echo_unseen"
request_bytes = 0
response_bytes = 0
peer = ""
nonce = ""
try:
    conn, address = server.accept()
    peer = f"{address[0]}:{address[1]}"
    with conn:
        conn.settimeout(10)
        data = conn.recv(4096)
        request_bytes = len(data)
        nonce = data.decode(errors="replace")
        accepted.write_text(
            f"family=AF_INET6\npeer={peer}\nrequestBytes={request_bytes}\n"
            f"nonce={nonce}\n",
            encoding="utf-8",
        )
        deadline = time.time() + 45
        while time.time() < deadline and not send_trigger.exists():
            time.sleep(0.2)
        if data == expected and send_trigger.exists():
            conn.sendall(data)
            response_bytes = len(data)
            result = "tcp_echo_matched"
        elif data == expected:
            result = "tcp_echo_release_not_triggered"
        else:
            result = "tcp_echo_mismatch"
except Exception as error:
    result = f"tcp_echo_failed:{error.__class__.__name__}:{error}"
finally:
    server.close()
    log.write_text(
        f"family=AF_INET6\nresult={result}\npeer={peer}\n"
        f"requestBytes={request_bytes}\nresponseBytes={response_bytes}\n"
        f"nonce={nonce}\n",
        encoding="utf-8",
    )
PY
  server_pid="$!"
}

finish_server() {
  if [[ -n "$server_pid" ]]; then
    wait "$server_pid" || true
    server_pid=""
  fi
}

run_udp4_probe() {
  local nonce="$1"
  local ready_file="$RESULT_DIR/${nonce}.udp4.ready"
  local log_file="$RESULT_DIR/${nonce}.udp4.server.log"
  rm -f "$ready_file" "$log_file"
  server_pid=""
  start_udp4_echo_server "0.0.0.0" "$udp4_port" "$nonce" "$ready_file" "$log_file"
  wait_for_host_ready "$ready_file" || fail_closed "UDP4 server did not become ready"
  start_activity --ez debugUdpTraffic true --es debugUdpHost "$host4" \
    --ei debugUdpPort "$udp4_port" --es debugUdpNonce "$nonce" \
    --ez debugUdpExpectReply true --ei debugUdpTimeoutMillis "$timeout_ms" \
    --ez debugTrafficBindToVpn true
  wait_probe_result "$UDP_PROBE_PATH" "$nonce" udp_echo_matched \
    "$RESULT_DIR/${nonce}.udp4.probe.properties" \
    || fail_closed "installed app UDP4 probe did not echo"
  finish_server
  grep -Fq "result=udp_echo_matched" "$log_file" \
    || fail_closed "controlled LAN UDP4 server did not observe nonce"
  require_app_probe "$RESULT_DIR/${nonce}.udp4.probe.properties" udp4
}

run_udp6_probe() {
  local nonce="$1"
  local ready_file="$RESULT_DIR/${nonce}.udp6.ready"
  local log_file="$RESULT_DIR/${nonce}.udp6.server.log"
  rm -f "$ready_file" "$log_file"
  server_pid=""
  start_udp6_echo_server "$host6" "$udp6_port" "$nonce" "$ready_file" "$log_file"
  wait_for_host_ready "$ready_file" || fail_closed "UDP6 server did not become ready"
  start_activity --ez debugUdpTraffic true --es debugUdpHost "$host6" \
    --ei debugUdpPort "$udp6_port" --es debugUdpNonce "$nonce" \
    --ez debugUdpExpectReply true --ei debugUdpTimeoutMillis "$timeout_ms" \
    --ez debugTrafficBindToVpn true
  wait_probe_result "$UDP_PROBE_PATH" "$nonce" udp_echo_matched \
    "$RESULT_DIR/${nonce}.udp6.probe.properties" \
    || fail_closed "installed app UDP6 probe did not echo"
  finish_server
  grep -Fq "result=udp_echo_matched" "$log_file" \
    || fail_closed "controlled LAN UDP6 server did not observe nonce"
  require_app_probe "$RESULT_DIR/${nonce}.udp6.probe.properties" udp6
}

run_tcp4_probe() {
  local nonce="$1"
  local ready_file="$RESULT_DIR/${nonce}.tcp4.ready"
  local log_file="$RESULT_DIR/${nonce}.tcp4.server.log"
  rm -f "$ready_file" "$log_file"
  server_pid=""
  start_tcp4_echo_server "0.0.0.0" "$tcp4_port" "$nonce" "$ready_file" "$log_file"
  wait_for_host_ready "$ready_file" || fail_closed "TCP4 server did not become ready"
  start_activity --ez debugTraffic true --es debugTrafficHost "$host4" \
    --ei debugTrafficPort "$tcp4_port" --es debugTrafficNonce "$nonce" \
    --ei debugTrafficTimeoutMillis "$timeout_ms" --ez debugTrafficBindToVpn true
  wait_probe_result "$TCP_PROBE_PATH" "$nonce" tcp_echo_matched \
    "$RESULT_DIR/${nonce}.tcp4.probe.properties" \
    || fail_closed "installed app TCP4 probe did not echo"
  finish_server
  grep -Fq "result=tcp_echo_matched" "$log_file" \
    || fail_closed "controlled LAN TCP4 server did not observe nonce"
  require_app_probe "$RESULT_DIR/${nonce}.tcp4.probe.properties" tcp4
}

run_tcp6_probe() {
  local nonce="$1"
  local listen_port="$2"
  local ready_file="$RESULT_DIR/${nonce}.tcp6.ready"
  local log_file="$RESULT_DIR/${nonce}.tcp6.server.log"
  rm -f "$ready_file" "$log_file"
  server_pid=""
  start_tcp6_echo_server "::" "$listen_port" "$nonce" "$ready_file" "$log_file"
  wait_for_host_ready "$ready_file" || fail_closed "TCP6 server did not become ready"
  start_activity --ez debugTraffic true --es debugTrafficHost "$host6" \
    --ei debugTrafficPort "$listen_port" --es debugTrafficNonce "$nonce" \
    --ei debugTrafficTimeoutMillis "$timeout_ms" --ez debugTrafficBindToVpn true
  wait_probe_result "$TCP_PROBE_PATH" "$nonce" tcp_echo_matched \
    "$RESULT_DIR/${nonce}.tcp6.probe.properties" \
    || fail_closed "installed app TCP6 probe did not echo"
  finish_server
  grep -Fq "result=tcp_echo_matched" "$log_file" \
    || fail_closed "controlled LAN TCP6 server did not observe nonce"
  require_app_probe "$RESULT_DIR/${nonce}.tcp6.probe.properties" tcp6
}

disable_wifi() {
  kv wifi.disable "cmd wifi set-wifi-enabled disabled"
  if adb_target shell cmd wifi set-wifi-enabled disabled >/dev/null 2>&1; then
    wifi_disabled=1
  else
    adb_target shell svc wifi disable >/dev/null 2>&1 \
      || fail_closed "could not disable Wi-Fi through Android CLI"
    wifi_disabled=1
  fi
  local deadline=$((SECONDS + 30))
  while (( SECONDS < deadline )); do
    adb_target shell cmd wifi status | tr -d '\r' > "$RESULT_DIR/wifi.disabled.poll.txt" || true
    if grep -Fq "Wifi is disabled" "$RESULT_DIR/wifi.disabled.poll.txt"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

enable_wifi() {
  kv wifi.enable "cmd wifi set-wifi-enabled enabled"
  adb_target shell cmd wifi set-wifi-enabled enabled >/dev/null 2>&1 \
    || adb_target shell svc wifi enable >/dev/null 2>&1 \
    || fail_closed "could not enable Wi-Fi through Android CLI"
  wifi_disabled=0
}

wait_after_wifi_enable() {
  local deadline=$((SECONDS + 30))
  while (( SECONDS < deadline )); do
    if adb_target shell cmd wifi status 2>/dev/null | tr -d '\r' \
      | grep -Fq 'Wifi is connected'; then
      sleep 5
      return 0
    fi
    sleep 1
  done
  return 1
}

compare_epoch() {
  local before_file="$1"
  local after_file="$2"
  local before after before_handle after_handle
  before="$(property_value vpn_direct_underlay_epoch "$before_file")"
  after="$(property_value vpn_direct_underlay_epoch "$after_file")"
  if ! [[ "$before" =~ ^[0-9]+$ && "$after" =~ ^[0-9]+$ ]]; then
    fail_closed "underlay epoch values are not numeric"
  fi
  if [[ "$after" == "$before" ]]; then
    fail_closed "fresh underlay epoch did not change after Wi-Fi restore"
  fi
  before_handle="$(property_value vpn_direct_underlay_network_handle "$before_file")"
  after_handle="$(property_value vpn_direct_underlay_network_handle "$after_file")"
  if ! [[ "$before_handle" =~ ^[0-9]+$ && "$after_handle" =~ ^[0-9]+$ ]]; then
    fail_closed "underlay network handles are not numeric"
  fi
  if [[ "$before_handle" == "$after_handle" ]]; then
    fail_closed "Wi-Fi Network handle did not change after off/on"
  fi
  kv underlay_epoch_before_wifi_disable "$before"
  kv underlay_epoch_after_wifi_restore "$after"
  kv underlay_epoch_changed true
  kv underlay_handle_before_wifi_disable "$before_handle"
  kv underlay_handle_after_wifi_restore "$after_handle"
  kv underlay_handle_changed true
  kv fresh_epoch_after_wifi_restore true
}

kv acceptance SAKAMOTO-184-vpn-network-epoch
kv serial "$serial"
kv package "$PACKAGE"
kv host4 "$host4"
kv host6 "$host6"

"$ADB" devices | tr -d '\r' | grep -Eq "^${serial}[[:space:]]+device$" \
  || fail_closed "controlled Pixel 6a serial is not in adb devices"
adb_target get-state >/dev/null || fail_closed "ADB device is not available"
adb_target shell getprop ro.product.model | tr -d '\r' > "$RESULT_DIR/device-model.txt"
if ! grep -Fq "Pixel 6a" "$RESULT_DIR/device-model.txt"; then
  fail_closed "connected serial is not the controlled Pixel 6a"
fi
adb_target shell pm path "$PACKAGE" >/dev/null 2>&1 \
  || fail_closed "installed debug APK is missing: $PACKAGE"
adb_target shell pm grant "$PACKAGE" android.permission.POST_NOTIFICATIONS \
  >/dev/null 2>&1 || true

capture_connectivity initial
wifi_handle_before="$(wifi_handle_from_connectivity "$RESULT_DIR/connectivity.initial.txt")"
if ! [[ "$wifi_handle_before" =~ ^[0-9]+$ ]]; then
  fail_closed "initial connectivity did not expose a Wi-Fi Network handle"
fi
kv wifi_handle_before "$wifi_handle_before"

clear_app_files
stop_runtime_best_effort
clear_app_files
start_activity --ez runtimeStart true --es runtimeProfile vpn
wait_app_property "$STATE_PATH" adapterReadiness vpn-tun-hev-lwip \
  "$RESULT_DIR/state.pre.running.properties" \
  || fail_closed "VPN Product Core did not publish adapterReadiness=vpn-tun-hev-lwip; approve any VPN dialog and rerun"
capture_runtime_log before

run_udp4_probe "s184-udp4-${RUN_ID}"
kv installed_app_udp4_source true
run_tcp4_probe "s184-tcp4-${RUN_ID}"
kv installed_app_tcp4_source true
run_udp6_probe "s184-udp6-${RUN_ID}"
kv installed_app_udp6_source true
run_tcp6_probe "s184-tcp6-${RUN_ID}" "$tcp6_port"
kv installed_app_tcp6_source true
kv uid_not_shell true

start_activity --ez debugRefresh true
wait_app_property "$STATUS_PATH" adapterReadiness vpn-tun-hev-lwip \
  "$RESULT_DIR/s184-pre-status.properties" \
  || fail_closed "S184 pre status did not publish"
require_s184_underlay_snapshot "$RESULT_DIR/s184-pre-status.properties" \
  "$wifi_handle_before" "S184 pre status"
require_positive_property vpn_tun_udp4_tun_origin_packets "$RESULT_DIR/s184-pre-status.properties"
require_positive_property vpn_tun_udp6_tun_origin_packets "$RESULT_DIR/s184-pre-status.properties"
require_positive_property vpn_tun_tcp4_tun_origin_packets "$RESULT_DIR/s184-pre-status.properties"
require_positive_property vpn_tun_tcp6_tun_origin_packets "$RESULT_DIR/s184-pre-status.properties"

old_tcp6_nonce="s184-old-tcp6-${RUN_ID}"
old_ready="$RESULT_DIR/${old_tcp6_nonce}.tcp6.ready"
old_accepted="$RESULT_DIR/${old_tcp6_nonce}.tcp6.accepted"
old_send_trigger="$RESULT_DIR/${old_tcp6_nonce}.tcp6.send"
old_log="$RESULT_DIR/${old_tcp6_nonce}.tcp6.server.log"
rm -f "$old_ready" "$old_accepted" "$old_send_trigger" "$old_log"
server_pid=""
start_delayed_tcp6_echo_server "::" "$old_tcp6_port" "$old_tcp6_nonce" \
  "$old_ready" "$old_accepted" "$old_log" "$old_send_trigger"
wait_for_host_ready "$old_ready" || fail_closed "delayed TCP6 server did not become ready"
start_activity --ez debugTraffic true --es debugTrafficHost "$host6" \
  --ei debugTrafficPort "$old_tcp6_port" --es debugTrafficNonce "$old_tcp6_nonce" \
  --ei debugTrafficTimeoutMillis 15000 --ez debugTrafficBindToVpn true
wait_for_host_ready "$old_accepted" \
  || fail_closed "old TCP6 active flow was not observed before Wi-Fi disable"
grep -Fq "nonce=${old_tcp6_nonce}" "$old_accepted" \
  || fail_closed "old TCP6 active flow observed the wrong nonce"
kv old_tcp6_active_flow_observed true

disable_wifi
wait_for_wifi_connectivity_gone \
  || fail_closed "connectivity still reports WIFI CONNECTED after Wi-Fi disable"
: > "$old_send_trigger"
wait_probe_nonce "$TCP_PROBE_PATH" "$old_tcp6_nonce" \
  "$RESULT_DIR/${old_tcp6_nonce}.probe.properties" \
  || fail_closed "old TCP6 probe did not publish an outcome after Wi-Fi disable"
if grep -Fq "result=tcp_echo_matched" \
  "$RESULT_DIR/${old_tcp6_nonce}.probe.properties"; then
  fail_closed "old TCP6 flow migrated/reconnected across Wi-Fi disable"
fi
kv old_tcp6_not_migrated true
finish_server

enable_wifi
wait_after_wifi_enable || fail_closed "Wi-Fi did not reconnect after restore"
capture_connectivity restored
wifi_handle_after="$(wifi_handle_from_connectivity "$RESULT_DIR/connectivity.restored.txt")"
if ! [[ "$wifi_handle_after" =~ ^[0-9]+$ ]]; then
  fail_closed "restored connectivity did not expose a Wi-Fi Network handle"
fi
if [[ "$wifi_handle_after" == "$wifi_handle_before" ]]; then
  fail_closed "Wi-Fi Network handle did not change after off/on"
fi
kv wifi_handle_after "$wifi_handle_after"
start_activity --ez runtimeStop true
wait_app_property "$STATE_PATH" state stopped "$RESULT_DIR/state.old.stopped.properties" \
  || fail_closed "old VPN Product Core generation did not stop cleanly"
if grep -Fq "mayBeActive=true" "$RESULT_DIR/state.old.stopped.properties"; then
  fail_closed "old stopped state still reports mayBeActive=true"
fi

clear_app_files
start_activity --ez runtimeStart true --es runtimeProfile vpn
wait_app_property "$STATE_PATH" adapterReadiness vpn-tun-hev-lwip \
  "$RESULT_DIR/state.post.running.properties" \
  || fail_closed "fresh VPN Product Core generation did not start after Wi-Fi restore"
capture_runtime_log after
run_tcp6_probe "s184-new-tcp6-${RUN_ID}" "$tcp6_port"
kv new_flow_after_wifi_restore true
start_activity --ez debugRefresh true
wait_app_property "$STATUS_PATH" adapterReadiness vpn-tun-hev-lwip \
  "$RESULT_DIR/s184-post-status.properties" \
  || fail_closed "S184 post status did not publish"
require_s184_underlay_snapshot "$RESULT_DIR/s184-post-status.properties" \
  "$wifi_handle_after" "S184 post status"
compare_epoch "$RESULT_DIR/s184-pre-status.properties" \
  "$RESULT_DIR/s184-post-status.properties"

start_activity --ez runtimeStop true
wait_app_property "$STATE_PATH" state stopped "$RESULT_DIR/state.final.stopped.properties" \
  || fail_closed "fresh VPN Product Core generation did not stop cleanly"
if grep -Fq "mayBeActive=true" "$RESULT_DIR/state.final.stopped.properties"; then
  fail_closed "final stopped state still reports mayBeActive=true"
fi
kv final_residue_clean true
kv result PASS
echo "SAKAMOTO-184 VPN network epoch: PASS"
