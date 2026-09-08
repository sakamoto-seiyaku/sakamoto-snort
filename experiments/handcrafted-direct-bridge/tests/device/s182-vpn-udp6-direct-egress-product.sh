#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-182-vpn-udp6-direct-egress real-device acceptance entry point.
#
# PASS means the installed debug APK starts the VPN Product Core on the
# controlled Pixel 6a, transfers the VpnService TUN fd plus protected Direct
# UDP4/UDP6/TCP4 socket fds to Product VPP, sends an installed-app UDP6 nonce
# bound to the VPN Network through TUN -> VPP -> owner-local Flow Stack ->
# protected UDP6 socket -> controlled LAN, receives echoed bytes back through
# VPP return provenance and TUN, then stops cleanly.

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export ADB="${repo_root}/dev/adb"

readonly S182_SERIAL="28201JEGR0XPAJ"
readonly PACKAGE="${PACKAGE:-com.sakamoto.snort.androidruntime}"
readonly ACTIVITY="${ACTIVITY:-${PACKAGE}/.DebugControlActivity}"
readonly RESULTS_ROOT="${RESULTS_ROOT:-${repo_root}/build-output/s182-vpn-udp6-direct-egress}"
readonly RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
readonly RESULT_DIR="${RESULT_DIR:-${RESULTS_ROOT}/${RUN_ID}}"

readonly STATE_PATH="files/runtime-state/snapshot.properties"
readonly STATUS_PATH="files/product-state/s182-vpn-udp6-direct-egress.properties"
readonly S180_STATUS_PATH="files/product-state/s180-vpn-udp4-direct-egress.properties"
readonly S181_STATUS_PATH="files/product-state/s181-vpn-tcp4-direct-egress.properties"
readonly TCP_PROBE_PATH="files/debug/traffic-probe.properties"
readonly UDP_PROBE_PATH="files/debug/udp-traffic-probe.properties"

usage() {
  cat <<'EOF'
Usage:
  tests/device/s182-vpn-udp6-direct-egress-product.sh --run --host <controlled-lan-ipv6>

Required:
  --run
  --host / S182_CONTROLLED_LAN_HOST6

Optional:
  --serial 28201JEGR0XPAJ
  --port / S182_UDP6_PORT             default 18182
  --timeout-ms / S182_TIMEOUT_MILLIS  default 5000

Before running, the debug APK must already be installed. If Android displays
the VPN authorization dialog, approve it on the Pixel 6a and rerun this
script; VpnService authorization is revocable and cannot be assumed.

Required final evidence:
  adapterReadiness=vpn-tun-hev-lwip
  installed_app_udp_source true
  uid_not_shell true
  files/product-state/s182-vpn-udp6-direct-egress.properties
  vpn_tun_udp6_tun_origin_packets > 0
  vpn_direct_udp6_socket_attached > 0
  vpn_direct_udp6_protect_succeeded > 0
  vpn_direct_udp6_bind_succeeded > 0
  vpn_direct_udp6_send_succeeded > 0
  vpn_direct_udp6_return_packets > 0
  vpn_direct_udp6_tun_write_completions > 0
  vpn_direct_udp6_transport_failed = 0
  final_residue_clean true
EOF
}

serial="$S182_SERIAL"
run=0
controlled_host="${S182_CONTROLLED_LAN_HOST6:-}"
port="${S182_UDP6_PORT:-18182}"
timeout_ms="${S182_TIMEOUT_MILLIS:-5000}"

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
    --host)
      controlled_host="${2:-}"
      shift 2
      ;;
    --port)
      port="${2:-}"
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

if [[ "$serial" != "$S182_SERIAL" ]]; then
  echo "SAKAMOTO-182 only accepts controlled Pixel 6a serial $S182_SERIAL; got $serial" >&2
  exit 2
fi
if [[ "$run" != 1 ]]; then
  usage >&2
  exit 2
fi
if [[ -z "$controlled_host" ]]; then
  echo "missing --host or S182_CONTROLLED_LAN_HOST6" >&2
  usage >&2
  exit 2
fi
if [[ "$controlled_host" != *:* ]]; then
  echo "controlled host must be an IPv6 literal: $controlled_host" >&2
  exit 2
fi
python3 - "$controlled_host" <<'PY'
import ipaddress
import sys

try:
    address = ipaddress.ip_address(sys.argv[1])
except ValueError:
    raise SystemExit("controlled host must be an IPv6 literal")
if address.version != 6:
    raise SystemExit("controlled host must be an IPv6 literal")
if getattr(address, "ipv4_mapped", None) is not None:
    raise SystemExit("controlled host must not be an IPv4-mapped IPv6 address")
if address.is_loopback or address.is_unspecified:
    raise SystemExit("controlled host must be reachable from the Pixel 6a")
PY
if ! [[ "$port" =~ ^[0-9]+$ ]] || (( port < 1024 || port > 65535 )); then
  echo "invalid UDP6 port: $port" >&2
  exit 2
fi
if ! [[ "$timeout_ms" =~ ^[0-9]+$ ]] || (( timeout_ms < 500 || timeout_ms > 30000 )); then
  echo "invalid timeout ms: $timeout_ms" >&2
  exit 2
fi

mkdir -p "$RESULT_DIR"
summary="$RESULT_DIR/summary.properties"
: > "$summary"

kv() {
  printf '%s=%s\n' "$1" "$2" | tee -a "$summary"
}

fail_closed() {
  kv result FAIL
  kv failure "$1"
  echo "SAKAMOTO-182 FAIL: $1" >&2
  exit 1
}

adb_target() {
  "$ADB" -s "$serial" "$@"
}

start_activity() {
  adb_target shell am start -n "$ACTIVITY" "$@" >/dev/null
}

read_app_file() {
  local relative="$1"
  adb_target shell run-as "$PACKAGE" cat "$relative" 2>/dev/null | tr -d '\r' || true
}

clear_app_files() {
  adb_target shell run-as "$PACKAGE" rm -f "$STATE_PATH" "$STATUS_PATH" \
    "$S180_STATUS_PATH" "$S181_STATUS_PATH" "$TCP_PROBE_PATH" "$UDP_PROBE_PATH" \
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
peer = ""
request_bytes = 0
response_bytes = 0
received_nonce = ""
try:
    data, address = sock.recvfrom(2048)
    peer = f"{address[0]}:{address[1]}"
    request_bytes = len(data)
    received_nonce = data.decode(errors="replace")
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
        f"nonce={received_nonce}\n",
        encoding="utf-8",
    )
PY
  server_pid="$!"
}

kv acceptance SAKAMOTO-182-vpn-udp6-direct-egress
kv serial "$serial"
kv package "$PACKAGE"
kv host "$controlled_host"
kv port "$port"

adb_target get-state >/dev/null || fail_closed "ADB device is not available"
adb_target shell getprop ro.product.model | tr -d '\r' > "$RESULT_DIR/device-model.txt"
if ! grep -Fq "Pixel 6a" "$RESULT_DIR/device-model.txt"; then
  fail_closed "connected serial is not the controlled Pixel 6a"
fi
adb_target shell pm path "$PACKAGE" >/dev/null 2>&1 \
  || fail_closed "installed debug APK is missing: $PACKAGE"
adb_target shell pm grant "$PACKAGE" android.permission.POST_NOTIFICATIONS \
  >/dev/null 2>&1 || true

ready_file="$RESULT_DIR/s182.udp6.ready"
server_log="$RESULT_DIR/s182.udp6.server.log"
nonce="s182-${RUN_ID}"

clear_app_files
start_activity --ez runtimeStart true --es runtimeProfile vpn
wait_app_property "$STATE_PATH" adapterReadiness vpn-tun-hev-lwip \
  "$RESULT_DIR/state.running.properties" \
  || fail_closed "VPN Product Core did not publish adapterReadiness=vpn-tun-hev-lwip; approve any VPN dialog and rerun"

rm -f "$ready_file" "$server_log"
server_pid=""
# Bind the controlled endpoint so the native exact remote-address match is deterministic.
start_udp6_echo_server "$controlled_host" "$port" "$nonce" "$ready_file" "$server_log"
trap 'kill "$server_pid" >/dev/null 2>&1 || true' EXIT
wait_for_host_ready "$ready_file" || fail_closed "controlled LAN UDP6 server did not become ready"

start_activity \
  --ez debugUdpTraffic true \
  --es debugUdpHost "$controlled_host" \
  --ei debugUdpPort "$port" \
  --es debugUdpNonce "$nonce" \
  --ez debugUdpExpectReply true \
  --ei debugUdpTimeoutMillis "$timeout_ms" \
  --ez debugTrafficBindToVpn true
wait_app_property "$UDP_PROBE_PATH" result udp_echo_matched \
  "$RESULT_DIR/device-udp6-probe.properties" \
  || fail_closed "installed app VPN-bound UDP6 probe did not echo through Product Core"
read_app_file "$UDP_PROBE_PATH" > "$RESULT_DIR/device-udp6-probe.properties"

wait "$server_pid" || true
trap - EXIT
if ! grep -Fq "family=AF_INET6" "$server_log"; then
  fail_closed "controlled LAN server did not run as AF_INET6"
fi
if ! grep -Fq "result=udp_echo_matched" "$server_log"; then
  fail_closed "controlled LAN server did not observe the UDP6 nonce"
fi
if ! grep -Fq "nonce=${nonce}" "$server_log"; then
  fail_closed "controlled LAN server observed the wrong UDP6 nonce"
fi

grep -Fq "bindToVpn=true" "$RESULT_DIR/device-udp6-probe.properties" \
  || fail_closed "S182 app probe was not requested as VPN-bound"
grep -Fq "bindResult=bound" "$RESULT_DIR/device-udp6-probe.properties" \
  || fail_closed "S182 app probe did not bind to the active VPN Network"
grep -Fq "nonce=${nonce}" "$RESULT_DIR/device-udp6-probe.properties" \
  || fail_closed "S182 app probe recorded the wrong nonce"
app_uid="$(property_value uid "$RESULT_DIR/device-udp6-probe.properties")"
if ! [[ "$app_uid" =~ ^[0-9]+$ ]]; then
  fail_closed "S182 app probe did not record a numeric uid"
fi
if [[ "$app_uid" == "2000" ]]; then
  fail_closed "S182 app probe used shell uid"
fi
kv installed_app_udp_source true
kv uid_not_shell true
kv uid "$app_uid"

start_activity --ez debugRefresh true
wait_app_property "$STATUS_PATH" adapterReadiness vpn-tun-hev-lwip \
  "$RESULT_DIR/s182-status.properties" \
  || fail_closed "S182 status did not publish the VPN adapter state after UDP6 response"

grep -Fq "adapterReadiness=vpn-tun-hev-lwip" "$RESULT_DIR/s182-status.properties" \
  || fail_closed "S182 status missing adapter readiness"
grep -Fq "controlled_lan_response=matched" "$RESULT_DIR/s182-status.properties" \
  || fail_closed "S182 status did not record controlled LAN UDP6 response"
require_positive_property vpn_tun_fd_attached "$RESULT_DIR/s182-status.properties"
require_positive_property vpn_direct_udp6_status_available "$RESULT_DIR/s182-status.properties"
require_positive_property vpn_direct_udp6_socket_attached "$RESULT_DIR/s182-status.properties"
require_positive_property vpn_direct_udp6_protect_succeeded "$RESULT_DIR/s182-status.properties"
require_positive_property vpn_direct_udp6_bind_succeeded "$RESULT_DIR/s182-status.properties"
require_positive_property vpn_tun_ingress_packets "$RESULT_DIR/s182-status.properties"
require_positive_property vpn_tun_udp6_tun_origin_packets "$RESULT_DIR/s182-status.properties"
require_positive_property vpn_flow_stack_admissions "$RESULT_DIR/s182-status.properties"
require_positive_property vpn_direct_udp6_send_succeeded "$RESULT_DIR/s182-status.properties"
require_positive_property vpn_direct_udp6_return_packets "$RESULT_DIR/s182-status.properties"
require_positive_property vpn_direct_udp6_tun_write_completions "$RESULT_DIR/s182-status.properties"
require_positive_property vpn_flow_stack_return_provenance_packets "$RESULT_DIR/s182-status.properties"
require_positive_property vpn_tun_write_completions "$RESULT_DIR/s182-status.properties"
require_zero_property vpn_direct_udp6_transport_failed "$RESULT_DIR/s182-status.properties"
kv vpn_infrastructure_faults \
  "$(property_value vpn_infrastructure_faults "$RESULT_DIR/s182-status.properties")"
kv vpn_duplicate_or_stale_drops \
  "$(property_value vpn_duplicate_or_stale_drops "$RESULT_DIR/s182-status.properties")"

start_activity --ez runtimeStop true
wait_app_property "$STATE_PATH" state stopped "$RESULT_DIR/state.stopped.properties" \
  || fail_closed "VPN Product Core did not stop cleanly"
if grep -Fq "mayBeActive=true" "$RESULT_DIR/state.stopped.properties"; then
  fail_closed "stopped state still reports mayBeActive=true"
fi
kv final_residue_clean true
kv result PASS
echo "SAKAMOTO-182 VPN UDP6 Direct Egress: PASS"
